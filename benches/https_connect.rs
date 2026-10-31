//! What sending HTTP/2's SETTINGS with the TLS handshake buys, and what it
//! costs, on a fresh HTTPS connection.
//!
//! Each case runs twice: with [`early_settings`] off, which is when hyper alone
//! would send SETTINGS (after the client's TLS `Finished` and HTTP/2 preface),
//! and on, the default, where they leave in rustls' first flight.
//!
//! - **latency**: from the TCP connection being up to the response's HEADERS,
//!   through a proxy that delays each direction by [`DELAY`], so round trips
//!   show on loopback. Two clients, both hand-written HTTP/2 so neither has a
//!   library's habits in the way:
//!   - *eager* sends its request right behind its preface, as browsers and curl
//!     do for a GET. Early SETTINGS should change nothing for it.
//!   - *waiting* holds its request until it has the server's SETTINGS, as every
//!     RFC 8441 WebSocket must. Early SETTINGS should save it a round trip.
//! - **CPU**: the server thread's CPU time per connection (a full TLS
//!   handshake and one request), over plain loopback with no delay.
//!
//! CPU is Linux only: the server's CPU time is read from its thread's CPU
//! clock. Elsewhere only latency runs.
//!
//! [`early_settings`]: goalkeeper::http::HttpServerBuilder::early_settings

use goalkeeper::SystemGoalkeeper;
use goalkeeper::http::ServeHttp;
use rustls::pki_types::ServerName;
use std::io::Write as _;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;

/// One way, so a round trip is twice this.
const DELAY: Duration = Duration::from_millis(10);
const LATENCY_CONNECTIONS: usize = 30;
#[cfg(target_os = "linux")]
const CPU_WARMUP: usize = 64;
#[cfg(target_os = "linux")]
const CPU_CONNECTIONS: usize = 2_048;
#[cfg(target_os = "linux")]
const CPU_CONCURRENCY: usize = 16;
#[cfg(target_os = "linux")]
const CPU_ROUNDS: usize = 3;

const CLIENT_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const HEADERS: u8 = 0x1;
const SETTINGS: u8 = 0x4;
const ACK: u8 = 0x1;
const END_STREAM: u8 = 0x1;
const END_HEADERS: u8 = 0x4;

/// A self-signed certificate for `127.0.0.1`, and the roots that trust it.
fn identity() -> (rustls::ServerConfig, rustls::RootCertStore) {
    let identity = wtransport::Identity::self_signed(["localhost", "127.0.0.1", "::1"]).unwrap();
    let chain: Vec<_> = identity
        .certificate_chain()
        .as_slice()
        .iter()
        .map(|c| rustls::pki_types::CertificateDer::from(c.der().to_vec()))
        .collect();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(chain[0].clone()).unwrap();
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(
        identity.private_key().secret_der().to_vec().into(),
    );
    let server = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .unwrap();
    (server, roots)
}

/// Offers only `h2`, and never resumes, so every connection is a full
/// handshake and costs the server the same.
fn connector(roots: rustls::RootCertStore) -> TlsConnector {
    let mut client = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client.alpn_protocols = vec![b"h2".to_vec()];
    client.resumption = rustls::client::Resumption::disabled();
    TlsConnector::from(Arc::new(client))
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

fn app() -> axum::Router {
    axum::Router::new().route("/", axum::routing::get(|| async { "ok" }))
}

/// An HTTPS server on a thread of its own, whose CPU time can be read from
/// outside.
struct Server {
    addr: SocketAddr,
    #[cfg(target_os = "linux")]
    clock: libc::clockid_t,
    stop: Arc<AtomicBool>,
    thread: std::thread::JoinHandle<()>,
}

impl Server {
    fn start(config: Arc<rustls::ServerConfig>, early: bool) -> Self {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let server_stop = Arc::clone(&stop);
        let thread = std::thread::spawn(move || {
            runtime().block_on(SystemGoalkeeper.run_until(async move {
                let listener = TcpListener::from_std(listener).unwrap();
                let tls = goalkeeper::http::tls::TlsConfig::new(config);
                let mut serving = SystemGoalkeeper
                    .serve_https(listener, tls, app())
                    .early_settings(early)
                    .spawn();
                while !server_stop.load(Ordering::Relaxed) {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                serving.stop().await;
            }));
        });
        Self {
            addr,
            #[cfg(target_os = "linux")]
            clock: cpu_clock(&thread),
            stop,
            thread,
        }
    }

    /// CPU time the server's thread has used so far.
    #[cfg(target_os = "linux")]
    fn cpu(&self) -> Duration {
        cpu_time(self.clock)
    }

    fn stop(self) {
        self.stop.store(true, Ordering::Relaxed);
        let _ = self.thread.join();
    }
}

#[cfg(target_os = "linux")]
fn cpu_clock(thread: &std::thread::JoinHandle<()>) -> libc::clockid_t {
    use std::os::unix::thread::JoinHandleExt;
    let mut clock: libc::clockid_t = 0;
    // SAFETY: the handle is to a thread that has not been joined, and `clock`
    // is a valid destination.
    let status = unsafe { libc::pthread_getcpuclockid(thread.as_pthread_t(), &mut clock) };
    assert_eq!(status, 0, "no CPU clock for the server thread");
    clock
}

#[cfg(target_os = "linux")]
fn cpu_time(clock: libc::clockid_t) -> Duration {
    // SAFETY: all zeroes is a valid `timespec`; then a clock from
    // `pthread_getcpuclockid`, and a valid destination.
    let mut now: libc::timespec = unsafe { std::mem::zeroed() };
    let status = unsafe { libc::clock_gettime(clock, &mut now) };
    assert_eq!(status, 0, "could not read the server thread's CPU clock");
    Duration::new(now.tv_sec as u64, now.tv_nsec as u32)
}

/// A proxy to `to` that delays every byte by [`DELAY`] in each direction,
/// returning the address to connect to instead.
///
/// It accepts locally and at once, so the TCP handshake itself is not delayed;
/// that is why latency is timed from the connection being up.
async fn delaying_proxy(to: SocketAddr) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((inbound, _)) = listener.accept().await {
            tokio::spawn(async move {
                let Ok(outbound) = TcpStream::connect(to).await else {
                    return;
                };
                let _ = inbound.set_nodelay(true);
                let _ = outbound.set_nodelay(true);
                let (inbound_read, inbound_write) = inbound.into_split();
                let (outbound_read, outbound_write) = outbound.into_split();
                tokio::join!(
                    delayed(inbound_read, outbound_write),
                    delayed(outbound_read, inbound_write)
                );
            });
        }
    });
    addr
}

/// Copies `from` to `to`, each read arriving [`DELAY`] after it was read and
/// in the order it was read.
async fn delayed(mut from: OwnedReadHalf, mut to: OwnedWriteHalf) {
    let (sender, mut receiver) =
        tokio::sync::mpsc::unbounded_channel::<(tokio::time::Instant, Vec<u8>)>();
    let read = async move {
        let mut buf = vec![0; 16 * 1024];
        while let Ok(read) = from.read(&mut buf).await {
            let due = tokio::time::Instant::now() + DELAY;
            if read == 0 || sender.send((due, buf[..read].to_vec())).is_err() {
                break;
            }
        }
    };
    let write = async move {
        while let Some((due, bytes)) = receiver.recv().await {
            tokio::time::sleep_until(due).await;
            if to.write_all(&bytes).await.is_err() {
                return;
            }
        }
        let _ = to.shutdown().await;
    };
    tokio::join!(read, write);
}

fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let length = (payload.len() as u32).to_be_bytes();
    let mut frame = vec![length[1], length[2], length[3], kind, flags];
    frame.extend_from_slice(&stream.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

/// `GET /` on stream 1: `:method`, `:scheme` and `:path` from HPACK's static
/// table, and `:authority` as a literal.
fn get() -> Vec<u8> {
    let block = [0x82, 0x87, 0x84, 0x41, 0x05, b'b', b'e', b'n', b'c', b'h'];
    frame(HEADERS, END_HEADERS | END_STREAM, 1, &block)
}

/// Reads one frame, returning its type, flags and stream.
async fn read_frame<S: AsyncRead + Unpin>(stream: &mut S) -> (u8, u8, u32) {
    let mut header = [0; 9];
    stream.read_exact(&mut header).await.unwrap();
    let length = u32::from_be_bytes([0, header[0], header[1], header[2]]) as usize;
    let mut payload = vec![0; length];
    stream.read_exact(&mut payload).await.unwrap();
    let id = u32::from_be_bytes([header[5], header[6], header[7], header[8]]) & 0x7fff_ffff;
    (header[3], header[4], id)
}

#[derive(Clone, Copy, PartialEq)]
enum Client {
    Eager,
    Waiting,
}

/// One connection and one request, returning the time from the TCP connection
/// being up to the response's HEADERS.
async fn connect(addr: SocketAddr, tls: &TlsConnector, client: Client) -> Duration {
    let tcp = TcpStream::connect(addr).await.unwrap();
    tcp.set_nodelay(true).unwrap();
    let started = Instant::now();
    let name = ServerName::IpAddress(addr.ip().into());
    let mut stream = tls.connect(name, tcp).await.unwrap();
    assert_eq!(stream.get_ref().1.alpn_protocol(), Some(&b"h2"[..]));

    // Both send their preface and SETTINGS at once; only the eager client
    // sends its request with them.
    let mut opening = CLIENT_PREFACE.to_vec();
    opening.extend(frame(SETTINGS, 0, 0, &[]));
    let mut requested = client == Client::Eager;
    if requested {
        opening.extend(get());
    }
    stream.write_all(&opening).await.unwrap();
    stream.flush().await.unwrap();

    loop {
        let (kind, flags, id) = read_frame(&mut stream).await;
        if kind == SETTINGS && flags & ACK == 0 {
            let mut reply = frame(SETTINGS, ACK, 0, &[]);
            if !requested {
                reply.extend(get());
                requested = true;
            }
            stream.write_all(&reply).await.unwrap();
            stream.flush().await.unwrap();
        } else if kind == HEADERS && id == 1 {
            return started.elapsed();
        }
    }
}

/// `connections` connections, [`CPU_CONCURRENCY`] at a time, each with one
/// request.
#[cfg(target_os = "linux")]
async fn churn(addr: SocketAddr, tls: &TlsConnector, connections: usize) {
    let tasks: Vec<_> = (0..CPU_CONCURRENCY)
        .map(|_| {
            let tls = tls.clone();
            tokio::spawn(async move {
                for _ in 0..connections / CPU_CONCURRENCY {
                    connect(addr, &tls, Client::Eager).await;
                }
            })
        })
        .collect();
    for task in tasks {
        task.await.unwrap();
    }
}

fn median(mut values: Vec<Duration>) -> Duration {
    values.sort_unstable();
    values[values.len() / 2]
}

/// See the note in `benches/http1.rs`: every client here is `127.0.0.1`, which
/// is precisely the shape the per-address limiter refuses.
fn stand_down_the_limiter() {
    // Large rather than `u32::MAX`: a per-second rate is turned into a period
    // by dividing a second by it, and a rate above a billion rounds that period
    // to zero.
    const PLENTY: u32 = 1_000_000_000;
    SystemGoalkeeper.set_address_bandwidth_limits(PLENTY, PLENTY);
    SystemGoalkeeper.set_connections_per_active(PLENTY, PLENTY);
    SystemGoalkeeper.set_total_connection_limits(PLENTY, PLENTY);
    SystemGoalkeeper.set_handshake_capacity(4096, 4096);
    SystemGoalkeeper.set_handshake_share(4096, 4096);
}

fn main() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    stand_down_the_limiter();
    let (server_config, roots) = identity();
    let server_config = Arc::new(server_config);
    let tls = connector(roots);
    let client_runtime = runtime();
    // A worker of its own, so the proxy runs without being polled. On the
    // client's runtime it would stop between cases, leaving the last
    // connection's close unrelayed, and stopping the server would then wait on
    // that connection until hyper's keep-alive reaped it, minutes later.
    let proxy_runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .unwrap();
    let round_trip = DELAY * 2;

    println!(
        "HTTP/2 over TLS 1.3, SETTINGS sent late (as hyper would) or early (with the handshake)\n"
    );
    println!(
        "Latency, TCP connection up to response HEADERS: median of {LATENCY_CONNECTIONS}, \
         {}ms round trip",
        round_trip.as_millis()
    );
    println!("  client     late                early");
    for client in [Client::Eager, Client::Waiting] {
        let mut cells = Vec::new();
        for early in [false, true] {
            let server = Server::start(Arc::clone(&server_config), early);
            let proxy = proxy_runtime.block_on(delaying_proxy(server.addr));
            let latency = client_runtime.block_on(async {
                let mut latencies = Vec::with_capacity(LATENCY_CONNECTIONS);
                for _ in 0..LATENCY_CONNECTIONS {
                    latencies.push(connect(proxy, &tls, client).await);
                }
                median(latencies)
            });
            server.stop();
            cells.push(format!(
                "{:>5.1}ms ({:.1} RTT)",
                latency.as_secs_f64() * 1000.0,
                latency.as_secs_f64() / round_trip.as_secs_f64()
            ));
        }
        let name = match client {
            Client::Eager => "eager",
            Client::Waiting => "waiting",
        };
        println!("  {name:<9}  {:<18}  {}", cells[0], cells[1]);
        std::io::stdout().flush().unwrap();
    }

    #[cfg(target_os = "linux")]
    cpu(&server_config, &tls, &client_runtime);
    #[cfg(not(target_os = "linux"))]
    println!("\nServer CPU per connection: skipped, Linux only");
}

/// The CPU case, on the same server configuration and client as the latency
/// case.
#[cfg(target_os = "linux")]
fn cpu(
    server_config: &Arc<rustls::ServerConfig>,
    tls: &TlsConnector,
    client_runtime: &tokio::runtime::Runtime,
) {
    println!(
        "\nServer CPU per connection (full handshake and one request): \
         {CPU_CONNECTIONS} connections, {CPU_CONCURRENCY} at a time, median of {CPU_ROUNDS}"
    );
    let mut per_connection = [Vec::new(), Vec::new()];
    // Alternating, so drift over the run (thermal, frequency) lands on both.
    for _ in 0..CPU_ROUNDS {
        for (index, early) in [false, true].into_iter().enumerate() {
            let server = Server::start(Arc::clone(server_config), early);
            let used = client_runtime.block_on(async {
                churn(server.addr, tls, CPU_WARMUP).await;
                let before = server.cpu();
                churn(server.addr, tls, CPU_CONNECTIONS).await;
                server.cpu() - before
            });
            server.stop();
            let connections = (CPU_CONNECTIONS / CPU_CONCURRENCY * CPU_CONCURRENCY) as u32;
            per_connection[index].push(used / connections);
        }
    }
    for (index, label) in ["late", "early"].into_iter().enumerate() {
        println!(
            "  {label:<6} {:>6.1}µs",
            median(per_connection[index].clone()).as_secs_f64() * 1e6
        );
    }
}
