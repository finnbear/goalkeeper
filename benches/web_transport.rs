//! What priority buys a WebTransport server, over real loopback UDP.
//!
//! The third of the connection benchmarks, and the one that leaves TCP behind.
//! Hundreds of clients each hold a WebTransport session over QUIC and exchange
//! small messages in lockstep on a bidirectional stream, sending one and
//! waiting for the echo, the same shape as `benches/web_socket.rs` so the two
//! are comparable.
//!
//! Reliable streams only. Datagrams are lossy by design, so a round trip is not
//! guaranteed to complete and latency would be measuring the network's mood
//! rather than the schedule's. They would want their own benchmark.
//!
//! Served two ways:
//!
//! - [`goalkeeper::web_transport::ServeWebTransport::serve_web_transport`],
//!   which gives each session a [`Conn`] and runs it at that connection's
//!   priority, and meters the shared UDP socket besides.
//! - a bare `wtransport::Endpoint` with one `tokio::spawn` per session, which is
//!   what the same application would write without goalkeeper.
//!
//! Each connection announces its priority in the session path. goalkeeper acts
//! on it; the baseline parses it and has nowhere to put it.
//!
//! - **latency (top)**: 99th percentile round trip on the best-priority
//!   sessions.
//! - **throughput (all)**: echoed messages per second across every client.
//!
//! `N = 1` is the control, where one priority is no priority.

use goalkeeper::SystemGoalkeeper;
use goalkeeper::executor::priority::{Priority, UserPriority};
use goalkeeper::web_transport::ServeWebTransport;
use std::hint::black_box;
use std::io::Write as _;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use wtransport::{ClientConfig, Endpoint, Identity, ServerConfig};

const CLIENTS: usize = 256;
const RUN: Duration = Duration::from_millis(750);
/// Work done per message, in spin iterations.
const WORK: u32 = 5_000;
/// The message every client sends, and expects back.
const PAYLOAD: &[u8] = b"ping";
/// The reply, which must be the same length so the client can read a fixed
/// number of bytes and call the round trip done.
const REPLY: &[u8] = b"pong";

const LEVELS: [UserPriority; 8] = [
    UserPriority::L0,
    UserPriority::L1,
    UserPriority::L2,
    UserPriority::L3,
    UserPriority::L4,
    UserPriority::L5,
    UserPriority::L6,
    UserPriority::L7,
];

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
}

fn assignment(n: usize) -> Vec<usize> {
    let mut rng = Rng(0x9E3779B97F4A7C15);
    let mut levels: Vec<usize> = (0..CLIENTS).map(|_| rng.next() as usize % n).collect();
    levels[0] = 0;
    levels
}

fn spin(iterations: u32) {
    let mut x = 0u64;
    for i in 0..iterations {
        x = x.wrapping_mul(6364136223846793005).wrapping_add(i as u64);
    }
    black_box(x);
}

/// The level a session asked for, from its path. Out-of-range clamps rather
/// than failing: the benchmark never sends one, and a server should not trust
/// the number anyway.
fn requested_level(path: &str) -> usize {
    path.rsplit('/')
        .next()
        .and_then(|tail| tail.parse::<usize>().ok())
        .unwrap_or(0)
        .min(LEVELS.len() - 1)
}

/// The echo loop both servers run, once the session exists.
///
/// One bidirectional stream, accepted from the client, then message for message
/// until it closes.
async fn echo(connection: &wtransport::Connection) {
    let Ok((mut send, mut recv)) = connection.accept_bi().await else {
        return;
    };
    let mut buffer = [0u8; PAYLOAD.len()];
    loop {
        if recv.read_exact(&mut buffer).await.is_err() {
            return;
        }
        spin(WORK);
        if send.write_all(REPLY).await.is_err() {
            return;
        }
    }
}

/// A certificate the client will accept, held for the whole run so both servers
/// present the same one.
fn identity() -> Identity {
    Identity::self_signed(["localhost", "127.0.0.1", "::1"]).unwrap()
}

/// The baseline still takes a whole `wtransport::ServerConfig`, because it *is*
/// a bare wtransport endpoint.
fn server_config(port: u16, identity: &Identity) -> ServerConfig {
    ServerConfig::builder()
        .with_bind_default(port)
        .with_identity(identity.clone_identity())
        .build()
}

/// The identity as the hot-swappable `TlsConfig` goalkeeper's server takes.
fn tls_config(identity: &Identity) -> goalkeeper::http::tls::TlsConfig {
    let chain = identity
        .certificate_chain()
        .as_slice()
        .iter()
        .map(|c| rustls::pki_types::CertificateDer::from(c.der().to_vec()))
        .collect();
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(
        identity.private_key().secret_der().to_vec().into(),
    );
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .unwrap();
    goalkeeper::http::tls::TlsConfig::new(Arc::new(config))
}

/// One client: connect, open a stream, then ping and await the pong, forever.
async fn client(
    port: u16,
    level: usize,
    stop: Arc<AtomicBool>,
    done: Arc<AtomicU64>,
) -> Vec<Duration> {
    let mut latencies = Vec::new();
    // The certificate is self-signed and the authority is a loopback port, so
    // there is nothing a real validator could check. This is a benchmark
    // client and never leaves the machine.
    let config = ClientConfig::builder()
        .with_bind_default()
        .with_no_cert_validation()
        .build();
    let Ok(endpoint) = Endpoint::client(config) else {
        return latencies;
    };
    // The literal v4 address, not `localhost`: goalkeeper's endpoint binds
    // `0.0.0.0`, so it is deaf to the `::1` that `localhost` resolves to first.
    // The baseline's `with_bind_default` is dual-stack and would have worked
    // either way, which is exactly how this benchmark found the difference.
    let Ok(connection) = endpoint
        .connect(format!("https://127.0.0.1:{port}/l/{level}"))
        .await
    else {
        return latencies;
    };
    // Two awaits: the first for the peer's permission to open, the second for
    // the stream itself.
    let Ok(opening) = connection.open_bi().await else {
        return latencies;
    };
    let Ok((mut send, mut recv)) = opening.await else {
        return latencies;
    };

    let mut buffer = [0u8; REPLY.len()];
    while !stop.load(Ordering::Relaxed) {
        let sent = Instant::now();
        if send.write_all(PAYLOAD).await.is_err() {
            break;
        }
        // Bounded, so a starved client still notices `stop` rather than leaving
        // the harness waiting on it forever.
        match tokio::time::timeout(Duration::from_millis(500), recv.read_exact(&mut buffer)).await {
            Ok(Ok(())) => {}
            Ok(Err(_)) => break,
            Err(_) => continue,
        }
        latencies.push(sent.elapsed());
        done.fetch_add(1, Ordering::Relaxed);
    }
    latencies
}

struct Report {
    top_p99: Duration,
    throughput: f64,
}

fn report(mut top: Vec<Duration>, done: u64, elapsed: Duration) -> Report {
    top.sort_unstable();
    let top_p99 = if top.is_empty() {
        Duration::ZERO
    } else {
        let rank = (top.len() as f64 * 0.99).ceil() as usize;
        top[rank.saturating_sub(1).min(top.len() - 1)]
    };
    Report {
        top_p99,
        throughput: done as f64 / elapsed.as_secs_f64(),
    }
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

fn drive_clients(port: u16, n: usize) -> Report {
    let levels = assignment(n);
    let stop = Arc::new(AtomicBool::new(false));
    let done = Arc::new(AtomicU64::new(0));
    let counted = Arc::clone(&done);

    runtime().block_on(async move {
        let clients: Vec<_> = levels
            .iter()
            .map(|&level| {
                let task = tokio::spawn(client(port, level, stop.clone(), done.clone()));
                (level, task)
            })
            .collect();

        // A QUIC handshake plus a WebTransport session request is the most
        // expensive setup of the three benchmarks, so it gets the longest to
        // settle before the clock starts.
        tokio::time::sleep(Duration::from_millis(750)).await;
        let started = Instant::now();
        tokio::time::sleep(RUN).await;
        stop.store(true, Ordering::Relaxed);
        let elapsed = started.elapsed();

        let mut top = Vec::new();
        for (level, task) in clients {
            let latencies = task.await.unwrap_or_default();
            if level == 0 {
                top.extend(latencies);
            }
        }
        report(top, counted.load(Ordering::Relaxed), elapsed)
    })
}

/// A loopback socket, and the port it landed on.
///
/// Held rather than probed and dropped, so nothing can take the port in
/// between. The baseline, which binds for itself, gets [`free_port`].
fn bound() -> (std::net::UdpSocket, u16) {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = socket.local_addr().unwrap().port();
    (socket, port)
}

/// A free UDP port, released before the baseline server binds it. Racy in
/// principle and not in practice on a loopback benchmark.
fn free_port() -> u16 {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.local_addr().unwrap().port()
}

fn on_goalkeeper(n: usize) -> Report {
    let (socket, port) = bound();
    let shutdown = Arc::new(AtomicBool::new(false));
    let server_stop = Arc::clone(&shutdown);
    let identity = identity();

    let server = std::thread::spawn(move || {
        runtime().block_on(SystemGoalkeeper.run_until(async move {
            let tls = tls_config(&identity);
            let handler = |session: goalkeeper::web_transport::Session| async move {
                let level = requested_level(session.request().path());
                session.conn().set_base(Priority::User(LEVELS[level]));
                let Ok(connection) = session.accept().await else {
                    return;
                };
                echo(&connection).await;
            };
            let mut serving = SystemGoalkeeper
                .serve_web_transport(socket, tls, handler)
                .spawn()
                .unwrap();
            while !server_stop.load(Ordering::Relaxed) {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            serving.stop().await;
        }));
    });

    let report = drive_clients(port, n);
    shutdown.store(true, Ordering::Relaxed);
    let _ = server.join();
    report
}

fn on_baseline(n: usize) -> Report {
    let port = free_port();
    let shutdown = Arc::new(AtomicBool::new(false));
    let server_stop = Arc::clone(&shutdown);
    let identity = identity();

    let server = std::thread::spawn(move || {
        runtime().block_on(async move {
            let Ok(endpoint) = Endpoint::server(server_config(port, &identity)) else {
                return;
            };
            loop {
                let accepted =
                    tokio::time::timeout(Duration::from_millis(5), endpoint.accept()).await;
                if server_stop.load(Ordering::Relaxed) {
                    return;
                }
                let Ok(incoming) = accepted else {
                    continue;
                };
                // The shape an application writes without goalkeeper: one bare
                // `tokio::spawn` per session, all equal, and the path's priority
                // read only to be discarded.
                tokio::spawn(async move {
                    let Ok(request) = incoming.await else {
                        return;
                    };
                    let _ = requested_level(request.path());
                    let Ok(connection) = request.accept().await else {
                        return;
                    };
                    echo(&connection).await;
                });
            }
        });
    });

    let report = drive_clients(port, n);
    shutdown.store(true, Ordering::Relaxed);
    let _ = server.join();
    report
}

/// See the note in `benches/http1.rs`, and one more besides.
///
/// QUIC goes through the handshake registry, which the TCP benchmarks never
/// touch, and its defaults are the tightest thing in goalkeeper: 32 handshakes
/// in flight and *two slow ones per address*. With 256 clients that are all
/// `127.0.0.1`, that is indistinguishable from one machine opening 256
/// connections at once, which is precisely what it exists to refuse. Before
/// this was stood down, goalkeeper completed zero round trips while the
/// baseline, which has no such registry, ran at full speed.
///
/// Worth stating plainly, because it is the most striking thing this benchmark
/// shows and the table does not show it: the numbers below are what goalkeeper
/// costs *once its admission control is disabled*. Its admission control is
/// most of what it is for.
fn stand_down_the_limiter() {
    SystemGoalkeeper.set_handshake_capacity(4096, 4096);
    SystemGoalkeeper.set_handshake_slow_per_ip(4096, 4096);
    // Large rather than `u32::MAX`: a per-second rate is turned into a period
    // by dividing a second by it, and a rate above a billion rounds that period
    // to zero.
    const PLENTY: u32 = 1_000_000_000;
    SystemGoalkeeper.set_address_bandwidth_limits(PLENTY, PLENTY);
    SystemGoalkeeper.set_connections_per_active(PLENTY, PLENTY);
    SystemGoalkeeper.set_total_connection_limits(PLENTY, PLENTY);
}

fn main() {
    stand_down_the_limiter();
    println!(
        "{CLIENTS} WebTransport sessions over loopback UDP, {}ms per run\n",
        RUN.as_millis()
    );
    println!("        latency (top, p99)      throughput (all, kmsg/s)");
    println!("  N     goalkeeper     tokio    goalkeeper        tokio");
    println!("  ---   ----------   -------    ----------   ----------");

    for n in 1..=LEVELS.len() {
        let gk = on_goalkeeper(n);
        let tk = on_baseline(n);
        println!(
            "  {n}     {:>8.0?}   {:>7.0?}    {:>10.1}   {:>10.1}",
            gk.top_p99,
            tk.top_p99,
            gk.throughput / 1000.0,
            tk.throughput / 1000.0,
        );
        std::io::stdout().flush().unwrap();
    }
}
