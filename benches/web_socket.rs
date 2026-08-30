//! What priority buys a WebSocket server, over real loopback TCP.
//!
//! The companion to `benches/http.rs`, and the same comparison one layer up.
//! Hundreds of clients each hold an open socket and exchange small text
//! messages in lockstep, sending one and waiting for the echo, the shape of a
//! game client talking to a game server, and the shape priority exists for.
//!
//! Served two ways:
//!
//! - [`goalkeeper::http::web_socket::WebSocketUpgrade`], whose `on_upgrade`
//!   runs the whole socket on goalkeeper's executor at the connection's
//!   priority.
//! - `axum_tws::WebSocketUpgrade`, which is what the same application would use
//!   without goalkeeper: the socket is handed to `tokio::spawn`, equal to every
//!   other task in the process.
//!
//! Each connection announces its priority in the upgrade path. goalkeeper acts
//! on it; the baseline parses it and has nowhere to put it.
//!
//! - **latency (top)**: 99th percentile round trip of a message on the
//!   best-priority sockets, socket write to echo received.
//! - **throughput (all)**: echoed messages per second across every client.
//!
//! `N = 1` is the control, where one priority is no priority.

use goalkeeper::SystemGoalkeeper;
use goalkeeper::executor::priority::{Priority, UserPriority};
use goalkeeper::http::ServeHttp;
use std::hint::black_box;
use std::io::Write as _;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const CLIENTS: usize = 256;
const RUN: Duration = Duration::from_millis(750);
/// Work done per message, in spin iterations.
const WORK: u32 = 5_000;
/// The message every client sends, and expects back.
const PAYLOAD: &[u8] = b"ping";

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

/// The echo loop both servers run, once the socket exists.
async fn echo<S>(mut socket: S)
where
    S: futures_util::Stream<Item = Result<axum_tws::Message, axum_tws::WebSocketError>>
        + futures_util::Sink<axum_tws::Message, Error = axum_tws::WebSocketError>
        + Unpin,
{
    use futures_util::{SinkExt, StreamExt};
    while let Some(Ok(message)) = socket.next().await {
        if !message.is_text() {
            continue;
        }
        spin(WORK);
        if socket.send(axum_tws::Message::text("pong")).await.is_err() {
            return;
        }
    }
}

fn goalkeeper_app() -> axum::Router {
    use axum::extract::Path;
    use axum::routing::any;

    async fn handler(
        upgrade: goalkeeper::http::web_socket::WebSocketUpgrade,
        Path(level): Path<usize>,
    ) -> axum::response::Response {
        let level = LEVELS[level.min(LEVELS.len() - 1)];
        // Also the base, so the connection's own IO, not just the callback,
        // is scheduled at this level.
        upgrade.conn().set_base(Priority::User(level));
        upgrade.on_upgrade(Priority::User(level), echo)
    }

    axum::Router::new().route("/l/{level}", any(handler))
}

fn baseline_app() -> axum::Router {
    use axum::extract::Path;
    use axum::routing::any;

    async fn handler(
        upgrade: axum_tws::WebSocketUpgrade,
        Path(_level): Path<usize>,
    ) -> axum::response::Response {
        // The level is parsed and discarded: there is nowhere for it to go.
        upgrade.on_upgrade(echo)
    }

    axum::Router::new().route("/l/{level}", any(handler))
}

/// One client: upgrade, then ping and await the pong, forever.
///
/// The handshake and framing are written out rather than taken from a client
/// crate. A client need not verify the server's `Sec-WebSocket-Accept`, so the
/// RFC's own example key can be sent verbatim and no SHA-1 is needed; the
/// frames are small, unfragmented and single-purpose, so the two-byte header
/// plus a mask is the whole of the encoding.
async fn client(
    addr: SocketAddr,
    level: usize,
    stop: Arc<AtomicBool>,
    done: Arc<AtomicU64>,
) -> Vec<Duration> {
    let mut latencies = Vec::new();
    let Ok(mut stream) = TcpStream::connect(addr).await else {
        return latencies;
    };
    let _ = stream.set_nodelay(true);

    let handshake = format!(
        "GET /l/{level} HTTP/1.1\r\n\
         Host: bench\r\n\
         Connection: Upgrade\r\n\
         Upgrade: websocket\r\n\
         Sec-WebSocket-Version: 13\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
    );
    if stream.write_all(handshake.as_bytes()).await.is_err() {
        return latencies;
    }

    let mut buffer = [0u8; 2048];
    // Reads until the end of the 101 response's headers. Nothing follows them
    // until we send something, so this cannot swallow a frame.
    let mut seen = Vec::new();
    loop {
        match tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buffer)).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => return latencies,
            Ok(Ok(read)) => seen.extend_from_slice(&buffer[..read]),
        }
        if seen.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }

    // One masked text frame, built once: FIN + text, mask bit + length, the
    // mask itself, then the payload under it.
    let mask = [0x37u8, 0xfa, 0x21, 0x3d];
    let mut frame = vec![0x81, 0x80 | PAYLOAD.len() as u8];
    frame.extend_from_slice(&mask);
    frame.extend(PAYLOAD.iter().zip(mask.iter().cycle()).map(|(b, m)| b ^ m));

    while !stop.load(Ordering::Relaxed) {
        let sent = Instant::now();
        if stream.write_all(&frame).await.is_err() {
            break;
        }

        // The reply is one unmasked four-byte text frame, so its whole encoding
        // is six bytes.
        let mut got = 0usize;
        while got < 6 {
            match tokio::time::timeout(Duration::from_millis(200), stream.read(&mut buffer[got..]))
                .await
            {
                Ok(Ok(0)) | Ok(Err(_)) => return latencies,
                Ok(Ok(read)) => got += read,
                // Bounded so a starved client still notices `stop`, rather than
                // leaving the harness waiting on it forever.
                Err(_) => {
                    if stop.load(Ordering::Relaxed) {
                        return latencies;
                    }
                }
            }
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

fn drive_clients(addr: SocketAddr, n: usize) -> Report {
    let levels = assignment(n);
    let stop = Arc::new(AtomicBool::new(false));
    let done = Arc::new(AtomicU64::new(0));
    let counted = Arc::clone(&done);

    runtime().block_on(async move {
        let clients: Vec<_> = levels
            .iter()
            .map(|&level| {
                let task = tokio::spawn(client(addr, level, stop.clone(), done.clone()));
                (level, task)
            })
            .collect();

        // Upgrades are more expensive than requests, so the sockets get longer
        // to establish before the clock starts.
        tokio::time::sleep(Duration::from_millis(250)).await;
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

fn listener() -> (std::net::TcpListener, SocketAddr) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let addr = listener.local_addr().unwrap();
    (listener, addr)
}

fn on_goalkeeper(n: usize) -> Report {
    let (std_listener, addr) = listener();
    let shutdown = Arc::new(AtomicBool::new(false));
    let server_stop = Arc::clone(&shutdown);

    let server = std::thread::spawn(move || {
        runtime().block_on(SystemGoalkeeper.run_until(async move {
            let listener = TcpListener::from_std(std_listener).unwrap();
            let mut serving = SystemGoalkeeper
                .serve_http(listener, goalkeeper_app())
                .spawn();
            while !server_stop.load(Ordering::Relaxed) {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            serving.stop().await;
        }));
    });

    let report = drive_clients(addr, n);
    shutdown.store(true, Ordering::Relaxed);
    let _ = server.join();
    report
}

fn on_baseline(n: usize) -> Report {
    let (std_listener, addr) = listener();
    let shutdown = Arc::new(AtomicBool::new(false));
    let server_stop = Arc::clone(&shutdown);

    let server = std::thread::spawn(move || {
        use hyper_util::rt::{TokioExecutor, TokioIo};
        use hyper_util::server::conn::auto;
        use tower::Service as _;

        runtime().block_on(async move {
            let listener = TcpListener::from_std(std_listener).unwrap();
            let app = baseline_app();
            loop {
                let accepted =
                    tokio::time::timeout(Duration::from_millis(5), listener.accept()).await;
                if server_stop.load(Ordering::Relaxed) {
                    return;
                }
                let Ok(Ok((stream, _))) = accepted else {
                    continue;
                };
                let _ = stream.set_nodelay(true);
                let app = app.clone();
                tokio::spawn(async move {
                    let io = TokioIo::new(stream);
                    let service =
                        hyper::service::service_fn(move |request| app.clone().call(request));
                    let _ = auto::Builder::new(TokioExecutor::new())
                        .serve_connection_with_upgrades(io, service)
                        .await;
                });
            }
        });
    });

    let report = drive_clients(addr, n);
    shutdown.store(true, Ordering::Relaxed);
    let _ = server.join();
    report
}

/// See the note in `benches/http.rs`: every client here is `127.0.0.1`, which
/// is precisely the shape the per-address limiter refuses, and the baseline has
/// no equivalent to stand down.
fn stand_down_the_limiter() {
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
        "{CLIENTS} WebSocket connections over loopback, {}ms per run\n",
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
