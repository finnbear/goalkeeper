//! What priority buys an HTTP server, over real loopback TCP.
//!
//! The same axum app is served two ways: by
//! [`goalkeeper::http::ServeHttp::serve_http`], and by hyper-util's `auto::Builder`
//! on a bare `tokio::spawn` accept loop, which is what an application would
//! write without goalkeeper. Hundreds of
//! concurrent clients each hold a keep-alive connection and request in a loop.
//!
//! Every connection announces a priority in its path, and goalkeeper's handler
//! applies it with `conn.set_base(..)`, so the connection is
//! scheduled at that level for the rest of its life. The baseline reads the same
//! path and ignores it, which is the comparison: `N` distinct priorities exist
//! in both runs, and only one of the two servers can act on them.
//!
//! - **latency (top)**: 99th percentile request round trip, over the clients
//!   holding the best priority. Socket write to response byte, so it includes
//!   the kernel, the accept path, hyper's parsing and the handler.
//! - **throughput (all)**: completed requests per second across every client.
//!
//! `N = 1` is the control: one priority is no priority, so what is left is the
//! cost of being able to have them.
//!
//! Server and clients get a runtime each, on their own threads. Sharing one
//! would mean the clients competed with the server for the very schedule under
//! test, and the measurement would include the tool.

use goalkeeper::SystemGoalkeeper;
use goalkeeper::conn::Conn;
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

/// Concurrent keep-alive connections. Enough that a request has to wait behind
/// others, which is the only condition under which priority means anything.
const CLIENTS: usize = 256;
/// Long enough to cross several of the executor's 100ms windows.
const RUN: Duration = Duration::from_millis(750);
/// Work in the handler, in spin iterations. A few microseconds, so serving is
/// not free and connections genuinely contend.
const WORK: u32 = 5_000;

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

/// Seeded, so both servers face the same distribution of priorities.
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
    // The best level must be occupied for its latency to mean anything.
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

/// The app, identical on both servers.
///
/// `Conn` is an `Option` because only goalkeeper inserts one; under the
/// baseline the requested priority is parsed, found to have nowhere to go, and
/// dropped. That is exactly the difference being measured.
fn app() -> axum::Router {
    use axum::extract::Path;
    use axum::routing::get;

    async fn handler(
        conn: Option<axum::Extension<Conn>>,
        Path(level): Path<usize>,
    ) -> &'static str {
        if let Some(axum::Extension(conn)) = conn {
            conn.set_base(Priority::User(LEVELS[level.min(LEVELS.len() - 1)]));
        }
        spin(WORK);
        "ok"
    }

    axum::Router::new().route("/l/{level}", get(handler))
}

/// One client: connect, then request and read the response, forever.
///
/// A hand-written HTTP/1.1 keep-alive exchange rather than a client crate. The
/// server's response is ours and fixed, so "read until the body arrives" is
/// exact rather than a parser's guess, and it keeps the measurement to a socket
/// write and a socket read.
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
    // Nagle would batch small requests and measure the algorithm, not the
    // server.
    let _ = stream.set_nodelay(true);

    let request =
        format!("GET /l/{level} HTTP/1.1\r\nHost: bench\r\nConnection: keep-alive\r\n\r\n");
    let mut buffer = [0u8; 1024];

    while !stop.load(Ordering::Relaxed) {
        let sent = Instant::now();
        if stream.write_all(request.as_bytes()).await.is_err() {
            break;
        }

        // The body is the two bytes "ok", so the response ends with them. Reads
        // until it has seen the end of one whole response.
        let mut seen = Vec::new();
        loop {
            // Bounded, since a client being deliberately starved must still
            // notice `stop` or the harness waits on it forever. A timeout here
            // abandons the sample, not the connection.
            let read =
                match tokio::time::timeout(Duration::from_millis(200), stream.read(&mut buffer))
                    .await
                {
                    Ok(Ok(0)) | Ok(Err(_)) => return latencies,
                    Ok(Ok(read)) => read,
                    Err(_) => {
                        if stop.load(Ordering::Relaxed) {
                            return latencies;
                        }
                        continue;
                    }
                };
            seen.extend_from_slice(&buffer[..read]);
            if seen.ends_with(b"\r\n\r\nok") {
                break;
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

/// Runs the clients against an already-listening `addr` and reports.
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

        // Lets every connection get established before the clock starts, so
        // the connect storm is not counted as request latency.
        tokio::time::sleep(Duration::from_millis(100)).await;
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

/// Binds up front on the main thread, so the address is known before either
/// server starts and the clients never race the bind.
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
            let mut serving = SystemGoalkeeper.serve_http(listener, app()).spawn();
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

fn on_hyper_util(n: usize) -> Report {
    let (std_listener, addr) = listener();
    let shutdown = Arc::new(AtomicBool::new(false));
    let server_stop = Arc::clone(&shutdown);

    let server = std::thread::spawn(move || {
        use hyper_util::rt::{TokioExecutor, TokioIo};
        use hyper_util::server::conn::auto;
        use tower::Service as _;

        runtime().block_on(async move {
            let listener = TcpListener::from_std(std_listener).unwrap();
            let app = app();
            loop {
                let accepted =
                    tokio::time::timeout(Duration::from_millis(5), listener.accept()).await;
                if server_stop.load(Ordering::Relaxed) {
                    // Connections are dropped with the runtime, which is what
                    // the goalkeeper side's `stop()` amounts to here: the clients
                    // have already finished measuring.
                    return;
                }
                let Ok(Ok((stream, _))) = accepted else {
                    continue;
                };
                let _ = stream.set_nodelay(true);
                let app = app.clone();
                // The shape an application writes without goalkeeper: one bare
                // `tokio::spawn` per connection, all equal, served in the order
                // the runtime happens to reach them.
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

/// Stands the per-address limiter down for the duration.
///
/// Every client here comes from `127.0.0.1`, so to goalkeeper the run looks
/// exactly like one machine opening 256 connections and hammering them, which
/// it is built to refuse and does. That refusal is correct and is measured
/// elsewhere; leaving it on here would benchmark the limiter instead of the
/// schedule. The baseline has no equivalent to stand down, which is the other
/// reason: a comparison in which only one side admits the load is not one.
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
        "{CLIENTS} keep-alive connections over loopback, {}ms per run\n",
        RUN.as_millis()
    );
    println!("        latency (top, p99)      throughput (all, kreq/s)");
    println!("  N     goalkeeper     tokio    goalkeeper        tokio");
    println!("  ---   ----------   -------    ----------   ----------");

    for n in 1..=LEVELS.len() {
        let gk = on_goalkeeper(n);
        let tk = on_hyper_util(n);
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
