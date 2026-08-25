//! What priority buys an HTTP/2 server, over real loopback TCP.
//!
//! The companion to `benches/http1.rs`. The servers are byte-for-byte the same,
//! since hyper's `auto` builder serves either protocol and sniffs which one
//! arrived, so what changes is entirely on the client: it speaks h2c with prior
//! knowledge, and requests ride streams multiplexed over one connection instead
//! of a serialised keep-alive exchange.
//!
//! That distinction is why this is worth measuring separately. Under HTTP/1 a
//! connection carries one request at a time, so a slow handler blocks only its
//! own client. Under HTTP/2 a connection's streams share the connection's task,
//! and goalkeeper's priority is per connection, so the level a client announces
//! governs everything it has in flight at once. It is also the shape that costs
//! an application the most connections per user, which is what the per-address
//! limiter's `connections_per_active_p90` note is about.
//!
//! One TCP connection per client, as in the HTTP/1 benchmark, so the priority
//! assignment means the same thing in both and the two tables can be compared.
//!
//! - **latency (top)**: 99th percentile request round trip on the best-priority
//!   connections.
//! - **throughput (all)**: completed requests per second across every client.

use bytes::Bytes;
use goalkeeper::SystemGoalkeeper;
use goalkeeper::conn::Conn;
use goalkeeper::executor::priority::{Priority, UserPriority};
use goalkeeper::http::ServeHttp;
use http_body_util::{BodyExt, Empty};
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::hint::black_box;
use std::io::Write as _;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::net::{TcpListener, TcpStream};

const CLIENTS: usize = 256;
const RUN: Duration = Duration::from_millis(750);
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

fn app() -> axum::Router {
    use axum::extract::Path;
    use axum::routing::get;

    async fn handler(
        conn: Option<axum::Extension<Conn>>,
        Path(level): Path<usize>,
    ) -> &'static str {
        if let Some(axum::Extension(conn)) = conn {
            conn.priority()
                .set_base(Priority::User(LEVELS[level.min(LEVELS.len() - 1)]));
        }
        spin(WORK);
        "ok"
    }

    axum::Router::new().route("/l/{level}", get(handler))
}

/// One client: one h2c connection, then a request at a time on it.
///
/// A real client rather than hand-written frames, because HTTP/2 means HPACK
/// and there is no honest way to fake that. `http2::handshake` speaks prior
/// knowledge, with no upgrade dance, which is what the `auto` builder is
/// sniffing for on the other end.
///
/// Requests are issued one at a time rather than pipelined, so the number
/// measured is a round trip and not a queue depth, and so it means the same as
/// the HTTP/1 figure.
async fn client(
    addr: SocketAddr,
    level: usize,
    stop: Arc<AtomicBool>,
    done: Arc<AtomicU64>,
) -> Vec<Duration> {
    let mut latencies = Vec::new();
    let Ok(stream) = TcpStream::connect(addr).await else {
        return latencies;
    };
    let _ = stream.set_nodelay(true);

    let Ok((mut sender, connection)) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(stream)).await
    else {
        return latencies;
    };
    // Drives the connection itself: frames, flow control, and the streams'
    // multiplexing. Nothing on the client side is under test, so plain tokio.
    tokio::spawn(connection);

    // Absolute form, because h2 carries `:authority` rather than a `Host`
    // header and hyper builds it from the URI.
    let uri = format!("http://bench/l/{level}");

    while !stop.load(Ordering::Relaxed) {
        if sender.ready().await.is_err() {
            break;
        }
        let Ok(request) = hyper::Request::builder()
            .uri(&uri)
            .body(Empty::<Bytes>::new())
        else {
            break;
        };

        let sent = Instant::now();
        // Bounded, so a starved client still notices `stop` rather than leaving
        // the harness waiting on it forever.
        let response =
            match tokio::time::timeout(Duration::from_millis(500), sender.send_request(request))
                .await
            {
                Ok(Ok(response)) => response,
                Ok(Err(_)) => break,
                Err(_) => continue,
            };

        // The round trip is not over until the body is, so drain it.
        let mut body = response.into_body();
        while let Some(Ok(_)) = body.frame().await {}

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

        // h2 handshakes cost more than a TCP connect, so they get longer to
        // settle before the clock starts.
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
        use hyper_util::server::conn::auto;
        use tower::Service as _;

        runtime().block_on(async move {
            let listener = TcpListener::from_std(std_listener).unwrap();
            let app = app();
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

/// See the note in `benches/http1.rs`: every client here is `127.0.0.1`, which
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
        "{CLIENTS} h2c connections over loopback, {}ms per run\n",
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
