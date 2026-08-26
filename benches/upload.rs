//! Who gets the *uplink* when there is not enough of it.
//!
//! The mirror of `benches/bandwidth.rs`. There, eight clients download and the
//! scarce direction is the server's egress; here they upload, and the scarce
//! direction is its ingress, which goalkeeper has rationed from the beginning,
//! since parking a read is the one thing a server can always do.
//!
//! Worth measuring separately rather than assuming, because the download case
//! taught the opposite lesson: five of the six defects found there were
//! invisible to reasoning and obvious under load.
//!
//! The link sits on the clients' *send* path, which is where an uplink is, and
//! is the same token bucket for both servers. Backpressure does the rest: a
//! connection goalkeeper declines to read fills its socket buffer, its client's
//! writes block, and it stops drawing on the link, so the capacity it is not
//! given goes to somebody else rather than being wasted. That is the whole
//! difference from egress, where the server had to be stopped before it wrote.
//!
//! - **2 Mbit/s** client to server, the same asymmetric link.
//! - Eight clients, one per priority `L0..L7`.
//! - Bytes are counted *at the server*, per level, since that is where the
//!   question is answered.

use bytes::Bytes;
use futures_util::StreamExt;

use goalkeeper::SystemGoalkeeper;
use goalkeeper::conn::Conn;
use goalkeeper::executor::priority::{Priority, UserPriority};
use goalkeeper::http::ServeHttp;
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::io::Write as _;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

/// One client per user priority.
const CLIENTS: usize = 8;
/// Long enough for a 2 Mbit/s link to carry a megabyte or so.
const RUN: Duration = Duration::from_secs(4);
/// Bytes per write.
const CHUNK: usize = 8 * 1024;
/// Client to server, in bytes per second. The binding limit here.
const UP_BYTES_PER_SECOND: u64 = 2_000_000 / 8;

const LEVELS: [UserPriority; CLIENTS] = [
    UserPriority::L0,
    UserPriority::L1,
    UserPriority::L2,
    UserPriority::L3,
    UserPriority::L4,
    UserPriority::L5,
    UserPriority::L6,
    UserPriority::L7,
];

/// The uplink, shared by every client and blind to priority. See
/// `benches/bandwidth.rs` for why it is a `tokio` mutex held across the wait.
struct Link {
    bytes_per_second: u64,
    gate: tokio::sync::Mutex<(f64, Instant)>,
    throttled: AtomicU64,
}

impl Link {
    fn new(bytes_per_second: u64) -> Arc<Self> {
        Arc::new(Self {
            bytes_per_second,
            gate: tokio::sync::Mutex::new((0.0, Instant::now())),
            throttled: AtomicU64::new(0),
        })
    }

    fn throttles(&self) -> u64 {
        self.throttled.load(Ordering::Relaxed)
    }

    async fn acquire(&self, bytes: usize) {
        let mut state = self.gate.lock().await;
        loop {
            let (ref mut tokens, ref mut last) = *state;
            let now = Instant::now();
            *tokens += now.duration_since(*last).as_secs_f64() * self.bytes_per_second as f64;
            let ceiling = (self.bytes_per_second as f64 / 10.0).max(bytes as f64);
            *tokens = tokens.min(ceiling);
            *last = now;

            if *tokens >= bytes as f64 {
                *tokens -= bytes as f64;
                return;
            }
            self.throttled.fetch_add(1, Ordering::Relaxed);
            let wait =
                Duration::from_secs_f64((bytes as f64 - *tokens) / self.bytes_per_second as f64);
            tokio::time::sleep(wait.max(Duration::from_millis(1))).await;
        }
    }
}

/// Bytes the server has received, by the level the sender asked for.
type Received = Arc<Vec<AtomicU64>>;

fn received() -> Received {
    Arc::new((0..CLIENTS).map(|_| AtomicU64::new(0)).collect())
}

struct Report {
    /// Bytes per second arriving from the `L0` client.
    top: f64,
    /// Bytes per second arriving from all of them.
    total: f64,
    /// How often the uplink made somebody wait.
    throttled: u64,
}

fn report(counts: &Received, elapsed: Duration, throttled: u64) -> Report {
    let seconds = elapsed.as_secs_f64();
    let total: u64 = counts.iter().map(|c| c.load(Ordering::Relaxed)).sum();
    Report {
        top: counts[0].load(Ordering::Relaxed) as f64 / seconds,
        total: total as f64 / seconds,
        throttled,
    }
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

/// See `benches/bandwidth.rs`: everything that would refuse eight connections
/// from one loopback address is stood down, and the ration is the one thing
/// goalkeeper is meant to act on.
fn configure() {
    // No handshake pool to stand down: this serves plaintext, and the pool is
    // behind `tls` because crypto is the only thing it rations.
    // Large rather than `u32::MAX`: a per-second rate is turned into a period
    // by dividing a second by it, and a rate above a billion rounds that period
    // to zero.
    const PLENTY: u32 = 1_000_000_000;
    SystemGoalkeeper.set_address_bandwidth_limits(PLENTY, PLENTY);
    SystemGoalkeeper.set_connections_per_active(PLENTY, PLENTY);
    SystemGoalkeeper.set_total_connection_limits(PLENTY, PLENTY);
    // Under the uplink, not equal to it.
    //
    // Set equal, goalkeeper can only reorder at the margin: the link's own
    // first-come sharing already holds every level well below its allowance, so
    // nothing is ever throttled and the split stays even. It has to run out of
    // budget before the wire does, which is what `max_rx_bytes_per_second`'s
    // documentation says and what the download benchmark found the hard way.
    //
    // What makes that work on ingress is backpressure: a level goalkeeper
    // stops reading fills its socket buffer, its client's writes block, and it
    // stops drawing on the link, so the capacity it gives up is left to the
    // levels still being read rather than spread evenly over everybody.
    SystemGoalkeeper.set_bandwidth_limits(UP_BYTES_PER_SECOND, UP_BYTES_PER_SECOND * 2 / 5);
}

// ---------------------------------------------------------------------- HTTP

/// The app both HTTP servers serve: read an endless request body, counting it.
fn http_app(counts: Received) -> axum::Router {
    use axum::extract::{Path, State};
    use axum::routing::post;

    async fn handler(
        State(counts): State<Received>,
        conn: Option<axum::Extension<Conn>>,
        Path(level): Path<usize>,
        body: axum::body::Body,
    ) -> &'static str {
        let level = level.min(LEVELS.len() - 1);
        if let Some(axum::Extension(conn)) = conn {
            conn.set_base(Priority::User(LEVELS[level]));
        }
        let mut stream = body.into_data_stream();
        while let Some(Ok(chunk)) = stream.next().await {
            counts[level].fetch_add(chunk.len() as u64, Ordering::Relaxed);
        }
        "done"
    }

    axum::Router::new()
        .route("/l/{level}", post(handler))
        .with_state(counts)
}

/// One client: a chunked POST that never ends, paced by the uplink.
async fn http1_client(addr: SocketAddr, level: usize, stop: Arc<AtomicBool>, link: Arc<Link>) {
    let Ok(mut stream) = TcpStream::connect(addr).await else {
        return;
    };
    let _ = stream.set_nodelay(true);
    let head = format!(
        "POST /l/{level} HTTP/1.1\r\n\
         Host: bench\r\n\
         Transfer-Encoding: chunked\r\n\r\n"
    );
    if stream.write_all(head.as_bytes()).await.is_err() {
        return;
    }

    // One chunked-encoding frame, built once.
    let mut frame = format!("{CHUNK:x}\r\n").into_bytes();
    frame.extend_from_slice(&vec![0u8; CHUNK]);
    frame.extend_from_slice(b"\r\n");

    while !stop.load(Ordering::Relaxed) {
        link.acquire(frame.len()).await;
        // Bounded, so a client goalkeeper has stopped reading still notices
        // `stop` instead of blocking on a socket buffer that will never drain.
        match tokio::time::timeout(Duration::from_millis(250), stream.write_all(&frame)).await {
            Ok(Ok(())) => {}
            Ok(Err(_)) => return,
            Err(_) => {}
        }
    }
}

async fn http2_client(addr: SocketAddr, level: usize, stop: Arc<AtomicBool>, link: Arc<Link>) {
    use http_body_util::StreamBody;
    use hyper::body::Frame;

    let Ok(stream) = TcpStream::connect(addr).await else {
        return;
    };
    let _ = stream.set_nodelay(true);
    let Ok((mut sender, connection)) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(stream)).await
    else {
        return;
    };
    tokio::spawn(connection);

    // An endless body, each frame paid for at the uplink first. Boxed because
    // hyper wants the body `Unpin` and an `unfold` holding an `async` block is
    // not.
    let body = StreamBody::new(Box::pin(futures_util::stream::unfold(
        (link, stop),
        |(link, stop)| async move {
            if stop.load(Ordering::Relaxed) {
                return None;
            }
            link.acquire(CHUNK).await;
            let frame = Frame::data(Bytes::from(vec![0u8; CHUNK]));
            Some((Ok::<_, std::io::Error>(frame), (link, stop)))
        },
    )));

    let Ok(request) = hyper::Request::builder()
        .method("POST")
        .uri(format!("http://bench/l/{level}"))
        .body(body)
    else {
        return;
    };
    let _ = sender.send_request(request).await;
}

// ----------------------------------------------------------------- harnesses

fn listener() -> (std::net::TcpListener, SocketAddr) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let addr = listener.local_addr().unwrap();
    (listener, addr)
}

fn baseline_server(std_listener: std::net::TcpListener, app: axum::Router, stop: Arc<AtomicBool>) {
    use hyper_util::server::conn::auto;
    use tower::Service as _;

    runtime().block_on(async move {
        let listener = TcpListener::from_std(std_listener).unwrap();
        loop {
            let accepted = tokio::time::timeout(Duration::from_millis(5), listener.accept()).await;
            if stop.load(Ordering::Relaxed) {
                return;
            }
            let Ok(Ok((stream, _))) = accepted else {
                continue;
            };
            let _ = stream.set_nodelay(true);
            let app = app.clone();
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let service = hyper::service::service_fn(move |request| app.clone().call(request));
                let _ = auto::Builder::new(TokioExecutor::new())
                    .serve_connection_with_upgrades(io, service)
                    .await;
            });
        }
    });
}

fn goalkeeper_server(
    std_listener: std::net::TcpListener,
    app: axum::Router,
    stop: Arc<AtomicBool>,
) {
    runtime().block_on(SystemGoalkeeper.run_until(async move {
        let listener = TcpListener::from_std(std_listener).unwrap();
        let mut serving = SystemGoalkeeper.serve_http(listener, app).spawn();
        while !stop.load(Ordering::Relaxed) {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        serving.stop().await;
        // See `benches/bandwidth.rs`: a task outliving its runtime panics
        // whoever polls it next.
        let deadline = Instant::now() + Duration::from_secs(2);
        while SystemGoalkeeper.tasks().alive() > 0 && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }));
}

/// Runs the eight uploading clients against a server on its own thread.
fn measure<S, C, Fut>(spawn_server: S, counts: Received, start_client: C) -> Report
where
    S: FnOnce(Arc<AtomicBool>) + Send + 'static,
    C: Fn(usize, Arc<AtomicBool>, Arc<Link>) -> Fut,
    Fut: Future<Output = ()> + Send + 'static,
{
    let shutdown = Arc::new(AtomicBool::new(false));
    let server = std::thread::spawn({
        let shutdown = Arc::clone(&shutdown);
        move || spawn_server(shutdown)
    });

    let stop = Arc::new(AtomicBool::new(false));
    let link = Link::new(UP_BYTES_PER_SECOND);
    let elapsed = runtime().block_on({
        let counts = Arc::clone(&counts);
        let link = Arc::clone(&link);
        let stop = Arc::clone(&stop);
        async move {
            let tasks: Vec<_> = (0..CLIENTS)
                .map(|index| {
                    tokio::spawn(start_client(index, Arc::clone(&stop), Arc::clone(&link)))
                })
                .collect();

            // Lets every upload establish before the clock starts.
            tokio::time::sleep(Duration::from_millis(750)).await;
            let baseline: Vec<u64> = counts.iter().map(|c| c.load(Ordering::Relaxed)).collect();
            let started = Instant::now();

            tokio::time::sleep(RUN).await;
            let elapsed = started.elapsed();
            // Rebased, so the warm-up is not counted.
            for (counter, before) in counts.iter().zip(&baseline) {
                let now = counter.load(Ordering::Relaxed);
                counter.store(now.saturating_sub(*before), Ordering::Relaxed);
            }

            stop.store(true, Ordering::Relaxed);
            for task in tasks {
                let _ = task.await;
            }
            elapsed
        }
    });

    shutdown.store(true, Ordering::Relaxed);
    let _ = server.join();
    report(&counts, elapsed, link.throttles())
}

use std::future::Future;

fn http1_on_goalkeeper() -> Report {
    let (std_listener, addr) = listener();
    let counts = received();
    let app = http_app(Arc::clone(&counts));
    measure(
        move |stop| goalkeeper_server(std_listener, app, stop),
        counts,
        move |index, stop, link| http1_client(addr, index, stop, link),
    )
}

fn http1_on_baseline() -> Report {
    let (std_listener, addr) = listener();
    let counts = received();
    let app = http_app(Arc::clone(&counts));
    measure(
        move |stop| baseline_server(std_listener, app, stop),
        counts,
        move |index, stop, link| http1_client(addr, index, stop, link),
    )
}

fn http2_on_goalkeeper() -> Report {
    let (std_listener, addr) = listener();
    let counts = received();
    let app = http_app(Arc::clone(&counts));
    measure(
        move |stop| goalkeeper_server(std_listener, app, stop),
        counts,
        move |index, stop, link| http2_client(addr, index, stop, link),
    )
}

fn http2_on_baseline() -> Report {
    let (std_listener, addr) = listener();
    let counts = received();
    let app = http_app(Arc::clone(&counts));
    measure(
        move |stop| baseline_server(std_listener, app, stop),
        counts,
        move |index, stop, link| http2_client(addr, index, stop, link),
    )
}

fn main() {
    configure();
    println!(
        "{CLIENTS} uploading clients, one per priority, {}s per run",
        RUN.as_secs()
    );
    println!("uplink: {} kB/s\n", UP_BYTES_PER_SECOND / 1000);
    println!("                  top client (kB/s)        total (kB/s)        link throttled");
    println!("  protocol        goalkeeper    tokio     goalkeeper    tokio     gk     tokio");
    println!("  -------------   ----------  -------     ----------  -------   -----   -----");

    for (name, gk, tk) in [
        (
            "http1",
            http1_on_goalkeeper as fn() -> Report,
            http1_on_baseline as fn() -> Report,
        ),
        ("http2", http2_on_goalkeeper, http2_on_baseline),
    ] {
        let goalkeeper = gk();
        let tokio = tk();
        println!(
            "  {name:<13}   {:>10.1}  {:>7.1}     {:>10.1}  {:>7.1}   {:>5}   {:>5}",
            goalkeeper.top / 1000.0,
            tokio.top / 1000.0,
            goalkeeper.total / 1000.0,
            tokio.total / 1000.0,
            goalkeeper.throttled,
            tokio.throttled,
        );
        std::io::stdout().flush().unwrap();
    }
}
