//! Who gets the link when there is not enough of it, across all four protocols.
//!
//! The other benchmarks are about CPU: hundreds of connections competing for a
//! schedule. This one is about the wire. Eight clients each download a
//! continuous stream, the link is capped well below what they collectively want,
//! and the question is how the shortfall is divided.
//!
//! The cap is enforced by a token bucket both servers write through, standing in
//! for an interface that cannot be shaped without root on a loopback benchmark.
//! It is deliberately *outside* goalkeeper: the limit is a fact about the host,
//! and goalkeeper is separately told what it is, exactly as a deployment would
//! configure `max_tx_bytes_per_second` to match its uplink. The baseline is
//! subject to the same bucket and simply has nothing to tell.
//!
//! - **2 Mbit/s client to server**, **1 Mbit/s server to client**, asymmetric
//!   like a real access link. Downloads make the 1 Mbit/s direction the binding
//!   one.
//! - Eight clients, one per priority `L0..L7`, so every level is occupied
//!   exactly once and the split is easy to read.
//! - Little CPU work per byte, so nothing here competes for the schedule and
//!   the only scarce thing is the link.
//!
//! Two numbers per protocol:
//!
//! - **top client**: bytes per second reaching the single `L0` client. If
//!   priority governs the link, this is most of the budget; if it does not, it
//!   is a fair share, about an eighth.
//! - **total**: bytes per second across all eight, which the bucket caps and
//!   which should therefore be about the same either way. Here to show that
//!   neither server is starved outright, so the first column is about division
//!   rather than about capacity.
//!
//! # Optional: run it at a realistic round trip
//!
//! Loopback has no delay, which flatters every congestion controller here and
//! QUIC's most of all. To measure under an access link's latency instead, run
//! the built binary in a network namespace. No root, and no interface the host
//! uses is touched:
//!
//! ```text
//! cargo build --benches --release
//! unshare -Urn sh -c 'ip link set lo up \
//!   && /sbin/tc qdisc add dev lo root netem delay 75ms \
//!   && target/release/deps/bandwidth-<hash>'
//! ```

use bytes::Bytes;

use goalkeeper::SystemGoalkeeper;
use goalkeeper::conn::Conn;
use goalkeeper::executor::priority::{Priority, UserPriority};
use goalkeeper::http::ServeHttp;
use goalkeeper::web_transport::ServeWebTransport;
use http_body_util::BodyExt;
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::future::Future;
use std::io::Write as _;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// One client per user priority, so every level is occupied exactly once.
const CLIENTS: usize = 8;
/// Long enough that a 1 Mbit/s link delivers a few hundred kilobytes, which is
/// enough to divide meaningfully.
const RUN: Duration = Duration::from_secs(4);
/// Bytes per write.
///
/// Small enough to interleave, large enough not to be all framing. A megabyte
/// would take the link eight seconds to carry and be the whole measurement.
const CHUNK: usize = 8 * 1024;

/// Server to client, in bytes per second. The binding limit here, since every
/// client is downloading.
const DOWN_BYTES_PER_SECOND: u64 = 1_000_000 / 8;
/// Client to server, in bytes per second.
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

/// A token bucket standing in for the interface.
///
/// One instance per run, shared by every connection that server accepts, so the
/// two servers face the identical constraint. First-come, with no notion of
/// priority, so any ordering in the results has to come from the server above
/// it.
struct Link {
    bytes_per_second: u64,
    /// A `tokio` mutex rather than a `std` one, and held across the wait rather
    /// than around the arithmetic.
    ///
    /// Both are deliberate. A link carries one thing at a time, so serialising
    /// is the model, not a concession. And `tokio`'s mutex is FIFO, which the
    /// first version of this was not: every waiter slept for its own estimate,
    /// they all woke together, and whoever won re-registered first and so won
    /// again, so one client took the entire link and the other seven got
    /// nothing on both servers. Arrival order is the only fair thing a dumb
    /// link can do.
    gate: tokio::sync::Mutex<(f64, Instant)>,
    /// How often a caller had to wait for capacity.
    ///
    /// The diagnostic that says whether the link was the binding constraint at
    /// all. If this is near zero the table below is measuring something else,
    /// and any difference between the two servers is noise rather than policy.
    throttled: AtomicU64,
}

impl Link {
    fn new(bytes_per_second: u64) -> Arc<Self> {
        Arc::new(Self {
            bytes_per_second,
            // Starts empty rather than full, so a burst at t=0 cannot borrow
            // against a second that has not happened.
            gate: tokio::sync::Mutex::new((0.0, Instant::now())),
            throttled: AtomicU64::new(0),
        })
    }

    /// How often this link made somebody wait.
    fn throttles(&self) -> u64 {
        self.throttled.load(Ordering::Relaxed)
    }

    /// Waits its turn, then until `bytes` may be sent, then spends them.
    async fn acquire(&self, bytes: usize) {
        let mut state = self.gate.lock().await;
        loop {
            let (ref mut tokens, ref mut last) = *state;
            let now = Instant::now();
            *tokens += now.duration_since(*last).as_secs_f64() * self.bytes_per_second as f64;
            // Capped at a tenth of a second's worth, so an idle link cannot
            // bank capacity and release it all at once. Never below what is
            // being asked for, though, or a request larger than the ceiling
            // could never be satisfied and the caller would spin forever.
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

/// The payload every protocol sends, over and over.
fn chunk() -> Bytes {
    Bytes::from(vec![0u8; CHUNK])
}

/// What every server's send loop needs, which is now only the flag that ends
/// the run.
///
/// Neither server is limited here. Both write as fast as their own policy
/// allows and both meet the same link at the clients, which is the comparison:
/// given identical capacity, who gets it.
#[derive(Clone)]
struct Wire {
    stop: Arc<AtomicBool>,
    /// Held until every session is established, so no connection is still
    /// handshaking while others are already at full rate.
    ///
    /// The server has one UDP socket for every QUIC connection, so a late
    /// handshake's packets arrive into a buffer that seven saturated
    /// connections are already filling with acknowledgements. Dropped handshake
    /// packets are how a connection fails to establish at all; see the module
    /// docs. Waiting costs nothing that is measured, since the clock starts
    /// after the warm-up either way.
    ready: Arc<tokio::sync::Barrier>,
}

/// The level a connection asked for, from its path.
fn requested_level(path: &str) -> usize {
    path.rsplit('/')
        .next()
        .and_then(|tail| tail.parse::<usize>().ok())
        .unwrap_or(0)
        .min(LEVELS.len() - 1)
}

/// What each client received, and over how long.
struct Report {
    /// Bytes per second reaching the `L0` client.
    top: f64,
    /// Bytes per second reaching all of them.
    total: f64,
    /// How often the link made somebody wait. See [`Link::throttled`].
    throttled: u64,
}

fn report(received: &[u64], elapsed: Duration, throttled: u64) -> Report {
    let seconds = elapsed.as_secs_f64();
    Report {
        top: received.first().copied().unwrap_or(0) as f64 / seconds,
        total: received.iter().sum::<u64>() as f64 / seconds,
        throttled,
    }
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

/// Tells goalkeeper what the link is, and stands down everything that would
/// otherwise refuse eight connections from one loopback address.
///
/// See `benches/http1.rs` and `benches/web_transport.rs` for why the limiter and
/// the handshake registry have to be stood down. The bandwidth configuration is
/// the opposite: it is the one thing here that goalkeeper is *meant* to act on.
fn configure() {
    SystemGoalkeeper.set_handshake_capacity(4096, 4096);
    SystemGoalkeeper.set_handshake_slow_per_ip(4096, 4096);
    // Large rather than `u32::MAX`: a per-second rate is turned into a period
    // by dividing a second by it, and a rate above a billion rounds that period
    // to zero.
    const PLENTY: u32 = 1_000_000_000;
    SystemGoalkeeper.set_address_bandwidth_limits(PLENTY, PLENTY);
    SystemGoalkeeper.set_connections_per_active(PLENTY, PLENTY);
    SystemGoalkeeper.set_total_connection_limits(PLENTY, PLENTY);
    // Under the link, as `max_tx_bytes_per_second`'s documentation advises.
    // Configured at the link exactly, goalkeeper never sees a level exceed its
    // allowance, since the link's own first-come queue has already divided the
    // capacity evenly, so it never gets to choose. The choosing only happens if
    // goalkeeper runs out of budget before the wire does.
    //
    // The price is the difference: whatever headroom is left here is capacity
    // the link could have carried and goalkeeper will not authorise.
    // The same rate the baseline's token bucket runs at, so the two servers are
    // limited equally and only the *division* differs.
    SystemGoalkeeper.set_bandwidth_limits(DOWN_BYTES_PER_SECOND, UP_BYTES_PER_SECOND);
}

// ---------------------------------------------------------------- HTTP shared

/// The app both HTTP servers serve: an endless body, one chunk at a time,
/// each chunk paid for at the link first.
fn http_app(wire: Wire) -> axum::Router {
    use axum::extract::Path;
    use axum::routing::get;

    async fn handler(
        axum::extract::State(wire): axum::extract::State<Wire>,
        conn: Option<axum::Extension<Conn>>,
        Path(level): Path<usize>,
    ) -> axum::response::Response {
        if let Some(axum::Extension(conn)) = conn {
            conn.set_base(Priority::User(LEVELS[level.min(LEVELS.len() - 1)]));
        }
        let stream = futures_util::stream::unfold(wire, |wire| async move {
            // Ends with the run. Without this the body is genuinely infinite, a
            // graceful shutdown has nothing to wait for, and the task outlives
            // the runtime its timers belong to, which panics the next
            // protocol's server when the shared executor polls it.
            if wire.stop.load(Ordering::Relaxed) {
                return None;
            }

            Some((Ok::<_, std::io::Error>(chunk()), wire))
        });
        axum::response::IntoResponse::into_response(axum::body::Body::from_stream(stream))
    }

    axum::Router::new()
        .route("/l/{level}", get(handler))
        .with_state(wire)
}

fn listener() -> (std::net::TcpListener, SocketAddr) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let addr = listener.local_addr().unwrap();
    (listener, addr)
}

/// Runs a server on its own thread while the clients run here, then reports.
///
/// The two get a runtime each, as in the other benchmarks, so the clients are
/// not competing with the server for the schedule under test.
fn measure<S, C, Fut>(spawn_server: S, start_client: C) -> Report
where
    S: FnOnce(Arc<AtomicBool>) + Send + 'static,
    C: Fn(usize, Arc<AtomicBool>, Arc<AtomicU64>, Arc<Link>) -> Fut,
    Fut: Future<Output = ()> + Send + 'static,
{
    let shutdown = Arc::new(AtomicBool::new(false));
    let server = std::thread::spawn({
        let shutdown = Arc::clone(&shutdown);
        move || spawn_server(shutdown)
    });
    let (received, elapsed, throttled) = drive_clients(start_client);
    shutdown.store(true, Ordering::Relaxed);
    let _ = server.join();
    report(&received, elapsed, throttled)
}

/// Serves `app` the way an application would without goalkeeper: hyper's `auto`
/// builder, one bare `tokio::spawn` per connection.
fn baseline_http_server(
    std_listener: std::net::TcpListener,
    app: axum::Router,
    stop: Arc<AtomicBool>,
) {
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

/// Serves `app` through goalkeeper.
fn goalkeeper_http_server(
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
        await_quiet().await;
    }));
}

/// Runs the shared executor until nothing of this server's is left alive.
///
/// The executor is one per process while a runtime is one per protocol here, so
/// a task that outlives its `run_until` is picked up by the next protocol's, on
/// a different thread and against a runtime that no longer exists. Polling one
/// panics inside tokio's timer. `stop` is supposed to have left nothing behind;
/// this checks that it did.
async fn await_quiet() {
    let deadline = Instant::now() + Duration::from_secs(2);
    while SystemGoalkeeper.tasks().alive() > 0 {
        if Instant::now() >= deadline {
            eprintln!("left behind: {:?}", SystemGoalkeeper.tasks());
            return;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

// ------------------------------------------------------------- HTTP/1 clients

/// Reads an endless chunked response, counting bytes, until told to stop.
async fn http1_client(
    addr: SocketAddr,
    level: usize,
    stop: Arc<AtomicBool>,
    got: Arc<AtomicU64>,
    link: Arc<Link>,
) {
    let Ok(mut stream) = TcpStream::connect(addr).await else {
        return;
    };
    let _ = stream.set_nodelay(true);
    let request = format!("GET /l/{level} HTTP/1.1\r\nHost: bench\r\n\r\n");
    if stream.write_all(request.as_bytes()).await.is_err() {
        return;
    }
    // Counts every byte off the wire, framing included. Chunked encoding adds a
    // handful per chunk, identically for both servers.
    let mut buffer = vec![0u8; 64 * 1024];
    while !stop.load(Ordering::Relaxed) {
        match tokio::time::timeout(Duration::from_millis(250), stream.read(&mut buffer)).await {
            Ok(Ok(0)) | Ok(Err(_)) => return,
            Ok(Ok(read)) => {
                link.acquire(read).await;
                got.fetch_add(read as u64, Ordering::Relaxed);
            }
            Err(_) => {}
        }
    }
}

// ------------------------------------------------------------- HTTP/2 clients

async fn http2_client(
    addr: SocketAddr,
    level: usize,
    stop: Arc<AtomicBool>,
    got: Arc<AtomicU64>,
    link: Arc<Link>,
) {
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

    let Ok(request) = hyper::Request::builder()
        .uri(format!("http://bench/l/{level}"))
        .body(http_body_util::Empty::<Bytes>::new())
    else {
        return;
    };
    let Ok(response) = sender.send_request(request).await else {
        return;
    };
    let mut body = response.into_body();
    while !stop.load(Ordering::Relaxed) {
        match tokio::time::timeout(Duration::from_millis(250), body.frame()).await {
            Ok(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    link.acquire(data.len()).await;
                    got.fetch_add(data.len() as u64, Ordering::Relaxed);
                }
            }
            Ok(Some(Err(_))) | Ok(None) => return,
            Err(_) => {}
        }
    }
}

// ---------------------------------------------------------- WebSocket clients

/// Reads endless binary frames, counting payload bytes.
///
/// The handshake and framing are written out for the same reason as in
/// `benches/web_socket.rs`: a client need not verify `Sec-WebSocket-Accept`, and
/// the server's frames are ours.
async fn web_socket_client(
    addr: SocketAddr,
    level: usize,
    stop: Arc<AtomicBool>,
    got: Arc<AtomicU64>,
    link: Arc<Link>,
) {
    let Ok(mut stream) = TcpStream::connect(addr).await else {
        return;
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
        return;
    }
    let mut buffer = vec![0u8; 64 * 1024];
    // Everything after the response headers is frames. Their bytes are counted
    // wholesale rather than parsed: the header is a few bytes per 8KiB chunk and
    // is identical on both servers.
    let mut seen_headers = false;
    while !stop.load(Ordering::Relaxed) {
        match tokio::time::timeout(Duration::from_millis(250), stream.read(&mut buffer)).await {
            Ok(Ok(0)) | Ok(Err(_)) => return,
            Ok(Ok(read)) => {
                link.acquire(read).await;
                if seen_headers {
                    got.fetch_add(read as u64, Ordering::Relaxed);
                } else if let Some(end) = buffer[..read].windows(4).position(|w| w == b"\r\n\r\n") {
                    seen_headers = true;
                    got.fetch_add((read - end - 4) as u64, Ordering::Relaxed);
                }
            }
            Err(_) => {}
        }
    }
}

// ------------------------------------------------------- WebTransport clients

async fn web_transport_client(
    port: u16,
    level: usize,
    stop: Arc<AtomicBool>,
    got: Arc<AtomicU64>,
    link: Arc<Link>,
) {
    let config = wtransport::ClientConfig::builder()
        .with_bind_default()
        .with_no_cert_validation()
        .build();
    let Ok(endpoint) = wtransport::Endpoint::client(config) else {
        return;
    };
    // The v4 literal: goalkeeper's endpoint binds `0.0.0.0`. See
    // `benches/web_transport.rs`.
    let Ok(connection) = endpoint
        .connect(format!("https://127.0.0.1:{port}/l/{level}"))
        .await
    else {
        return;
    };
    let Ok(mut recv) = connection.accept_uni().await else {
        return;
    };
    let mut buffer = vec![0u8; 64 * 1024];
    while !stop.load(Ordering::Relaxed) {
        match tokio::time::timeout(Duration::from_millis(250), recv.read(&mut buffer)).await {
            Ok(Ok(Some(read))) => {
                link.acquire(read).await;
                got.fetch_add(read as u64, Ordering::Relaxed);
            }
            Ok(Ok(None)) | Ok(Err(_)) => return,
            Err(_) => {}
        }
    }
}

// ------------------------------------------------------------------ harnesses

/// Runs the eight clients and reports what each received.
///
/// `start` is given each client's index and level and returns its future; the
/// counters are per client so the top one can be told apart.
///
/// The link lives here, on the *client* side, and every client pays it for
/// every byte it reads. That is the only place it can honestly go. Below both
/// servers it is a downlink both of them face identically; above either one it
/// would divide the capacity before that server ever saw it, as an earlier
/// version did. That meant neither server's own policy could matter, and that
/// the one server without a link of its own was free to exceed the cap the
/// other was held to.
fn drive_clients<F, Fut>(start: F) -> (Vec<u64>, Duration, u64)
where
    F: Fn(usize, Arc<AtomicBool>, Arc<AtomicU64>, Arc<Link>) -> Fut,
    Fut: Future<Output = ()> + Send + 'static,
{
    let stop = Arc::new(AtomicBool::new(false));
    let link = Link::new(DOWN_BYTES_PER_SECOND);
    let counters: Vec<_> = (0..CLIENTS).map(|_| Arc::new(AtomicU64::new(0))).collect();

    runtime().block_on(async {
        let tasks: Vec<_> = counters
            .iter()
            .enumerate()
            .map(|(index, counter)| {
                tokio::spawn(start(
                    index,
                    Arc::clone(&stop),
                    Arc::clone(counter),
                    Arc::clone(&link),
                ))
            })
            .collect();

        // Lets every stream establish before the clock starts, so setup is not
        // counted against the link.
        tokio::time::sleep(Duration::from_millis(750)).await;
        let baseline: Vec<u64> = counters
            .iter()
            .map(|counter| counter.load(Ordering::Relaxed))
            .collect();
        let started = Instant::now();

        tokio::time::sleep(RUN).await;
        let elapsed = started.elapsed();
        let received: Vec<u64> = counters
            .iter()
            .zip(&baseline)
            .map(|(counter, before)| counter.load(Ordering::Relaxed).saturating_sub(*before))
            .collect();

        stop.store(true, Ordering::Relaxed);
        for task in tasks {
            let _ = task.await;
        }
        (received, elapsed, link.throttles())
    })
}

// ------------------------------------------------------------- the protocols

/// A [`Wire`] for one run, from the shutdown flag the harness owns.
fn wire(stop: Arc<AtomicBool>) -> Wire {
    Wire {
        stop,
        ready: Arc::new(tokio::sync::Barrier::new(CLIENTS)),
    }
}

fn http1_on_goalkeeper() -> Report {
    let (std_listener, addr) = listener();
    measure(
        move |stop| goalkeeper_http_server(std_listener, http_app(wire(stop.clone())), stop),
        move |index, stop, got, link| http1_client(addr, index, stop, got, link),
    )
}

fn http1_on_baseline() -> Report {
    let (std_listener, addr) = listener();
    measure(
        move |stop| baseline_http_server(std_listener, http_app(wire(stop.clone())), stop),
        move |index, stop, got, link| http1_client(addr, index, stop, got, link),
    )
}

fn http2_on_goalkeeper() -> Report {
    let (std_listener, addr) = listener();
    measure(
        move |stop| goalkeeper_http_server(std_listener, http_app(wire(stop.clone())), stop),
        move |index, stop, got, link| http2_client(addr, index, stop, got, link),
    )
}

fn http2_on_baseline() -> Report {
    let (std_listener, addr) = listener();
    measure(
        move |stop| baseline_http_server(std_listener, http_app(wire(stop.clone())), stop),
        move |index, stop, got, link| http2_client(addr, index, stop, got, link),
    )
}

/// The send loop both WebSocket servers run, until the run ends.
async fn web_socket_stream<S>(mut socket: S, wire: Wire)
where
    S: futures_util::Sink<axum_tws::Message> + Unpin,
{
    use futures_util::SinkExt;
    while !wire.stop.load(Ordering::Relaxed) {
        if socket
            .send(axum_tws::Message::binary(chunk()))
            .await
            .is_err()
        {
            return;
        }
    }
}

fn goalkeeper_web_socket_app(wire: Wire) -> axum::Router {
    use axum::extract::{Path, State};
    use axum::routing::any;

    async fn handler(
        State(wire): State<Wire>,
        upgrade: goalkeeper::http::web_socket::WebSocketUpgrade,
        Path(level): Path<usize>,
    ) -> axum::response::Response {
        let level = LEVELS[level.min(LEVELS.len() - 1)];
        upgrade.conn().set_base(Priority::User(level));
        upgrade.on_upgrade(Priority::User(level), move |socket| {
            web_socket_stream(socket, wire)
        })
    }

    axum::Router::new()
        .route("/l/{level}", any(handler))
        .with_state(wire)
}

fn baseline_web_socket_app(wire: Wire) -> axum::Router {
    use axum::extract::{Path, State};
    use axum::routing::any;

    async fn handler(
        State(wire): State<Wire>,
        upgrade: axum_tws::WebSocketUpgrade,
        Path(_level): Path<usize>,
    ) -> axum::response::Response {
        // The level is parsed and discarded: there is nowhere for it to go.
        upgrade.on_upgrade(move |socket| web_socket_stream(socket, wire))
    }

    axum::Router::new()
        .route("/l/{level}", any(handler))
        .with_state(wire)
}

fn web_socket_on_goalkeeper() -> Report {
    let (std_listener, addr) = listener();
    measure(
        move |stop| {
            let app = goalkeeper_web_socket_app(wire(stop.clone()));
            goalkeeper_http_server(std_listener, app, stop)
        },
        move |index, stop, got, link| web_socket_client(addr, index, stop, got, link),
    )
}

fn web_socket_on_baseline() -> Report {
    let (std_listener, addr) = listener();
    measure(
        move |stop| {
            let app = baseline_web_socket_app(wire(stop.clone()));
            baseline_http_server(std_listener, app, stop)
        },
        move |index, stop, got, link| web_socket_client(addr, index, stop, got, link),
    )
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

/// A free UDP port, released before the baseline server binds it.
fn free_port() -> u16 {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.local_addr().unwrap().port()
}

fn wt_identity() -> wtransport::Identity {
    wtransport::Identity::self_signed(["localhost", "127.0.0.1", "::1"]).unwrap()
}

/// The baseline still takes a whole `wtransport::ServerConfig`, because it *is*
/// a bare wtransport endpoint.
fn wt_server_config(port: u16, identity: &wtransport::Identity) -> wtransport::ServerConfig {
    wtransport::ServerConfig::builder()
        .with_bind_default(port)
        .with_identity(identity.clone_identity())
        .build()
}

/// The identity as the hot-swappable `TlsConfig` goalkeeper's server takes.
fn wt_tls_config(identity: &wtransport::Identity) -> goalkeeper::http::tls::TlsConfig {
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

/// The endless send loop both WebTransport servers run, on a unidirectional
/// stream the server opens.
async fn web_transport_stream(
    connection: &goalkeeper::web_transport::GovernedConnection,
    wire: Wire,
) {
    // The governed connection's own `open_uni`, so the stream is rationed the
    // same way a TCP socket is, by delaying the write. Every stream on the
    // connection shares that one ration.
    let Ok(send) = connection.open_uni().await else {
        return;
    };
    pump(send, wire).await;
}

/// The same loop on a bare connection, for the baseline, which has no ration to
/// apply and so opens its stream the ordinary way.
async fn baseline_web_transport_stream(connection: &wtransport::Connection, wire: Wire) {
    let Ok(opening) = connection.open_uni().await else {
        return;
    };
    let Ok(send) = opening.await else {
        return;
    };
    pump(send, wire).await;
}

/// Writes until the run ends.
async fn pump<S: tokio::io::AsyncWrite + Unpin>(send: S, wire: Wire) {
    let mut send = send;
    let payload = chunk();

    // Every session established before any of them sends. Bounded, so a
    // connection that never arrives delays the others by this much rather than
    // holding them forever.
    let _ = tokio::time::timeout(Duration::from_millis(500), wire.ready.wait()).await;

    while !wire.stop.load(Ordering::Relaxed) {
        if send.write_all(&payload).await.is_err() {
            return;
        }
    }
}

fn web_transport_on_goalkeeper() -> Report {
    let (socket, port) = bound();
    let identity = wt_identity();

    measure(
        move |stop| {
            let wire = wire(Arc::clone(&stop));
            runtime().block_on(SystemGoalkeeper.run_until(async move {
                let tls = wt_tls_config(&identity);
                let handler = move |session: goalkeeper::web_transport::Session| {
                    let wire = wire.clone();
                    async move {
                        let level = requested_level(session.request().path());
                        session.conn().set_base(Priority::User(LEVELS[level]));
                        // Accepting bounds the flow-control windows to a fair
                        // share and installs the governor. The stream opened
                        // below is rationed the same way a TCP socket is, by
                        // delaying the write. The windows are the coarse second
                        // line, not the mechanism.
                        let Ok(connection) = session.accept().await else {
                            return;
                        };
                        web_transport_stream(&connection, wire).await;
                    }
                };
                let mut serving = SystemGoalkeeper
                    .serve_web_transport(socket, tls, handler)
                    .spawn()
                    .unwrap();
                while !stop.load(Ordering::Relaxed) {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                serving.stop().await;
                await_quiet().await;
            }));
        },
        move |index, stop, got, link| web_transport_client(port, index, stop, got, link),
    )
}

fn web_transport_on_baseline() -> Report {
    let port = free_port();
    let identity = wt_identity();

    measure(
        move |stop| {
            let wire = wire(Arc::clone(&stop));
            runtime().block_on(async move {
                let Ok(endpoint) = wtransport::Endpoint::server(wt_server_config(port, &identity))
                else {
                    return;
                };
                loop {
                    let accepted =
                        tokio::time::timeout(Duration::from_millis(5), endpoint.accept()).await;
                    if stop.load(Ordering::Relaxed) {
                        return;
                    }
                    let Ok(incoming) = accepted else {
                        continue;
                    };
                    let wire = wire.clone();
                    tokio::spawn(async move {
                        let Ok(request) = incoming.await else {
                            return;
                        };
                        let _ = requested_level(request.path());
                        let Ok(connection) = request.accept().await else {
                            return;
                        };
                        baseline_web_transport_stream(&connection, wire).await;
                    });
                }
            });
        },
        move |index, stop, got, link| web_transport_client(port, index, stop, got, link),
    )
}

fn main() {
    configure();
    println!(
        "{CLIENTS} downloading clients, one per priority, {}s per run",
        RUN.as_secs()
    );
    println!(
        "link: {} kB/s down, {} kB/s up\n",
        DOWN_BYTES_PER_SECOND / 1000,
        UP_BYTES_PER_SECOND / 1000
    );
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
        (
            "web_socket",
            web_socket_on_goalkeeper,
            web_socket_on_baseline,
        ),
        (
            "web_transport",
            web_transport_on_goalkeeper,
            web_transport_on_baseline,
        ),
    ] {
        let goalkeeper = gk();
        let tokio = tk();
        // The last pair is the diagnostic: if the link never made anybody wait,
        // it was not the binding constraint and the rest of the row is
        // measuring something other than what it claims to.
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
