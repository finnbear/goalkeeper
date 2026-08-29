//! A flood against a real goalkeeper server, from a few hundred addresses, on
//! this machine and without privileges.
//!
//! Per-address limits are the interesting half of this crate and the hard half
//! to demonstrate, because a loopback test normally has exactly one address to
//! work with: every client is `127.0.0.1`, so an attacker and a crowd look
//! identical. This gives each simulated attacker an address of its own.
//!
//! # How the addresses work
//!
//! Linux gives `lo` the whole of `127.0.0.0/8`, not just `127.0.0.1`, so every
//! address in it is already local and bindable. A client picks a source address
//! out of `127.42.0.0/16` and binds it; nothing is added to an interface and
//! nothing needs root.
//!
//! Other platforms alias only `127.0.0.1`, so this is Linux-only.
//!
//! # What it shows
//!
//! Sixteen behaviours, each from [`ADDRESSES_EACH`] addresses, plus one
//! well-behaved client as the control. The report says how many connections
//! each behaviour got through and how many goalkeeper withheld. The point is
//! the first row of the summary: the polite client is refused nothing, while
//! the address beside it attempting hundreds of thousands of connections is
//! refused almost every time.
//!
//! The server runs alone on a single-threaded runtime, which is the shape
//! goalkeeper is built for, and the flood runs on a multi-threaded one with the
//! rest of the machine. Sharing a runtime would have measured the two competing
//! for a thread rather than what the limits do.
//!
//! This listener is plaintext, so nothing here reaches the handshake pool —
//! that is behind `tls`, since crypto is the only thing it rations.

use axum::http::StatusCode;
use axum::response::IntoResponse;
use goalkeeper::SystemGoalkeeper;
use goalkeeper::executor::priority::{Priority, UserPriority};
use goalkeeper::http::ServeHttp;
use goalkeeper::http::web_socket::{Limits, WebSocketUpgrade};
use goalkeeper::rate_limiter::RateLimiterProps;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream};

/// How long the flood runs before the summary.
const RUN: Duration = Duration::from_secs(20);

/// How often the running report is printed.
const REPORT: Duration = Duration::from_secs(2);

/// How often goalkeeper's own view of the process is printed.
///
/// Its own cadence rather than a column on [`REPORT`], since it answers a
/// different question: that report says what the limiter did, this says what it
/// currently believes about the host.
const PRESSURE: Duration = Duration::from_secs(3);

/// Addresses each behaviour attacks from, so a per-address limit is not the
/// only thing being measured.
const ADDRESSES_EACH: u16 = 12;

/// Connections a hoarding client opens at once.
const HOARD: usize = 10;

/// What one cohort of attackers does. Sixteen cohorts, one per combination.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
struct Behaviour {
    /// Opens many connections at once and keeps them, which is what
    /// `set_connections_per_active` bounds.
    hoard: bool,
    /// Reconnects the moment it is disconnected, which is what the per-address
    /// connect cost bounds.
    churn: bool,
    /// Connects and then says nothing, holding a permit and a connection task
    /// without ever asking for anything. What hyper's header read timeout is
    /// for, and what the per-address connection ceiling bounds meanwhile.
    mute: bool,
    /// Sends as fast as it is allowed to, which is what the byte ration bounds.
    flood: bool,
}

impl Behaviour {
    /// The `n`th combination of the four.
    fn nth(n: usize) -> Self {
        Self {
            hoard: n & 0b0001 != 0,
            churn: n & 0b0010 != 0,
            mute: n & 0b0100 != 0,
            flood: n & 0b1000 != 0,
        }
    }

    /// A short label, or `polite` for the control.
    fn label(&self) -> String {
        let mut parts = Vec::new();
        for (set, name) in [
            (self.hoard, "hoard"),
            (self.churn, "churn"),
            (self.mute, "mute"),
            (self.flood, "flood"),
        ] {
            if set {
                parts.push(name);
            }
        }
        if parts.is_empty() {
            "polite".to_owned()
        } else {
            parts.join("+")
        }
    }
}

/// What one cohort managed, which is the number the limits are judged by.
#[derive(Default, Debug)]
struct Tally {
    /// Sockets that connected at the TCP level.
    connected: AtomicU64,
    /// Of those, the ones goalkeeper let reach a WebSocket.
    upgraded: AtomicU64,
    /// Messages echoed back, so a throttled client is visibly slower rather
    /// than merely refused.
    echoed: AtomicU64,
    /// Connections refused outright, whether by a closed socket or a `429`.
    refused: AtomicU64,
}

fn main() {
    env_logger::builder()
        .filter_level(log::LevelFilter::Warn)
        .init();

    if !cfg!(target_os = "linux") {
        eprintln!("this example needs Linux, where 127.0.0.0/8 is all loopback");
        return;
    }

    let stop = Arc::new(AtomicBool::new(false));
    let (ready, address) = std::sync::mpsc::channel();

    // The server gets a thread and a single-threaded runtime, which is what
    // goalkeeper is for: one schedule, deciding what to spend it on. The
    // attackers get everything else. Sharing a runtime would have measured the
    // two competing for one thread rather than what the limits do.
    let server = std::thread::spawn({
        let stop = Arc::clone(&stop);
        move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(SystemGoalkeeper.run_until(serve(ready, stop)));
        }
    });

    let server_addr = address.recv().expect("the server did not start");
    println!("serving on {server_addr}, flooding for {RUN:?}\n");

    // As many threads as the machine has, so the flood is genuinely outside the
    // thing defending against it.
    let clients = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let (cohorts, tallies) = clients.block_on(flood(server_addr, Arc::clone(&stop)));

    stop.store(true, Ordering::Relaxed);
    drop(clients);
    server.join().unwrap();

    println!("\n  behaviour               connected  upgraded   echoed  refused");
    println!("  ----------------------  ---------  --------  -------  -------");
    for (behaviour, tally) in cohorts.iter().zip(&tallies) {
        println!(
            "  {:<22}  {:>9}  {:>8}  {:>7}  {:>7}",
            behaviour.label(),
            tally.connected.load(Ordering::Relaxed),
            tally.upgraded.load(Ordering::Relaxed),
            tally.echoed.load(Ordering::Relaxed),
            tally.refused.load(Ordering::Relaxed),
        );
    }
    println!("\nthe first row is the control: it shares the host with all the rest");
}

/// The defended side: configure, listen, and hold it open until told to stop.
async fn serve(ready: std::sync::mpsc::Sender<SocketAddr>, stop: Arc<AtomicBool>) {
    // Per-address limits do the shedding. The global ceiling is deliberately
    // well clear of what this offers it: reaching a *global* cap is a bad day
    // for everyone, since it refuses the next arrival whoever it is, and the
    // per-address limits exist to keep the host away from it.
    SystemGoalkeeper.set_connections_per_active(2, 6);
    SystemGoalkeeper.set_total_connection_limits(4_000, 8_000);
    SystemGoalkeeper.set_address_bandwidth_limits(64 * 1024, 128 * 1024);
    SystemGoalkeeper.set_custom_limit(RateLimiterProps::new(Duration::from_secs(1), 3));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    ready.send(listener.local_addr().unwrap()).unwrap();
    let mut server = SystemGoalkeeper.serve_http(listener, app()).spawn();

    while !stop.load(Ordering::Relaxed) {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let _ = tokio::time::timeout(Duration::from_secs(2), server.stop()).await;
}

/// The attacking side, on a runtime of its own.
async fn flood(server: SocketAddr, stop: Arc<AtomicBool>) -> (Vec<Behaviour>, Vec<Arc<Tally>>) {
    // The control first, so it is the top row of the report.
    let cohorts: Vec<Behaviour> = std::iter::once(Behaviour::default())
        .chain((1..16).map(Behaviour::nth))
        .collect();

    let mut tallies = Vec::new();
    let mut address = 0u16;
    for behaviour in &cohorts {
        let tally = Arc::new(Tally::default());
        tallies.push(Arc::clone(&tally));
        for _ in 0..ADDRESSES_EACH {
            let source = nth_address(address);
            address += 1;
            for _ in 0..if behaviour.hoard { HOARD } else { 1 } {
                tokio::spawn(attack(
                    *behaviour,
                    source,
                    server,
                    Arc::clone(&tally),
                    Arc::clone(&stop),
                ));
            }
        }
    }

    // Two cadences against one deadline. `interval_at` rather than `interval`
    // because the latter fires immediately, which would print both lines before
    // a single client had connected.
    let started = tokio::time::Instant::now();
    let mut reports = tokio::time::interval_at(started + REPORT, REPORT);
    let mut pressures = tokio::time::interval_at(started + PRESSURE, PRESSURE);
    let mut deadline = std::pin::pin!(tokio::time::sleep_until(started + RUN));
    loop {
        tokio::select! {
            _ = &mut deadline => break,
            _ = reports.tick() => report(),
            _ = pressures.tick() => pressure(),
        }
    }
    (cohorts, tallies)
}

/// The server: an echo, and an upgrade to it.
fn app() -> axum::Router {
    use axum::routing::any;

    async fn upgrade(upgrade: WebSocketUpgrade) -> axum::response::Response {
        // The one expensive thing an unauthenticated peer can ask for
        // repeatedly, so it is charged against the address before anything is
        // spent on it.
        if SystemGoalkeeper.should_limit_custom(upgrade.conn().ip(), 1) {
            return (StatusCode::TOO_MANY_REQUESTS, "too many requests").into_response();
        }
        upgrade
            .limits(Limits::default().max_payload_len(Some(16 * 1024)))
            // Taking the upgrade is what earns the address an active session,
            // and with it the headroom `set_connections_per_active` scales.
            .on_upgrade(Priority::User(UserPriority::L1), |mut socket| async move {
                while let Some(Ok(message)) = socket.recv().await {
                    if message.is_close() || socket.send(message).await.is_err() {
                        break;
                    }
                }
            })
    }

    axum::Router::new().route("/ws", any(upgrade))
}

/// One attacker, reconnecting for as long as the run lasts.
async fn attack(
    behaviour: Behaviour,
    source: Ipv4Addr,
    server: SocketAddr,
    tally: Arc<Tally>,
    stop: Arc<AtomicBool>,
) {
    // A polite client waits between connections; a churning one does not.
    let backoff = if behaviour.churn {
        Duration::from_millis(1)
    } else {
        Duration::from_millis(250)
    };

    while !stop.load(Ordering::Relaxed) {
        let Ok(mut stream) = connect_from(source, server).await else {
            tally.refused.fetch_add(1, Ordering::Relaxed);
            tokio::time::sleep(backoff).await;
            continue;
        };
        tally.connected.fetch_add(1, Ordering::Relaxed);

        if behaviour.mute {
            // The whole attack: hold the connection, and with it a handshake
            // slot, without ever asking for anything.
            tokio::time::sleep(Duration::from_secs(2)).await;
            continue;
        }

        match handshake(&mut stream).await {
            Ok(true) => {
                tally.upgraded.fetch_add(1, Ordering::Relaxed);
            }
            // A `429`, or a connection goalkeeper closed under us.
            _ => {
                tally.refused.fetch_add(1, Ordering::Relaxed);
                tokio::time::sleep(backoff).await;
                continue;
            }
        }

        let gap = if behaviour.flood {
            Duration::from_millis(1)
        } else {
            Duration::from_millis(100)
        };
        let payload = vec![b'x'; if behaviour.flood { 4096 } else { 64 }];
        let deadline = tokio::time::Instant::now()
            + if behaviour.churn {
                Duration::from_millis(500)
            } else {
                Duration::from_secs(5)
            };

        let mut buffer = [0u8; 8192];
        while !stop.load(Ordering::Relaxed) && tokio::time::Instant::now() < deadline {
            if stream.write_all(&text_frame(&payload)).await.is_err() {
                break;
            }
            match tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buffer)).await {
                Ok(Ok(read)) if read > 0 => {
                    tally.echoed.fetch_add(1, Ordering::Relaxed);
                }
                // Throttled into silence, or disconnected.
                _ => break,
            }
            tokio::time::sleep(gap).await;
        }
        tokio::time::sleep(backoff).await;
    }
}

/// The `n`th source address, out of a range that is loopback but is not
/// `127.0.0.1`.
fn nth_address(n: u16) -> Ipv4Addr {
    Ipv4Addr::new(127, 42, (n >> 8) as u8, n as u8)
}

/// Connects to `server` from `source`.
///
/// The whole trick of this example. `TcpSocket` binds before connecting, which
/// is what lets one process present hundreds of addresses.
async fn connect_from(source: Ipv4Addr, server: SocketAddr) -> std::io::Result<TcpStream> {
    let socket = TcpSocket::new_v4()?;
    // Several thousand short-lived connections leave that many sockets in
    // `TIME_WAIT`, and without this the ephemeral ports run out long before the
    // run does.
    socket.set_reuseaddr(true)?;
    socket.bind(SocketAddr::from((source, 0)))?;
    socket.connect(server).await
}

/// Asks for the upgrade, reporting whether it was granted.
async fn handshake(stream: &mut TcpStream) -> std::io::Result<bool> {
    const REQUEST: &str = "GET /ws HTTP/1.1\r\n\
         Host: goalkeeper\r\n\
         Connection: Upgrade\r\n\
         Upgrade: websocket\r\n\
         Sec-WebSocket-Version: 13\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n";
    stream.write_all(REQUEST.as_bytes()).await?;
    let mut buffer = [0u8; 1024];
    let read = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buffer))
        .await
        .unwrap_or(Ok(0))?;
    Ok(buffer[..read].starts_with(b"HTTP/1.1 101"))
}

/// One masked text frame, which is the only shape a client may send.
fn text_frame(payload: &[u8]) -> Vec<u8> {
    const MASK: [u8; 4] = [0xAA, 0xBB, 0xCC, 0xDD];
    let mut frame = vec![0x81];
    match payload.len() {
        length if length < 126 => frame.push(0x80 | length as u8),
        length => {
            frame.push(0x80 | 126);
            frame.extend((length as u16).to_be_bytes());
        }
    }
    frame.extend(MASK);
    frame.extend(
        payload
            .iter()
            .enumerate()
            .map(|(index, byte)| byte ^ MASK[index % 4]),
    );
    frame
}

/// What goalkeeper measures about the host for itself.
///
/// Internal rather than combined, so this is goalkeeper's own reading and not
/// anything an application has reported: scheduling lateness for `cpu`, the
/// share of the bandwidth budget the ledger saw for `network`. `ram` is never
/// measured internally, since the meaningful ceiling is a deployment's
/// business, so it reads zero here.
///
/// Worth watching under load because these drive
/// [`strained`][goalkeeper::ProvideGoalkeeper::strained], which the per-address
/// limiter consults before admitting anything: a reading that climbs on its own
/// tightens admission with nothing actually wrong.
fn pressure() {
    let pressure = SystemGoalkeeper.internal_pressure();
    println!(
        "pressure   cpu {:>6.3}  network {:>6.3}  ram {:>6.3}{}",
        pressure.cpu,
        pressure.network,
        pressure.ram,
        if SystemGoalkeeper.strained() {
            "  (strained)"
        } else {
            ""
        },
    );
}

/// What goalkeeper is holding and what it has turned away.
fn report() {
    let mut addresses = 0u32;
    let mut connections = 0u32;
    let mut sessions = 0u32;
    SystemGoalkeeper.address_stats(|_, stats| {
        addresses += 1;
        connections += stats.connections;
        sessions += stats.active_sessions;
    });
    // Drains, so these are the interval since the last report rather than the
    // run so far.
    let (permits, withheld) = SystemGoalkeeper.permit_counts();
    let tasks = SystemGoalkeeper.tasks();

    println!(
        "addresses {addresses:>3}  connections {connections:>4}  sessions {sessions:>3}  \
         asked {permits:>6} withheld {withheld:>6}  \
         tasks {:>4} ({} unvouched)",
        tasks.alive(),
        tasks.alive_at(Priority::New),
    );
}
