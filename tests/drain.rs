//! What a goalkeeper is still holding once every client has gone.
//!
//! Every guard this crate hands out is released by dropping, and every ledger
//! entry is meant to fall with the guard that raised it. That is easy to get
//! right for one protocol on a quiet day and easy to get wrong where several
//! meet under churn, so this runs all four at once while a fifth task spends
//! the run re-levelling connections, killing them, and moving the limits
//! between generous and binding. Then everything disconnects and the ledgers
//! have to be empty.
//!
//! The churn is the point. Re-levelling moves booked memory between levels,
//! killing releases guards from a path that never returns normally, and a
//! binding limit exercises the refusal arms that a comfortable one never
//! reaches. A leak that only shows up when a connection dies mid-lease is
//! exactly the kind this is for.
//!
//! # What is allowed to survive, and why it is not a leak
//!
//! - **Per-address rows.** [`ArcGoalkeeper::address_stats`] keeps one per
//!   address for `ddos_memory`, five minutes by default, after the last
//!   connection closes. That is deliberate: an attacker reconnecting should not
//!   arrive with a clean record. The row surviving is the feature; what must
//!   fall to zero with the guards are its `connections` and `active_sessions`,
//!   asserted per row below.
//! - **The bandwidth epoch and the controller's tick.** Counters that only move
//!   forwards, and neither grows with connections.
//! - **The run's handshake counts.** [`ArcGoalkeeper::handshake_counts`] takes
//!   and clears, so an uncollected report is history nobody has read rather than
//!   work still outstanding. What must balance is `attempts` against
//!   `completed + killed + refused`, asserted below: the residue is what is
//!   still in the pool, and a handshake in the pool holds a slot and a task.
//! - **Executor queues.** Emptiness is asserted through `alive`; the `VecDeque`
//!   behind each level keeps whatever capacity it reached. An allocator
//!   question, not a ledger one.
//! - **The glide positions.** The memory controller and the handshake pool sit
//!   wherever pressure last left them and walk back on their own cadence. They
//!   are positions, not tallies.
//!
//! Everything else is asserted to be zero: permits, active sessions, handshake
//! slots, reserved memory, bytes in the window and live tasks.

#![cfg(all(feature = "web_socket", feature = "web_transport"))]

use goalkeeper::ArcGoalkeeper;
use goalkeeper::conn::Conn;
use goalkeeper::executor::priority::{Priority, UserPriority};
use goalkeeper::http::web_socket::WebSocketUpgrade;
use goalkeeper::http::{ServeHttp, tls};
use goalkeeper::resource::bandwidth::Direction;
use goalkeeper::web_transport::{ServeWebTransport, Session};
use rand::prelude::*;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// How long clients and the churn run before anything is asked to stop.
const RUN: Duration = Duration::from_secs(3);

/// Several bandwidth windows (100ms) and a memory controller interval (1s) with
/// nothing arriving, so anything that clears on a cadence has had its cue.
const QUIET: Duration = Duration::from_secs(2);

/// Concurrent clients per protocol. More than one, so a single leaked guard
/// shows as a count rather than having to be inferred.
const CLIENTS: usize = 3;

/// No operation may outlast this. A drain test that hangs says far less than
/// one that fails, and every client here is racing a task that may kill it.
const PATIENCE: Duration = Duration::from_secs(5);

/// What the ledgers are set to when they should bind, chosen low enough to
/// refuse and evict rather than merely to slow.
const LOW_BYTES: u32 = 4 * 1024;
const LOW_MEMORY: u64 = 512 * 1024;

/// What they are set to when nothing should be refused for its own sake.
const PLENTY: u32 = 1_000_000_000;

/// The payload every protocol exchanges, in both directions.
const PING: &[u8] = b"goalkeeper-drain-ping";

/// Live connections, so the churn can re-level and kill them.
///
/// Holding a [`Conn`] holds its permit, so this is cleared before the drain is
/// asserted. That is not an artefact of the test: an application that parks
/// connection handles somewhere and forgets them leaks exactly this way, and
/// the clearing models letting go.
type Registry = Arc<Mutex<Vec<Conn<ArcGoalkeeper>>>>;

fn identity() -> (Arc<rustls::ServerConfig>, rustls::RootCertStore) {
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
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .unwrap();
    (Arc::new(config), roots)
}

/// The app both HTTP listeners serve: an echo, and an upgrade that echoes.
fn app(registry: Registry, exchanged: Arc<AtomicU64>) -> axum::Router {
    use axum::routing::{any, post};

    async fn echo(
        axum::Extension(conn): axum::Extension<Conn<ArcGoalkeeper>>,
        axum::Extension(registry): axum::Extension<Registry>,
        axum::Extension(exchanged): axum::Extension<Arc<AtomicU64>>,
        body: String,
    ) -> String {
        registry.lock().unwrap().push(conn);
        exchanged.fetch_add(1, Ordering::Relaxed);
        body
    }

    async fn upgrade(
        upgrade: WebSocketUpgrade<ArcGoalkeeper>,
        axum::Extension(registry): axum::Extension<Registry>,
        axum::Extension(exchanged): axum::Extension<Arc<AtomicU64>>,
    ) -> axum::response::Response {
        registry.lock().unwrap().push(upgrade.conn().clone());
        // Takes the boost and the address's active session, which is what makes
        // this worth draining: both are guards on state asserted below.
        upgrade.on_upgrade(
            Priority::User(UserPriority::L1),
            move |mut socket| async move {
                // `Ok` only: a client that drops without a close frame reports an
                // error rather than an end, and treating that as "still open" would
                // spin forever holding the guards this test drains.
                while let Some(Ok(message)) = socket.recv().await {
                    if message.is_close() {
                        break;
                    }
                    exchanged.fetch_add(1, Ordering::Relaxed);
                    if socket.send(message).await.is_err() {
                        break;
                    }
                }
            },
        )
    }

    axum::Router::new()
        .route("/echo", post(echo))
        .route("/ws", any(upgrade))
        .layer(axum::Extension(registry))
        .layer(axum::Extension(exchanged))
}

/// A plaintext HTTP/1 client: several exchanges, then either a polite close or
/// an abrupt drop.
async fn http1(addr: std::net::SocketAddr, polite: bool, stop: Arc<AtomicBool>) {
    let Ok(mut stream) = TcpStream::connect(addr).await else {
        return;
    };
    let request = format!(
        "POST /echo HTTP/1.1\r\nHost: drain\r\nContent-Length: {}\r\n\r\n",
        PING.len()
    );
    while !stop.load(Ordering::Relaxed) {
        if stream.write_all(request.as_bytes()).await.is_err()
            || stream.write_all(PING).await.is_err()
        {
            return;
        }
        let mut buffer = [0u8; 512];
        match tokio::time::timeout(PATIENCE, stream.read(&mut buffer)).await {
            Ok(Ok(n)) if n > 0 => {}
            // Killed, refused or timed out: all fine, the server still has to
            // let go of whatever it took.
            _ => return,
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    if polite {
        let _ = stream.shutdown().await;
    }
}

/// One masked client frame, which is the only shape a browser may send.
fn ws_frame(payload: &[u8]) -> Vec<u8> {
    let mut frame = vec![0x81, 0x80 | payload.len() as u8, 0xAA, 0xBB, 0xCC, 0xDD];
    frame.extend(
        payload
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ [0xAA, 0xBB, 0xCC, 0xDD][i % 4]),
    );
    frame
}

/// A WebSocket client: upgrade, exchange, then a close frame or a bare drop.
async fn web_socket(addr: std::net::SocketAddr, polite: bool, stop: Arc<AtomicBool>) {
    let Ok(mut stream) = TcpStream::connect(addr).await else {
        return;
    };
    let handshake = "GET /ws HTTP/1.1\r\n\
         Host: drain\r\n\
         Connection: Upgrade\r\n\
         Upgrade: websocket\r\n\
         Sec-WebSocket-Version: 13\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n";
    if stream.write_all(handshake.as_bytes()).await.is_err() {
        return;
    }
    let mut buffer = [0u8; 1024];
    if !matches!(
        tokio::time::timeout(PATIENCE, stream.read(&mut buffer)).await,
        Ok(Ok(n)) if n > 0
    ) {
        return;
    }
    while !stop.load(Ordering::Relaxed) {
        if stream.write_all(&ws_frame(PING)).await.is_err() {
            return;
        }
        match tokio::time::timeout(PATIENCE, stream.read(&mut buffer)).await {
            Ok(Ok(n)) if n > 0 => {}
            _ => return,
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    if polite {
        // An unmasked-payload close, which the server answers and then ends.
        let _ = stream.write_all(&[0x88, 0x80, 0, 0, 0, 0]).await;
        let _ = stream.shutdown().await;
    }
}

/// An HTTPS client speaking HTTP/2, which is what the ALPN negotiates. The TLS
/// handshake is what takes a slot from the crypto pool.
async fn https(addr: std::net::SocketAddr, roots: rustls::RootCertStore, stop: Arc<AtomicBool>) {
    let mut client = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client.alpn_protocols = vec![b"h2".to_vec()];
    let Ok(stream) = TcpStream::connect(addr).await else {
        return;
    };
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client));
    let name = rustls::pki_types::ServerName::IpAddress(addr.ip().into());
    let Ok(Ok(tls)) = tokio::time::timeout(PATIENCE, connector.connect(name, stream)).await else {
        return;
    };
    let Ok(Ok((mut sender, connection))) = tokio::time::timeout(
        PATIENCE,
        hyper::client::conn::http2::handshake(
            hyper_util::rt::TokioExecutor::new(),
            hyper_util::rt::TokioIo::new(tls),
        ),
    )
    .await
    else {
        return;
    };
    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });
    while !stop.load(Ordering::Relaxed) {
        let request = hyper::Request::builder()
            .method("POST")
            .uri("/echo")
            .body(http_body_util::Full::new(bytes::Bytes::from_static(PING)))
            .unwrap();
        match tokio::time::timeout(PATIENCE, sender.send_request(request)).await {
            Ok(Ok(response)) => {
                use http_body_util::BodyExt;
                let _ = response.into_body().collect().await;
            }
            _ => break,
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    drop(sender);
    let _ = tokio::time::timeout(PATIENCE, driver).await;
}

/// A WebTransport client: a bidirectional stream, exchanged both ways, then a
/// clean close or a dropped endpoint.
async fn web_transport(port: u16, polite: bool, stop: Arc<AtomicBool>) {
    let config = wtransport::ClientConfig::builder()
        .with_bind_default()
        .with_no_cert_validation()
        .build();
    let Ok(endpoint) = wtransport::Endpoint::client(config) else {
        return;
    };
    let Ok(Ok(connection)) = tokio::time::timeout(
        PATIENCE,
        endpoint.connect(format!("https://127.0.0.1:{port}/")),
    )
    .await
    else {
        return;
    };
    // `open_bi` yields an opening that resolves once the peer grants credit for
    // the stream, so there are two waits here rather than one.
    let Ok(Ok(opening)) = tokio::time::timeout(PATIENCE, connection.open_bi()).await else {
        return;
    };
    let Ok(Ok((mut send, mut recv))) = tokio::time::timeout(PATIENCE, opening).await else {
        return;
    };
    let mut buffer = vec![0u8; PING.len()];
    while !stop.load(Ordering::Relaxed) {
        if send.write_all(PING).await.is_err() {
            break;
        }
        match tokio::time::timeout(PATIENCE, recv.read_exact(&mut buffer)).await {
            Ok(Ok(())) => {}
            _ => break,
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    if polite {
        let _ = send.finish().await;
        connection.close(0u32.into(), b"done");
        // Given a moment to leave, so the close is on the wire before the
        // endpoint that would carry it is dropped.
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[test]
fn every_ledger_drains_once_the_clients_have_gone() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let (server_config, roots) = identity();
    let gk = ArcGoalkeeper::new();
    let driven = gk.clone();

    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(driven.run_until(run(gk, server_config, roots)));
}

/// Sets the limits so nothing is refused for a reason other than a leak.
fn generous(gk: &ArcGoalkeeper) {
    gk.set_connections_per_active(PLENTY, PLENTY);
    gk.set_total_connection_limits(PLENTY, PLENTY);
    gk.set_address_bandwidth_limits(PLENTY, PLENTY);
    gk.set_bandwidth_limits(u64::from(PLENTY), u64::from(PLENTY));
    gk.set_handshake_capacity(4096, 4096);
    gk.set_handshake_slow_per_ip(4096, 4096);
    // A limit at all, so reservations are booked rather than waved through: an
    // unlimited ledger authorises without recording, and would drain trivially.
    gk.set_memory_limit(256 * 1024 * 1024);
}

/// Sets them low enough to refuse, evict and throttle.
fn binding(gk: &ArcGoalkeeper) {
    gk.set_connections_per_active(1, 1);
    gk.set_total_connection_limits(2, 4);
    gk.set_address_bandwidth_limits(LOW_BYTES, LOW_BYTES);
    gk.set_bandwidth_limits(u64::from(LOW_BYTES), u64::from(LOW_BYTES));
    gk.set_handshake_capacity(1, 1);
    gk.set_handshake_slow_per_ip(1, 1);
    gk.set_memory_limit(LOW_MEMORY);
}

async fn run(
    gk: ArcGoalkeeper,
    server_config: Arc<rustls::ServerConfig>,
    roots: rustls::RootCertStore,
) {
    generous(&gk);

    let registry: Registry = Arc::new(Mutex::new(Vec::new()));
    let exchanged = Arc::new(AtomicU64::new(0));

    let plain = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let plain_addr = plain.local_addr().unwrap();
    let secure = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let secure_addr = secure.local_addr().unwrap();
    let quic = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let quic_port = quic.local_addr().unwrap().port();

    let tls = tls::TlsConfig::new(server_config);
    let mut http = gk
        .serve_http(plain, app(Arc::clone(&registry), Arc::clone(&exchanged)))
        .spawn();
    let mut https_server = gk
        .serve_https(
            secure,
            tls.clone(),
            app(Arc::clone(&registry), Arc::clone(&exchanged)),
        )
        .spawn();
    let mut wt = {
        let registry = Arc::clone(&registry);
        let exchanged = Arc::clone(&exchanged);
        gk.serve_web_transport(quic, tls, move |session: Session<ArcGoalkeeper>| {
            let registry = Arc::clone(&registry);
            let exchanged = Arc::clone(&exchanged);
            async move {
                registry.lock().unwrap().push(session.conn().clone());
                // Accepting is what reserves `PER_CONNECTION` and installs the
                // governor, so an unaccepted session would leave the memory
                // ledger untouched.
                let Ok(connection) = session.accept().await else {
                    return;
                };
                let Ok(Ok((mut send, mut recv))) =
                    tokio::time::timeout(PATIENCE, connection.accept_bi()).await
                else {
                    return;
                };
                let mut buffer = vec![0u8; PING.len()];
                while recv.read_exact(&mut buffer).await.is_ok() {
                    exchanged.fetch_add(1, Ordering::Relaxed);
                    if send.write_all(&buffer).await.is_err() {
                        break;
                    }
                }
            }
        })
        // Short, so a peer that vanishes cannot hold the endpoint open past the
        // shutdown below and turn a leak assertion into a hang.
        .configure_transport(|transport| {
            transport.max_idle_timeout(Some(Duration::from_secs(2).try_into().unwrap()));
        })
        .spawn()
        .unwrap()
    };

    let stop = Arc::new(AtomicBool::new(false));
    let mut clients = Vec::new();
    for n in 0..CLIENTS {
        // Two in three leave politely, so both the graceful and the abrupt
        // teardown paths are drained.
        let polite = n % 3 != 0;
        clients.push(tokio::spawn(http1(plain_addr, polite, Arc::clone(&stop))));
        clients.push(tokio::spawn(web_socket(
            plain_addr,
            polite,
            Arc::clone(&stop),
        )));
        clients.push(tokio::spawn(https(
            secure_addr,
            roots.clone(),
            Arc::clone(&stop),
        )));
        clients.push(tokio::spawn(web_transport(
            quic_port,
            polite,
            Arc::clone(&stop),
        )));
    }

    let churn = tokio::spawn(churn(gk.clone(), Arc::clone(&registry), Arc::clone(&stop)));

    tokio::time::sleep(RUN).await;

    // Nothing should be refused while the drain is being watched, and a binding
    // memory limit would refuse the reservations whose release is the point.
    generous(&gk);
    stop.store(true, Ordering::Relaxed);
    let _ = tokio::time::timeout(PATIENCE, churn).await;
    for client in clients {
        let _ = tokio::time::timeout(PATIENCE, client).await;
    }

    // Proves the run was a run. Without this the assertions below would pass
    // just as well against a server nobody ever reached.
    let exchanges = exchanged.load(Ordering::Relaxed);
    assert!(
        exchanges > 0,
        "no protocol exchanged anything, so nothing was drained"
    );

    assert!(
        tokio::time::timeout(PATIENCE, http.stop()).await.is_ok(),
        "the plaintext listener would not shut down"
    );
    assert!(
        tokio::time::timeout(PATIENCE, https_server.stop())
            .await
            .is_ok(),
        "the TLS listener would not shut down"
    );
    assert!(
        tokio::time::timeout(PATIENCE, wt.stop()).await.is_ok(),
        "the WebTransport endpoint would not shut down"
    );

    // The test's own handles, which hold permits like any other holder would.
    registry.lock().unwrap().clear();

    // Taken before the quiet period rather than after, because taking is what
    // clears them: this is the run's whole history, and every handshake that
    // reached the pool has to be accounted for in it.
    let run = gk.handshake_counts();

    tokio::time::sleep(QUIET).await;

    let connections = gk.total_connections();
    let memory = gk.memory_usage().held_total();
    let tx = gk.bandwidth_usage().moved_total(Direction::Tx);
    let rx = gk.bandwidth_usage().moved_total(Direction::Rx);
    let alive = gk.tasks().alive();
    let mut charged: Vec<(std::net::IpAddr, u32, u32)> = Vec::new();
    gk.address_stats(|ip, stats| {
        if stats.connections != 0 || stats.active_sessions != 0 {
            charged.push((ip, stats.connections, stats.active_sessions));
        }
    });

    eprintln!("{exchanges} exchanges across four protocols, then drained");

    assert_eq!(
        connections, 0,
        "connection permits outlived their connections"
    );
    assert!(
        charged.is_empty(),
        "an address is still charged for guards nobody holds: {charged:?}"
    );
    assert_eq!(
        memory, 0,
        "reserved memory outlived the connections that reserved it"
    );
    assert_eq!(tx, 0, "a window's worth of sent bytes never rolled away");
    assert_eq!(
        rx, 0,
        "a window's worth of received bytes never rolled away"
    );
    assert_eq!(alive, 0, "tasks outlived the servers that spawned them");

    // Everything that reached the pool left it. The residue is what is still in
    // flight, and a handshake in flight holds a slot and a task.
    assert_eq!(
        run.attempts,
        run.completed + run.killed + run.refused,
        "handshakes reached the crypto pool and never left it: {run:?}"
    );
    assert!(run.attempts > 0, "no handshake was exercised at all");

    // A second take, covering only the quiet period, so this says nothing
    // happened after the clients had gone rather than nothing happened at all.
    let quiet = gk.handshake_counts();
    assert_eq!(
        (quiet.attempts, quiet.completed, quiet.killed, quiet.refused),
        (0, 0, 0, 0),
        "the crypto pool was still working after every client had gone"
    );
}

/// Re-levels, kills and reconfigures for the length of the run.
///
/// Re-levelling is what moves booked memory between levels, killing releases
/// guards from a path that never returns normally, and the limits moving under
/// live traffic is what reaches the refusal arms.
async fn churn(gk: ArcGoalkeeper, registry: Registry, stop: Arc<AtomicBool>) {
    const LEVELS: [UserPriority; 4] = [
        UserPriority::L0,
        UserPriority::L1,
        UserPriority::L4,
        UserPriority::L9,
    ];
    // Seeded, so a failure is a failure again on the next run.
    let mut rng = StdRng::seed_from_u64(0x60A1_4EEE_u64);
    let mut generous_now = true;
    while !stop.load(Ordering::Relaxed) {
        tokio::time::sleep(Duration::from_millis(rng.gen_range(5..40))).await;

        // Everything, every time: the ledger has to survive a level changing
        // under a connection that is mid-lease and mid-reservation.
        let conns: Vec<_> = registry.lock().unwrap().clone();
        for conn in &conns {
            conn.set_base(Priority::User(*LEVELS.choose(&mut rng).unwrap()));
        }

        if rng.gen_bool(0.15)
            && let Some(victim) = conns.choose(&mut rng)
        {
            victim.kill();
        }

        if rng.gen_bool(0.25) {
            generous_now = !generous_now;
            if generous_now {
                generous(&gk);
            } else {
                binding(&gk);
            }
        }
    }
}
