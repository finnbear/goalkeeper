//! Real QUIC handshakes against the real server, over loopback UDP.
//!
//! `tests/load.rs` is deliberately socket-free; this is the opposite, and
//! exists for the one class of bug that cannot be reproduced any other way. The
//! server answers an unvalidated address with a Retry packet carrying a token
//! it seals with a secret only it holds, and whether that token is still
//! readable a round trip later depends on state the server carries between two
//! packets from the same peer. Nothing in-memory models that.
//!
//! One test, then, per thing that can move underneath a handshake in flight.

#![cfg(feature = "web_transport")]

use goalkeeper::web_transport::{ServeWebTransport, Session};
use goalkeeper::{ArcGoalkeeper, Goalkeeper, SystemGoalkeeper};
use std::net::UdpSocket;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

/// One server at a time.
///
/// goalkeeper's executor is process-wide and is driven by whoever calls
/// `run_until`; two of those at once would be two schedulers over one queue.
/// The limiters below are process-wide for the same reason.
static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Enough for the failure to be unambiguous, since a stale token wedges every
/// handshake still in flight, and few enough to be quick.
const CLIENTS: usize = 4;

/// The certificate is self-signed and the authority is a loopback port, so
/// there is nothing a real validator could check.
fn identity() -> wtransport::Identity {
    wtransport::Identity::self_signed(["localhost", "127.0.0.1", "::1"]).unwrap()
}

/// The identity as the hot-swappable `TlsConfig` the server takes, which is
/// the same shape a deployment shares with its HTTPS listener.
fn tls_config(identity: &wtransport::Identity) -> goalkeeper::http::tls::TlsConfig {
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
    goalkeeper::http::tls::TlsConfig::new(std::sync::Arc::new(config))
}

/// A loopback socket, and the port it landed on.
///
/// Held rather than probed and dropped, so nothing can take the port between
/// asking and serving.
fn bound() -> (UdpSocket, u16) {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = socket.local_addr().unwrap().port();
    (socket, port)
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

/// Stands down everything that would otherwise refuse several connections from
/// one loopback address, which is all of them coming from here.
fn stand_down(gk: &Goalkeeper) {
    gk.set_handshake_capacity(4096, 4096);
    gk.set_handshake_slow_per_ip(4096, 4096);
    // Large rather than `u32::MAX`: a per-second rate is turned into a period
    // by dividing a second by it, and a rate above a billion rounds that period
    // to zero, which a debug build rightly refuses.
    const PLENTY: u32 = 1_000_000_000;
    gk.set_address_bandwidth_limits(PLENTY, PLENTY);
    gk.set_connections_per_active(PLENTY, PLENTY);
    gk.set_total_connection_limits(PLENTY, PLENTY);
}

/// Whether a session can be established at all, within `within`.
///
/// The connect half of [`client`], for a server expected to refuse. Waiting out
/// the full handshake timeout would only make such a test slower.
async fn connects(port: u16, within: Duration) -> bool {
    let Ok(endpoint) = wtransport::Endpoint::client(client_config()) else {
        return false;
    };
    matches!(
        tokio::time::timeout(within, endpoint.connect(url(port))).await,
        Ok(Ok(_))
    )
}

fn client_config() -> wtransport::ClientConfig {
    wtransport::ClientConfig::builder()
        .with_bind_default()
        .with_no_cert_validation()
        .build()
}

/// The literal v4 address, not `localhost`: [`bound`] binds v4 loopback, and
/// `localhost` resolves to `::1` first.
fn url(port: u16) -> String {
    format!("https://127.0.0.1:{port}/")
}

/// Connects, takes the stream the server opens, and reports whether the byte on
/// it arrived.
async fn client(port: u16) -> bool {
    let Ok(endpoint) = wtransport::Endpoint::client(client_config()) else {
        return false;
    };
    let connect = endpoint.connect(url(port));
    let Ok(Ok(connection)) = tokio::time::timeout(Duration::from_secs(5), connect).await else {
        return false;
    };
    let Ok(Ok(mut recv)) =
        tokio::time::timeout(Duration::from_secs(5), connection.accept_uni()).await
    else {
        return false;
    };
    let mut byte = [0u8; 1];
    matches!(
        tokio::time::timeout(Duration::from_secs(5), recv.read(&mut byte)).await,
        Ok(Ok(Some(1)))
    )
}

/// Runs a server that reloads its configuration every `reload_every` while
/// `CLIENTS` clients handshake against it, and returns how many got their byte.
fn handshakes_under_reload(reload_every: Duration) -> usize {
    let _serial = serial();
    stand_down(&SystemGoalkeeper);
    let (socket, port) = bound();
    let identity = identity();
    let stop = Arc::new(AtomicBool::new(false));

    let server = std::thread::spawn({
        let stop = Arc::clone(&stop);
        move || {
            runtime().block_on(SystemGoalkeeper.run_until(async move {
                let tls = tls_config(&identity);
                let held = Arc::clone(&stop);
                let handler = move |session: Session| {
                    let stop = Arc::clone(&held);
                    async move {
                        let Ok(connection) = session.accept().await else {
                            return;
                        };
                        if let Ok(mut send) = connection.open_uni().await {
                            let _ = send.write_all(&[1u8]).await;
                            let _ = send.finish().await;
                        }
                        // Held open until the run ends, so the client's read
                        // cannot succeed merely because the stream was reset.
                        while !stop.load(Ordering::Relaxed) {
                            tokio::time::sleep(Duration::from_millis(5)).await;
                        }
                    }
                };
                let mut serving = SystemGoalkeeper
                    .serve_web_transport(socket, tls, handler)
                    .reload_every(reload_every)
                    .spawn()
                    .unwrap();
                while !stop.load(Ordering::Relaxed) {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                serving.stop().await;
            }));
        }
    });

    let arrived = Arc::new(AtomicUsize::new(0));
    runtime().block_on({
        let arrived = Arc::clone(&arrived);
        async move {
            let clients: Vec<_> = (0..CLIENTS)
                .map(|_| {
                    let arrived = Arc::clone(&arrived);
                    tokio::spawn(async move {
                        if client(port).await {
                            arrived.fetch_add(1, Ordering::Relaxed);
                        }
                    })
                })
                .collect();
            for handle in clients {
                let _ = handle.await;
            }
        }
    });

    stop.store(true, Ordering::Relaxed);
    let _ = server.join();
    arrived.load(Ordering::Relaxed)
}

/// Every handshake completes while the configuration is being replaced under it.
///
/// The reload interval is absurd on purpose: a second is the shortest a
/// deployment would plausibly ask for, and this asks for one every millisecond,
/// so a reload is guaranteed to land between a client receiving its Retry and
/// answering it. That window is exactly where this used to break. Installing a
/// freshly built configuration installs a fresh `token_key`, the
/// secret the Retry token is sealed with, so the token a client was carrying
/// back stopped decrypting. quinn cannot tell that from a client that sent no
/// token at all, so the server retried the connection again. The client, having
/// already processed one Retry, is required to discard every later one (RFC 9000
/// §17.2.5.2), so it answered with the same dead token until it timed out. On a
/// loopback benchmark that cost most of eight clients most runs.
#[test]
fn handshakes_survive_a_configuration_reload() {
    assert_eq!(handshakes_under_reload(Duration::from_millis(1)), CLIENTS);
}

/// The control for the test above, with the reload out of the way. If this
/// fails too, the fault is not the reload.
#[test]
fn handshakes_complete_without_a_reload() {
    assert_eq!(handshakes_under_reload(Duration::from_secs(60)), CLIENTS);
}

/// An instance of its own serves WebTransport with nothing driving the
/// process's.
///
/// quinn spawns the endpoint's demultiplexer and every connection's driver
/// through a `quinn::Runtime` that goalkeeper supplies, and quinn stores that
/// as a trait object. If the concrete type behind it did not carry the provider
/// those drivers would land on the process's executor, which nothing here
/// drives since the only `run_until` is the instance's. The handshake would
/// never make progress, so a hung client is the failure this catches.
#[test]
fn an_instance_of_its_own_drives_its_own_quic() {
    let _serial = serial();
    let gk = ArcGoalkeeper::new();
    stand_down(&gk);
    let (socket, port) = bound();
    let identity = identity();
    let stop = Arc::new(AtomicBool::new(false));

    let server = std::thread::spawn({
        let stop = Arc::clone(&stop);
        let driven = gk.clone();
        move || {
            runtime().block_on(driven.run_until(async move {
                let tls = tls_config(&identity);
                let held = Arc::clone(&stop);
                let handler = move |session: Session<ArcGoalkeeper>| {
                    let stop = Arc::clone(&held);
                    async move {
                        let Ok(connection) = session.accept().await else {
                            return;
                        };
                        if let Ok(mut send) = connection.open_uni().await {
                            let _ = send.write_all(&[1u8]).await;
                            let _ = send.finish().await;
                        }
                        while !stop.load(Ordering::Relaxed) {
                            tokio::time::sleep(Duration::from_millis(5)).await;
                        }
                    }
                };
                let mut serving = gk
                    .serve_web_transport(socket, tls, handler)
                    .spawn()
                    .unwrap();
                while !stop.load(Ordering::Relaxed) {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                serving.stop().await;
            }));
        }
    });

    let arrived = runtime().block_on(client(port));

    stop.store(true, Ordering::Relaxed);
    let _ = server.join();
    assert!(
        arrived,
        "an instance of its own could not complete a handshake"
    );
}

/// `configure_server` reaches the endpoint, and wins over goalkeeper's own
/// settings.
///
/// Asserted by refusing every handshake: goalkeeper sets `max_incoming` to 256,
/// so a client that cannot connect proves both that the hook ran and that it
/// ran last.
#[test]
fn configure_server_overrides_goalkeepers_own_settings() {
    let _serial = serial();
    stand_down(&SystemGoalkeeper);
    let (socket, port) = bound();
    let identity = identity();
    let stop = Arc::new(AtomicBool::new(false));
    let configured = Arc::new(AtomicBool::new(false));

    let server = std::thread::spawn({
        let stop = Arc::clone(&stop);
        let configured = Arc::clone(&configured);
        move || {
            runtime().block_on(SystemGoalkeeper.run_until(async move {
                let tls = tls_config(&identity);
                let handler = |session: Session| async move {
                    let _ = session.accept().await;
                };
                let mut serving = SystemGoalkeeper
                    .serve_web_transport(socket, tls, handler)
                    .configure_server(move |config| {
                        configured.store(true, Ordering::Relaxed);
                        config.max_incoming(0);
                    })
                    .spawn()
                    .unwrap();
                while !stop.load(Ordering::Relaxed) {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                serving.stop().await;
            }));
        }
    });

    let connected = runtime().block_on(connects(port, Duration::from_secs(1)));

    stop.store(true, Ordering::Relaxed);
    let _ = server.join();
    assert!(configured.load(Ordering::Relaxed), "the hook never ran");
    assert!(!connected, "`max_incoming(0)` did not reach the endpoint");
}
