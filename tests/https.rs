//! What an HTTPS listener negotiates, over real loopback TCP.
//!
//! ALPN is the only way a browser reaches HTTP/2, and a `rustls::ServerConfig`
//! offers none by default. goalkeeper sets it rather than leaving it to the
//! caller, so this asserts a client that offers both is given `h2`.
//!
//! It also serves a connection before its handshake is over, so that HTTP/2's
//! SETTINGS go out with the handshake. This asserts that by reading them before
//! the client has sent anything, and that every kind of connection is still
//! served.

#![cfg(feature = "tls")]

use bytes::Bytes;
use goalkeeper::http::ServeHttp;
use goalkeeper::{ArcGoalkeeper, OwnedGoalkeeper};
use http_body_util::{BodyExt, Empty};
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};

/// How long anything here waits on loopback before calling it a failure.
const PATIENCE: Duration = Duration::from_secs(5);

/// The length of `/large`: more than loopback's socket buffers hold, at their
/// largest, so a client that pauses before reading it holds the server's writes
/// up, and many times the 64KiB rustls buffers before it refuses a write.
const LARGE: usize = 32 * 1024 * 1024;

/// What every listener here serves: `/large`, and 404 for anything else.
fn app() -> axum::Router {
    axum::Router::new().route("/large", axum::routing::get(|| async { vec![0u8; LARGE] }))
}

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

/// What a client offering `h2` and `http/1.1` ends up on, against a listener
/// whose configuration was left to goalkeeper.
#[test]
fn an_https_listener_negotiates_http2() {
    assert_eq!(
        negotiated(false).as_deref(),
        Some(&b"h2"[..]),
        "an HTTPS listener offered no usable ALPN, so a browser would fall back \
         to HTTP/1.1 and never reach the HTTP/2 limits or RFC 8441 WebSockets"
    );
}

/// The same, for a caller that had already set what goalkeeper would.
///
/// Worth its own case because that is the path where nothing is derived: the
/// configuration is passed through untouched, so a mistake there would be
/// invisible to the test above.
#[test]
fn an_https_listener_accepts_an_already_correct_alpn() {
    assert_eq!(negotiated(true).as_deref(), Some(&b"h2"[..]));
}

/// The server's SETTINGS reach a client that has not yet sent a byte of
/// HTTP/2, and the connection then serves requests.
///
/// Left to hyper's protocol detection, SETTINGS wait for the client's preface,
/// so the read below would time out.
#[test]
fn settings_arrive_with_the_handshake() {
    let statuses = with_server(false, true, |addr, roots, _| async move {
        let mut tls_stream = connect(addr, roots, vec![b"h2".to_vec()]).await;

        let mut header = [0u8; 9];
        tokio::time::timeout(PATIENCE, tls_stream.read_exact(&mut header))
            .await
            .expect("no SETTINGS before the client spoke, so none came with the handshake")
            .unwrap();
        assert_eq!(header[3], 0x4, "the first frame is SETTINGS");
        assert_eq!(header[4], 0, "and not an acknowledgement");
        let length = u32::from_be_bytes([0, header[0], header[1], header[2]]) as usize;
        let mut payload = vec![0; length];
        tls_stream.read_exact(&mut payload).await.unwrap();
        assert!(
            payload
                .chunks_exact(6)
                .any(|setting| setting == [0, 0x8, 0, 0, 0, 1]),
            "SETTINGS_ENABLE_CONNECT_PROTOCOL, which is what a WebSocket waits for"
        );

        // Handed back to a real client, which is owed the frame just read.
        let replay = Replay {
            replay: [&header[..], &payload[..]].concat(),
            at: 0,
            inner: tls_stream,
        };
        h2_statuses(replay, 3).await
    });
    // An empty router's answer, three times on one connection.
    assert_eq!(statuses, [404; 3]);
}

/// With early SETTINGS off, nothing comes before the client's preface, and
/// the connection is served as hyper alone would serve it.
#[test]
fn early_settings_can_be_turned_off() {
    let statuses = with_server(false, false, |addr, roots, _| async move {
        let mut tls_stream = connect(addr, roots, vec![b"h2".to_vec()]).await;
        let mut header = [0u8; 9];
        assert!(
            tokio::time::timeout(
                Duration::from_millis(250),
                tls_stream.read_exact(&mut header)
            )
            .await
            .is_err(),
            "SETTINGS came before the client's preface"
        );
        h2_statuses(tls_stream, 3).await
    });
    assert_eq!(statuses, [404; 3]);
}

/// The handshake's slot is given up once the handshake completes, not when
/// the connection it opened closes, even though it is the connection that
/// completes it.
#[test]
fn the_slot_is_released_with_the_connection_still_open() {
    with_server(false, true, |addr, roots, gk| async move {
        let tls_stream = connect(addr, roots, vec![b"h2".to_vec()]).await;
        let (mut sender, driver) = h2_client(tls_stream).await;
        assert_eq!(get(&mut sender).await, 404);
        let counts = gk.handshake_counts();
        assert_eq!(
            (counts.completed, counts.killed),
            (1, 0),
            "the slot was still held"
        );
        drop(sender);
        let _ = tokio::time::timeout(PATIENCE, driver).await;
    });
}

/// HTTP/1.1, which hyper reads before it writes, so the server's half of the
/// handshake has to go out on a read.
#[test]
fn http1_is_served() {
    let status = with_server(false, true, |addr, roots, _| async move {
        let tls_stream = connect(addr, roots, vec![b"http/1.1".to_vec()]).await;
        assert_eq!(
            tls_stream.get_ref().1.alpn_protocol(),
            Some(&b"http/1.1"[..])
        );
        let (mut sender, connection) =
            hyper::client::conn::http1::handshake(TokioIo::new(tls_stream))
                .await
                .unwrap();
        let driver = tokio::spawn(async move {
            let _ = connection.await;
        });
        let request = hyper::Request::builder()
            .uri("/")
            .header("host", "127.0.0.1")
            .body(Empty::<Bytes>::new())
            .unwrap();
        let response = tokio::time::timeout(PATIENCE, sender.send_request(request))
            .await
            .expect("request timed out")
            .unwrap();
        drop(sender);
        let _ = tokio::time::timeout(PATIENCE, driver).await;
        response.status().as_u16()
    });
    assert_eq!(status, 404);
}

/// A response that fills the transport arrives whole once the client reads
/// it, with nothing more from the client to prompt the server along.
#[test]
fn a_large_http1_response_is_not_stalled() {
    let length = with_server(false, true, |addr, roots, gk| async move {
        // Not what is under test, and at the default the response would take
        // a minute.
        gk.set_address_bandwidth_limits(1_000_000_000, 1_000_000_000);
        let tls_stream = connect(addr, roots, vec![b"http/1.1".to_vec()]).await;
        let (mut sender, connection) =
            hyper::client::conn::http1::handshake(TokioIo::new(tls_stream))
                .await
                .unwrap();
        let driver = tokio::spawn(async move {
            let _ = connection.await;
        });
        let request = hyper::Request::builder()
            .uri("/large")
            .header("host", "127.0.0.1")
            .body(Empty::<Bytes>::new())
            .unwrap();
        let length = tokio::time::timeout(PATIENCE, async {
            let response = sender.send_request(request).await.unwrap();
            // Long enough for the server to fill the socket and be refused.
            tokio::time::sleep(Duration::from_millis(200)).await;
            response
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .len()
        })
        .await
        .expect("the response stalled");
        drop(sender);
        let _ = tokio::time::timeout(PATIENCE, driver).await;
        length
    });
    assert_eq!(length, LARGE);
}

/// HTTP/2 over TLS 1.2, which has no half-RTT data: rustls holds what hyper
/// writes early until the handshake completes.
#[test]
fn http2_over_tls12_is_served() {
    let statuses = with_server(false, true, |addr, roots, _| async move {
        let tls_stream = connect_with(
            addr,
            roots,
            vec![b"h2".to_vec()],
            &[&rustls::version::TLS12],
        )
        .await;
        assert_eq!(
            tls_stream.get_ref().1.protocol_version(),
            Some(rustls::ProtocolVersion::TLSv1_2)
        );
        h2_statuses(tls_stream, 3).await
    });
    assert_eq!(statuses, [404; 3]);
}

/// A `configure_hyper` that has already said which protocol to speak, which
/// hyper-util panics on being told twice, still has its `h2` connections
/// served.
#[test]
fn a_protocol_set_by_configure_hyper_is_not_set_again() {
    fn http1_only(builder: &mut HyperBuilder) {
        *builder = builder.clone().http1_only();
    }
    fn http2_only(builder: &mut HyperBuilder) {
        *builder = builder.clone().http2_only();
    }
    for configure in [http1_only as fn(&mut HyperBuilder), http2_only] {
        let statuses =
            with_configured_server(false, true, configure, |addr, roots, _| async move {
                let tls_stream = connect(addr, roots, vec![b"h2".to_vec()]).await;
                h2_statuses(tls_stream, 1).await
            });
        assert_eq!(statuses, [404]);
    }
}

/// Serves one HTTPS connection and reports the protocol it negotiated.
fn negotiated(preset: bool) -> Option<Vec<u8>> {
    with_server(preset, true, |addr, roots, _| async move {
        // Both, best first, exactly as a browser offers them.
        let tls_stream = connect(addr, roots, vec![b"h2".to_vec(), b"http/1.1".to_vec()]).await;
        tls_stream.get_ref().1.alpn_protocol().map(<[u8]>::to_vec)
    })
}

/// An HTTP/2 client on `io`, and the task driving its connection.
async fn h2_client<S>(
    io: S,
) -> (
    hyper::client::conn::http2::SendRequest<Empty<Bytes>>,
    tokio::task::JoinHandle<()>,
)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (sender, connection) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(io))
            .await
            .unwrap();
    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });
    (sender, driver)
}

/// The status of a `GET /`.
async fn get(sender: &mut hyper::client::conn::http2::SendRequest<Empty<Bytes>>) -> u16 {
    let request = hyper::Request::builder()
        .uri("/")
        .body(Empty::<Bytes>::new())
        .unwrap();
    tokio::time::timeout(PATIENCE, sender.send_request(request))
        .await
        .expect("request timed out")
        .expect("the connection failed")
        .status()
        .as_u16()
}

/// The statuses of `count` requests over HTTP/2 on `io`, one connection.
async fn h2_statuses<S>(io: S, count: usize) -> Vec<u16>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, driver) = h2_client(io).await;
    let mut statuses = Vec::new();
    for _ in 0..count {
        statuses.push(get(&mut sender).await);
    }
    drop(sender);
    let _ = tokio::time::timeout(PATIENCE, driver).await;
    statuses
}

/// Runs `client` against an HTTPS listener serving an empty router, with
/// [`early_settings`] as given.
///
/// `preset` has the configuration already say what goalkeeper would, so the
/// listener uses it as it is.
///
/// An instance of its own, so nothing here shares a schedule or a limiter with
/// another test, and its handshake counts are this test's alone.
///
/// [`early_settings`]: goalkeeper::http::HttpServerBuilder::early_settings
fn with_server<T, F, Fut>(preset: bool, early: bool, client: F) -> T
where
    F: FnOnce(SocketAddr, rustls::RootCertStore, ArcGoalkeeper) -> Fut,
    Fut: Future<Output = T>,
{
    with_configured_server(preset, early, |_| {}, client)
}

/// The builder `configure_hyper` is handed.
type HyperBuilder =
    hyper_util::server::conn::auto::Builder<goalkeeper::http::PrioritisedExecutor<ArcGoalkeeper>>;

/// [`with_server`], with `configure` passed to `configure_hyper`.
fn with_configured_server<T, F, Fut>(
    preset: bool,
    early: bool,
    configure: fn(&mut HyperBuilder),
    client: F,
) -> T
where
    F: FnOnce(SocketAddr, rustls::RootCertStore, ArcGoalkeeper) -> Fut,
    Fut: Future<Output = T>,
{
    let _ = rustls::crypto::ring::default_provider().install_default();
    let (mut server_config, roots) = identity();
    if preset {
        server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        server_config.send_half_rtt_data = true;
    }
    let owner = OwnedGoalkeeper::new();
    let gk = owner.handle();
    let driven = gk.clone();

    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(driven.run_until(async move {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let tls = goalkeeper::http::tls::TlsConfig::new(Arc::new(server_config));
            let mut serving = gk
                .serve_https(listener, tls, app())
                .early_settings(early)
                .configure_hyper(configure)
                .spawn();
            // Done with its connection by the time it returns, since stopping
            // waits for every connection to finish.
            let out = client(addr, roots, gk.clone()).await;
            serving.stop().await;
            out
        }))
}

/// A TLS connection to `addr`, offering `alpn`.
async fn connect(
    addr: SocketAddr,
    roots: rustls::RootCertStore,
    alpn: Vec<Vec<u8>>,
) -> tokio_rustls::client::TlsStream<TcpStream> {
    connect_with(addr, roots, alpn, rustls::DEFAULT_VERSIONS).await
}

/// The same, offering only `versions` of TLS.
async fn connect_with(
    addr: SocketAddr,
    roots: rustls::RootCertStore,
    alpn: Vec<Vec<u8>>,
    versions: &[&'static rustls::SupportedProtocolVersion],
) -> tokio_rustls::client::TlsStream<TcpStream> {
    let mut client = rustls::ClientConfig::builder_with_protocol_versions(versions)
        .with_root_certificates(roots)
        .with_no_client_auth();
    client.alpn_protocols = alpn;
    let stream = TcpStream::connect(addr).await.unwrap();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client));
    let name = rustls::pki_types::ServerName::IpAddress(addr.ip().into());
    connector.connect(name, stream).await.unwrap()
}

/// A stream that reads `replay` before anything from `inner`.
struct Replay<S> {
    replay: Vec<u8>,
    at: usize,
    inner: S,
}

impl<S: AsyncRead + Unpin> AsyncRead for Replay<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.at < this.replay.len() {
            let length = buf.remaining().min(this.replay.len() - this.at);
            buf.put_slice(&this.replay[this.at..this.at + length]);
            this.at += length;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Replay<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}
