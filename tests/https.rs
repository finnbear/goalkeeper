//! What an HTTPS listener negotiates, over real loopback TCP.
//!
//! ALPN is the only way a browser reaches HTTP/2, and a `rustls::ServerConfig`
//! offers none by default. goalkeeper sets it rather than leaving it to the
//! caller, so this asserts a client that offers both is given `h2`.

#![cfg(feature = "tls")]

use goalkeeper::ArcGoalkeeper;
use goalkeeper::http::ServeHttp;
use std::sync::Arc;
use tokio::net::TcpListener;

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

/// Serves one HTTPS connection and reports the protocol it negotiated.
///
/// An instance of its own, so nothing here shares a schedule or a limiter with
/// another test.
fn negotiated(preset: bool) -> Option<Vec<u8>> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let (mut server_config, roots) = identity();
    if preset {
        server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    }
    let gk = ArcGoalkeeper::new();
    let driven = gk.clone();

    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(driven.run_until(async move {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let tls = goalkeeper::http::tls::TlsConfig::new(Arc::new(server_config));
            let mut serving = gk.serve_https(listener, tls, axum::Router::new()).spawn();

            let mut client = rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth();
            // Both, best first, exactly as a browser offers them.
            client.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

            let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
            let connector = tokio_rustls::TlsConnector::from(Arc::new(client));
            let name = rustls::pki_types::ServerName::IpAddress(addr.ip().into());
            let tls_stream = connector.connect(name, stream).await.unwrap();
            let negotiated = tls_stream.get_ref().1.alpn_protocol().map(<[u8]>::to_vec);

            drop(tls_stream);
            serving.stop().await;
            negotiated
        }))
}
