use axum::{
    body::Body,
    extract::{ws::Message, ConnectInfo, WebSocketUpgrade},
    response::Response,
    routing::get,
    Router,
};
use axum_server::{accept::Accept, Server};
use futures_util::SinkExt;
use goalkeeper::{
    axum::AxumServerAcceptor,
    ip_limiter::{ActiveSession, ProvideIpLimiter, SystemIpLimiter},
    rate_limiter::RateLimiterProps,
};
use hyper::StatusCode;
use log::{info, LevelFilter};
use std::{
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    process::Command,
    time::{Duration, Instant},
};
use tokio::net::TcpStream;

#[tokio::main]
pub async fn main() {
    env_logger::builder().filter_level(LevelFilter::Info).init();

    info!("you must run this example on Linux, as root");

    SystemIpLimiter.set_custom_limits(RateLimiterProps::new(Duration::from_secs(1), 3));
    SystemIpLimiter.set_total_connections_soft_limit(16);

    let router = Router::new().route(
        "/ws",
        get(
            move |addr: ConnectInfo<SocketAddr>, websocket: WebSocketUpgrade| async move {
                let ip = addr.ip();
                if SystemIpLimiter.should_limit_custom(ip, 1, Instant::now()) {
                    log::trace!("refusing {ip} due to too many WebSockets");
                    return Response::builder()
                        .status(StatusCode::TOO_MANY_REQUESTS)
                        .body(Body::new("Too many requests".to_owned()))
                        .unwrap();
                }
                websocket
                    .max_frame_size(16384)
                    .max_message_size(16384)
                    .write_buffer_size(8192)
                    .max_write_buffer_size(16384)
                    .on_upgrade(move |mut websocket| async move {
                        let _session = ActiveSession::new(ip);

                        loop {
                            match websocket.recv().await {
                                None => break,
                                Some(Ok(message)) => {
                                    let len = match &message {
                                        Message::Binary(b) => b.len(),
                                        Message::Text(t) => t.len(),
                                        _ => 100,
                                    };
                                    if SystemIpLimiter.should_limit_bandwidth(
                                        ip,
                                        len as u32,
                                        "WS message",
                                        Instant::now(),
                                    ) {
                                        // Ignore.
                                        continue;
                                    }
                                    if websocket.send(message).await.is_err() {
                                        break;
                                    }
                                }
                                Some(Err(_)) => break,
                            }
                        }

                        drop(_session);
                    })
            },
        ),
    );

    // If you had separate HTTP and HTTPS servers, you could use a trait like this
    // to configure both.
    trait ConfigureExt<S, A> {
        fn configure(self) -> Server<AxumServerAcceptor<S, A>>;
    }
    impl<S, A: Accept<TcpStream, S>> ConfigureExt<S, A> for Server<A> {
        fn configure(mut self) -> Server<AxumServerAcceptor<S, A>> {
            let http = self.http_builder();
            http.http1()
                .timer(hyper_util::rt::TokioTimer::new())
                .keep_alive(true)
                .header_read_timeout(Duration::from_secs(5))
                .max_buf_size(32768);
            self.map(AxumServerAcceptor::new)
        }
    }

    const PORT: u16 = 8000;

    let http_server = axum_server::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), PORT))
        .configure()
        .serve(router.into_make_service_with_connect_info::<SocketAddr>());

    #[derive(Copy, Clone, Default, Debug, PartialEq)]
    struct Abuse {
        too_many_connections_per_ip: bool,
        too_high_connection_rate: bool,
        no_handshake: bool,
        too_high_message_rate: bool,
    }

    for i in 0..32 {
        let abuse = Abuse {
            too_many_connections_per_ip: i & 0b1 != 0,
            too_high_connection_rate: i & 0b10 != 0,
            no_handshake: i & 0b100 != 0,
            too_high_message_rate: i & 0b1000 != 0,
        };

        for _ in 0..if abuse.too_many_connections_per_ip {
            10
        } else {
            1
        } {
            tokio::spawn(async move {
                loop {
                    let stream = connect_to_localhost_from_nth_ip(i, PORT).unwrap();

                    if abuse.no_handshake {
                        tokio::time::sleep(Duration::from_millis(500)).await;
                        break;
                    }
                    let Ok((mut client, _)) = tokio_websockets::ClientBuilder::new()
                        .uri(&format!("ws://127.0.0.1:{PORT}/ws"))
                        .unwrap()
                        .connect_on(stream)
                        .await
                    else {
                        assert_ne!(abuse, Default::default());
                        tokio::time::sleep(Duration::from_millis(10)).await;
                        continue;
                    };

                    let start = Instant::now();

                    loop {
                        if start.elapsed()
                            > Duration::from_millis(if abuse.too_high_connection_rate {
                                500
                            } else {
                                5000
                            })
                        {
                            break;
                        }

                        client
                            .send(tokio_websockets::Message::text("f".repeat(1024)))
                            .await
                            .unwrap();

                        tokio::time::sleep(Duration::from_millis(if abuse.too_high_message_rate {
                            5
                        } else {
                            100
                        }))
                        .await;
                    }
                }
            });
        }
    }

    tokio::spawn(async move {
        loop {
            let mut ips = 0u32;
            let mut connections = 0;
            let mut active_sessions = 0;
            SystemIpLimiter.stats(|_, s| {
                ips += 1;
                connections += s.connections;
                active_sessions += s.active_sessions;
            });

            log::info!("ips: {ips} connections: {connections} active sessions: {active_sessions}");

            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    });

    http_server.await.unwrap();
}

/// Creates a new IP address to connect to a port on localhost.
fn connect_to_localhost_from_nth_ip(nth: u16, port: u16) -> io::Result<TcpStream> {
    let link = String::from_utf8(
        Command::new("ip")
            .arg("link")
            .arg("show")
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap()
    .lines()
    .filter_map(|l| {
        l.split_ascii_whitespace()
            .nth(1)
            .map(|l| l.trim_end_matches(':').to_owned())
    })
    .find(|l| l.starts_with("en") || l.starts_with("eth") || l.starts_with("wl"))
    .unwrap();

    let local_ipv4 = Ipv4Addr::new(127, 42, (nth >> 8) as u8, nth as u8);

    let add = Command::new("ip")
        .arg("addr")
        .arg("add")
        .arg(&local_ipv4.to_string())
        .arg("dev")
        .arg(&format!("{link}:0"))
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&add.stderr);
    assert!(
        add.status.success() || stderr.contains("File exists"),
        "{stderr}"
    );

    let local_addr = SocketAddr::new(IpAddr::V4(local_ipv4), 0);
    let dest_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));

    let socket = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )?;

    socket.bind(&local_addr.into())?;
    socket.connect(&dest_addr.into())?;
    socket.set_nonblocking(true)?;

    Ok(TcpStream::from_std(socket.into())?)
}
