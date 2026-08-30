//! WebTransport over QUIC, scheduled and metered like everything else.
//!
//! `wtransport::Endpoint::server` hardcodes `Arc::new(TokioRuntime)`, leaving
//! no way to say where quinn's per-connection drivers are spawned, and those
//! drivers are where the QUIC handshake crypto runs. Its config accessors and
//! `IncomingSessionFuture::with_quic_incoming` are public, so the endpoint is
//! built directly on quinn with a `quinn::Runtime` of ours and each
//! `quinn::Incoming` handed back to wtransport for the h3 half. None of the
//! protocol is reimplemented here.
//!
//! One UDP socket carries every connection, so the driver demultiplexing it has
//! no correct fixed level. Each connection lends it their level and it runs at
//! the best of them; see
//! [`SharedPriority::depend_on`][crate::executor::priority::SharedPriority::depend_on].
//!
//! Connections report their own bytes exactly, since quinn counts wire bytes
//! per connection including acknowledgements and retransmissions. Traffic
//! belonging to no connection, which is the attack traffic, is the socket's
//! total minus what they reported.

use crate::conn::{Conn, Throttled, canonize};
use crate::executor::priority::{Priority, SharedPriority};
use crate::http::tls::TlsConfig;
use crate::resource::bandwidth::{self, Direction};
use crate::resource::handshake;
use crate::{Goalkeeper, ProvideGoalkeeper, SystemGoalkeeper};
use log::warn;
use std::cell::RefCell;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use wtransport::endpoint::{IncomingSessionFuture, SessionRequest};
use wtransport::quinn;

/// Connections beyond this are refused before any crypto: an endpoint holding
/// this many is already well past anything legitimate traffic produces.
const DEFAULT_MAX_OPEN: usize = 1000;

/// What a QUIC connection is charged when it is accepted.
///
/// Two flow-control windows at [`MIN_WINDOW`] plus quinn's own per-connection
/// state: the floor of what the connection costs however hard the controller
/// squeezes it. Everything above the floor is authorised later by [`govern`],
/// so this is what admission must afford rather than what the connection ends
/// up holding.
///
/// An authorisation rather than a measurement; see [`crate::memory`].
pub(crate) const PER_CONNECTION: u64 = MIN_WINDOW * 2 + 32 * 1024;

/// How often quinn's per-connection byte counters are read.
///
/// `Connection::stats` takes the connection's lock and copies a sizeable
/// struct, so it is sampled rather than consulted per packet. A sample per
/// window is all the resolution the ledger can use.
const SAMPLE_INTERVAL: Duration = Duration::from_millis(100);

/// Adjusts QUIC's transport parameters. See
/// [`WebTransportServerBuilder::configure_transport`].
///
/// `Fn` rather than `FnOnce`: applied to a fresh default per configuration
/// build, the same shape as the hyper escape hatch.
type ConfigureTransport = Arc<dyn Fn(&mut quinn::TransportConfig) + Send + Sync>;

/// Adjusts the endpoint's server configuration. See
/// [`WebTransportServerBuilder::configure_server`].
type ConfigureServer = Arc<dyn Fn(&mut quinn::ServerConfig) + Send + Sync>;

/// The constructor for [`WebTransportServerBuilder`], on the handle whose
/// budgets the server will serve against.
///
/// On the trait rather than on [`Goalkeeper`][crate::Goalkeeper] because a
/// server outlives the call that built it and has to remember which instance
/// rations it.
pub trait ServeWebTransport: ProvideGoalkeeper {
    /// Serves WebTransport sessions on `socket`, with the certificates in `tls`.
    ///
    /// The same [`TlsConfig`] the HTTPS listener takes, so one
    /// [`reload`][TlsConfig::reload] renews every listener at once. This
    /// endpoint re-reads it on the
    /// [`reload_every`][WebTransportServerBuilder::reload_every] cadence, and
    /// overrides the ALPN to WebTransport's, so the configuration can be shared
    /// without the caller minding it.
    ///
    /// `handler` receives each established session together with its [`Conn`],
    /// whose priority it should raise as the session proves itself.
    ///
    /// `socket` is bound by the caller, as [`ServeHttp`][crate::http::ServeHttp]
    /// takes an already-bound `TcpListener`, so which address and family the
    /// endpoint answers on is the caller's to choose. It is put into
    /// non-blocking mode here, since quinn requires that and nothing else would
    /// want it otherwise.
    fn serve_web_transport<H, Fut>(
        &self,
        socket: std::net::UdpSocket,
        tls: TlsConfig,
        handler: H,
    ) -> WebTransportServerBuilder<H, Self>
    where
        H: Fn(Session<Self>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        WebTransportServerBuilder {
            provider: self.clone(),
            socket,
            tls,
            handler,
            max_open: DEFAULT_MAX_OPEN,
            reload_every: Duration::from_secs(60),
            transport: None,
            server: None,
        }
    }
}

impl<P: ProvideGoalkeeper> ServeWebTransport for P {}

/// A WebTransport server that has not started yet.
///
/// [`WebTransportServerBuilder::spawn`] starts it.
pub struct WebTransportServerBuilder<H, P: ProvideGoalkeeper = SystemGoalkeeper> {
    provider: P,
    socket: std::net::UdpSocket,
    tls: TlsConfig,
    handler: H,
    max_open: usize,
    reload_every: Duration,
    transport: Option<ConfigureTransport>,
    server: Option<ConfigureServer>,
}

impl<H, Fut, P: ProvideGoalkeeper> WebTransportServerBuilder<H, P>
where
    H: Fn(Session<P>) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    /// Connections beyond which new ones are refused before any crypto.
    pub fn max_open_connections(mut self, max: usize) -> Self {
        self.max_open = max;
        self
    }

    /// Adjusts QUIC's transport parameters, which apply per connection.
    ///
    /// Goalkeeper sets the limits that are about denial of service, such as
    /// stream counts, and this is for everything else, such as keep-alives and
    /// idle timeouts. Runs after goalkeeper's own settings, so it wins where
    /// they overlap. Compare
    /// [`configure_hyper`][crate::http::HttpServerBuilder::configure_hyper].
    pub fn configure_transport<F>(mut self, configure: F) -> Self
    where
        F: Fn(&mut quinn::TransportConfig) + Send + Sync + 'static,
    {
        self.transport = Some(Arc::new(configure));
        self
    }

    /// Adjusts the endpoint's server configuration, which applies to the
    /// listener as a whole.
    ///
    /// [`Self::configure_transport`] for what applies per connection. Runs
    /// after goalkeeper's own settings and after the transport configuration
    /// has been installed, so it wins where they overlap.
    ///
    /// Applied once, at startup. A certificate reload replaces only
    /// [`ServerConfig::crypto`][quinn::ServerConfig::crypto] on a clone of what
    /// this produced, so whatever it sets survives one; setting `crypto` here
    /// is therefore pointless, since the first reload discards it.
    ///
    /// Take care with [`token_key`][quinn::ServerConfig::validation_token]: the
    /// address validation below depends on tokens outliving the round trip that
    /// carries them.
    pub fn configure_server<F>(mut self, configure: F) -> Self
    where
        F: Fn(&mut quinn::ServerConfig) + Send + Sync + 'static,
    {
        self.server = Some(Arc::new(configure));
        self
    }

    /// How often the TLS configuration is re-read, picking up a renewed
    /// certificate.
    ///
    /// The certificate and nothing else. The rest of the endpoint's
    /// configuration is fixed at startup, since the key sealing
    /// address-validation tokens cannot change without breaking the handshakes
    /// it is in the middle of. The first reload is one interval from now.
    pub fn reload_every(mut self, every: Duration) -> Self {
        self.reload_every = every;
        self
    }

    /// Starts the server, returning a handle to it.
    pub fn spawn(self) -> io::Result<WebTransportServer> {
        let base = self.quic_config()?;
        // The endpoint driver quinn spawns from here sees no ambient route, so
        // it lands at `Main`: it belongs to no connection and every connection
        // needs it.
        let runtime = Runtime::new(self.provider.clone());
        let (tx, rx) = runtime.meters();
        let Self {
            provider,
            socket,
            tls,
            handler,
            max_open,
            reload_every,
            ..
        } = self;
        // quinn requires it, and a caller has no other reason to have set it.
        socket.set_nonblocking(true)?;
        let endpoint = quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            Some(base.clone()),
            socket,
            Arc::new(runtime),
        )?;
        let closing = endpoint.clone();
        let accepting = Accepting {
            provider: provider.clone(),
            tls,
            handler,
            max_open,
            reload_every,
        };
        let task = provider.spawn(
            Priority::Accept,
            accepting.run(endpoint, Sampler { tx, rx }, base),
        );
        Ok(WebTransportServer {
            task: Some(task),
            endpoint: Some(closing),
        })
    }

    /// The whole QUIC configuration, built once at startup.
    ///
    /// The limits here are denial-of-service hardening and are goalkeeper's to
    /// set. [`Self::configure_transport`] and [`Self::configure_server`] are
    /// there for whatever is left, and run last.
    fn quic_config(&self) -> io::Result<quinn::ServerConfig> {
        let mut transport = quinn::TransportConfig::default();
        // A connection's streams are a memory bound goalkeeper answers for, and
        // a game-shaped protocol wants a handful, not quinn's default hundred.
        transport.max_concurrent_uni_streams(4u32.into());
        transport.max_concurrent_bidi_streams(4u32.into());
        if let Some(configure) = &self.transport {
            configure(&mut transport);
        }

        // `with_crypto` generates the random `token_key` that seals retry
        // tokens, so this is built exactly once. See the reload arm in `run`.
        let mut config = quinn::ServerConfig::with_crypto(crypto(&self.tls)?);
        config.transport_config(Arc::new(transport));
        config.migration(true);
        // Handshakes admitted before goalkeeper's own slots see them, and the
        // buffers quinn may fill for them. Bounded so an address validation
        // flood costs a few megabytes rather than a few gigabytes.
        config.max_incoming(256);
        config.incoming_buffer_size(256 * 1024);
        config.incoming_buffer_size_total(8 * 1024 * 1024);
        // Short, because a token outliving its handshake is only spoofing
        // surface.
        config.retry_token_lifetime(Duration::from_secs(10));

        // Last, so the caller wins over goalkeeper's own settings and over the
        // transport configuration installed above.
        if let Some(configure) = &self.server {
            configure(&mut config);
        }
        Ok(config)
    }
}

/// The accept loop's own state, which is the builder minus what only startup
/// needed.
///
/// Separate so [`WebTransportServerBuilder::spawn`] can move the socket into
/// quinn and still hand the rest to the loop, and so the loop cannot reach for
/// a socket it no longer owns.
struct Accepting<H, P: ProvideGoalkeeper> {
    provider: P,
    tls: TlsConfig,
    handler: H,
    max_open: usize,
    reload_every: Duration,
}

/// The TLS half of the configuration, from `tls` as of now.
///
/// The ALPN is forced to WebTransport's, since the configuration is typically
/// shared with an HTTPS listener whose ALPN says `h2`.
fn crypto(tls: &TlsConfig) -> io::Result<Arc<quinn::crypto::rustls::QuicServerConfig>> {
    let mut rustls = tls.current().as_ref().clone();
    rustls.alpn_protocols = vec![wtransport::proto::WEBTRANSPORT_ALPN.to_vec()];
    quinn::crypto::rustls::QuicServerConfig::try_from(rustls)
        .map(Arc::new)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))
}

impl<H, Fut, P: ProvideGoalkeeper> Accepting<H, P>
where
    H: Fn(Session<P>) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    async fn run(self, endpoint: quinn::Endpoint, mut sampler: Sampler, base: quinn::ServerConfig) {
        // Shared rather than borrowed: each session's task outlives this loop's
        // stack frame, so the handler has to be `'static` for all of them.
        let handler = Arc::new(self.handler);
        // Lends its level to the driver; every connection lends to this.
        let driver = SharedPriority::new(Priority::New);
        // One period out, not now: `interval` fires its first tick immediately,
        // and reloading at t=0 would replace the config built moments ago in
        // `endpoint`, in the middle of the first handshakes. See the reload arm
        // below for why that is fatal.
        let mut reload = tokio::time::interval_at(
            tokio::time::Instant::now() + self.reload_every,
            self.reload_every,
        );
        // A reload that runs late is a reload that runs once. Bursting to catch
        // up would re-read the certificate several times in a row for nothing.
        reload.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut sample = tokio::time::interval(SAMPLE_INTERVAL);

        loop {
            let incoming = tokio::select! {
                incoming = endpoint.accept() => match incoming {
                    Some(incoming) => incoming,
                    // The endpoint was closed, which is how this loop ends.
                    None => break,
                },
                _ = reload.tick() => {
                    // Only the certificate, never the whole config.
                    //
                    // A `quinn::ServerConfig` carries `token_key`, the secret
                    // the retry tokens below are sealed with, and building one
                    // generates a new random key. Installing a fresh config
                    // stops the token a client is carrying from decrypting;
                    // quinn cannot tell that from a client that sent none, so
                    // it hands the connection back unvalidated and this loop
                    // retries it. Having processed one Retry, the client must
                    // discard every later one (RFC 9000 §17.2.5.2), so it
                    // answers with the same dead token forever. Cloning the
                    // original config keeps the key that issued those tokens.
                    match crypto(&self.tls) {
                        Ok(crypto) => {
                            let mut next = base.clone();
                            next.crypto = crypto;
                            endpoint.set_server_config(Some(next));
                        }
                        // The old certificate keeps serving; a reload must
                        // never take down a listener that was working.
                        Err(e) => warn!("skipping TLS reload: {e}"),
                    }
                    continue;
                }
                _ = sample.tick() => {
                    sampler.sample(&self.provider);
                    continue;
                }
            };

            if endpoint.open_connections() > self.max_open {
                incoming.refuse();
                continue;
            }

            // Makes the peer prove its address before anything is spent on it.
            // Costs one packet and defeats spoofed-source floods. Before
            // admission, whose per-address accounting would otherwise be keyed
            // on addresses that may not exist.
            if !incoming.remote_address_validated() {
                let _ = incoming.retry();
                continue;
            }

            let peer = canonize(incoming.remote_address());
            let Some(permit) = self
                .provider
                .connection_permit(peer.ip(), "QUIC connection")
            else {
                incoming.refuse();
                continue;
            };
            let (conn, _killed) = Conn::new(peer, permit);
            // What quinn is authorised to buffer for this connection, charged
            // at accept rather than discovered when the windows are set. A
            // refusal is the memory ledger's backstop, so the connection is
            // refused rather than admitted into a budget with no room for it.
            let Some(ram) = conn.try_reserve(PER_CONNECTION) else {
                incoming.refuse();
                continue;
            };
            let accepted_at = Instant::now();
            let slot = self.provider.handshake_slot(peer.ip(), accepted_at);
            // Everything already sharing the socket, this one included, so the
            // opening windows are a fair share rather than a guess. Read here
            // because this is the last place that holds the endpoint.
            let population = endpoint.open_connections().max(1);

            let priority = conn.priority().clone();
            // While this connection lives, the driver runs at least as well as
            // it does.
            let inherit = priority.depend_on(&driver);
            let session = IncomingSessionFuture::with_quic_incoming(incoming);
            let handler = Arc::clone(&handler);

            // `route` must wrap the future that polls the session, not its
            // construction: `Incoming::accept`, and so the `Runtime::spawn` of
            // the connection driver, runs on the first poll.
            let routed = route(priority.clone(), async move {
                let _inherit = inherit;
                // Held for the connection's life, so the ledger sees it go when
                // the session ends however it ends.
                let _ram = ram;
                #[allow(
                    clippy::single_match,
                    reason = "the empty arm is where the reasoning lives"
                )]
                match handshake::bounded(slot, session).await {
                    Some(Ok(request)) => {
                        handler(Session {
                            request,
                            conn,
                            population,
                        })
                        .await
                    }
                    // Failed, out of time, evicted, or the peer went away.
                    // Nothing to log that the counters do not already show.
                    Some(Err(_)) | None => {}
                }
            });
            self.provider.spawn_with(priority, routed).detach();
        }
    }
}

/// A running WebTransport server.
pub struct WebTransportServer {
    task: Option<async_task::Task<()>>,
    /// An `Option` so [`Self::stop`] can drop it.
    ///
    /// quinn's endpoint driver runs for as long as any [`quinn::Endpoint`]
    /// handle exists, so holding one here would keep the driver alive through a
    /// complete shutdown. The surviving task belongs to a runtime that has gone
    /// away, so whoever polls it next panics inside tokio's timer.
    endpoint: Option<quinn::Endpoint>,
}

impl WebTransportServer {
    /// Stops accepting, tells peers the endpoint is going away, and waits for
    /// connections to finish.
    ///
    /// Uses quinn's own shutdown rather than cancelling the accept task:
    /// `close` sends a `CONNECTION_CLOSE` so peers learn why instead of timing
    /// out, and `wait_idle` resolves once they have acknowledged it.
    pub async fn stop(&mut self) {
        let Some(endpoint) = self.endpoint.take() else {
            return;
        };
        // Closing makes `accept` return `None`, so the loop ends under its own
        // power rather than by being killed.
        endpoint.close(0u32.into(), b"shutting down");
        if let Some(task) = self.task.take() {
            task.await;
        }
        endpoint.wait_idle().await;
        // The last handle, so the driver may now finish too. See the field.
        drop(endpoint);
    }

    /// Returns how many connections are currently open.
    pub fn connections(&self) -> usize {
        self.endpoint
            .as_ref()
            .map(quinn::Endpoint::open_connections)
            .unwrap_or(0)
    }
}

impl Drop for WebTransportServer {
    fn drop(&mut self) {
        // The abrupt path, as for HTTP: peers are told, but nothing is awaited.
        // Dropping the handle is still what releases the driver.
        if let Some(endpoint) = self.endpoint.take() {
            endpoint.close(0u32.into(), b"shutting down");
        }
        self.task.take();
    }
}

/// A session offered to the application, which governs itself if accepted.
///
/// Accepting is the caller's decision, and until it is made there is no
/// connection to govern. This stands in for a bare [`SessionRequest`] so the
/// governor comes with the session rather than depending on every call site to
/// ask for it.
pub struct Session<P: ProvideGoalkeeper = SystemGoalkeeper> {
    request: SessionRequest,
    conn: Conn<P>,
    /// Connections the endpoint held when this one arrived, which is what its
    /// opening windows are divided by. See [`Self::accept`].
    population: usize,
}

impl<P: ProvideGoalkeeper> Session<P> {
    /// Returns what the peer asked for, before deciding whether to accept.
    pub fn request(&self) -> &SessionRequest {
        &self.request
    }

    /// Returns the connection's goalkeeper state: priority, address, byte
    /// counters.
    pub fn conn(&self) -> &Conn<P> {
        &self.conn
    }

    /// Accepts the session, bounded and governed.
    ///
    /// Both flow-control windows are set before the connection is handed back,
    /// and so before it can carry anything, to the process's budget divided by
    /// the connections already open. quinn's defaults are sized for a link with
    /// nobody else on it: measured, one such session put 1.28MB on the wire in
    /// 300ms, a hundred windows' worth, before the governor's first tick.
    ///
    /// The opening share is pessimistic by design. A connection that deserves
    /// more is given it by the governor within a window.
    pub async fn accept(self) -> Result<GovernedConnection<P>, wtransport::error::ConnectionError> {
        let connection = self.request.accept().await?;

        let quic = connection.quic_connection();
        let rtt = quic.rtt();
        let window = bandwidth::window_of(self.conn.provider());
        let share = |dir| self.conn.provider().budget_per_window(dir) / self.population as u64;
        quic.set_send_window(flight(share(Direction::Tx), window, rtt));
        quic.set_receive_window(
            quinn::VarInt::from_u64(flight(share(Direction::Rx), window, rtt))
                .unwrap_or(quinn::VarInt::MAX),
        );

        let governor = govern(&connection, &self.conn);
        Ok(GovernedConnection {
            connection,
            conn: self.conn,
            _governor: governor,
        })
    }

    /// The request itself, for anything this does not wrap, mostly the several
    /// ways wtransport can refuse a session.
    ///
    /// Taking it gives up the governor, since this is the path where no session
    /// is accepted.
    pub fn into_request(self) -> SessionRequest {
        self.request
    }
}

/// An accepted WebTransport session, governed for as long as it is held.
///
/// Used exactly like the [`wtransport::Connection`] it derefs to. The governor
/// lives and dies with the connection, so dropping this cancels it rather than
/// leaving a task asking the ledger about a session that has gone.
pub struct GovernedConnection<P: ProvideGoalkeeper = SystemGoalkeeper> {
    connection: wtransport::Connection,
    /// Handed to every stream this connection opens, so they share one ration.
    conn: Conn<P>,
    _governor: async_task::Task<()>,
}

impl<P: ProvideGoalkeeper> GovernedConnection<P> {
    /// The bare connection, giving up the governor.
    ///
    /// For a caller that wants the ration to stop applying, or that needs to
    /// move the connection somewhere this cannot follow.
    pub fn into_inner(self) -> wtransport::Connection {
        self.connection
    }

    /// Opens a unidirectional stream, rationed.
    ///
    /// The stream is wrapped in [`Throttled`] against this connection's
    /// [`Conn`], which is where WebTransport's rate limiting lives: delaying a
    /// write, as TCP does. The flow-control windows the governor sets are a
    /// coarse second line, bounded below by one datagram.
    ///
    /// Every stream shares the one ration, so opening more buys no bandwidth.
    /// `io::Result` because the two stages of opening a stream fail with two
    /// different wtransport errors.
    pub async fn open_uni(&self) -> io::Result<Throttled<wtransport::SendStream, P>> {
        let opening = self.connection.open_uni().await.map_err(io::Error::other)?;
        let stream = opening.await.map_err(io::Error::other)?;
        Ok(Throttled::new(stream, self.conn.clone()))
    }

    /// Opens a bidirectional stream, rationed. See [`Self::open_uni`].
    #[allow(clippy::type_complexity, reason = "a rationed pair is still a pair")]
    pub async fn open_bi(
        &self,
    ) -> io::Result<(
        Throttled<wtransport::SendStream, P>,
        Throttled<wtransport::RecvStream, P>,
    )> {
        let opening = self.connection.open_bi().await.map_err(io::Error::other)?;
        let (send, recv) = opening.await.map_err(io::Error::other)?;
        Ok((
            Throttled::new(send, self.conn.clone()),
            Throttled::new(recv, self.conn.clone()),
        ))
    }

    /// Accepts a unidirectional stream, rationed. See [`Self::open_uni`].
    pub async fn accept_uni(&self) -> io::Result<Throttled<wtransport::RecvStream, P>> {
        let stream = self
            .connection
            .accept_uni()
            .await
            .map_err(io::Error::other)?;
        Ok(Throttled::new(stream, self.conn.clone()))
    }

    /// Accepts a bidirectional stream, rationed. See [`Self::open_uni`].
    #[allow(clippy::type_complexity, reason = "a rationed pair is still a pair")]
    pub async fn accept_bi(
        &self,
    ) -> io::Result<(
        Throttled<wtransport::SendStream, P>,
        Throttled<wtransport::RecvStream, P>,
    )> {
        let (send, recv) = self
            .connection
            .accept_bi()
            .await
            .map_err(io::Error::other)?;
        Ok((
            Throttled::new(send, self.conn.clone()),
            Throttled::new(recv, self.conn.clone()),
        ))
    }
}

impl<P: ProvideGoalkeeper> std::ops::Deref for GovernedConnection<P> {
    type Target = wtransport::Connection;

    fn deref(&self) -> &Self::Target {
        &self.connection
    }
}

/// Holds a WebTransport session's QUIC flow-control windows to its bandwidth
/// ration, for as long as the returned task lives.
///
/// What [`crate::conn::ConnIo`] does for TCP, by a different route: goalkeeper
/// does not own the streams, so there is nowhere to park a QUIC write, but
/// quinn exposes both windows per connection and lets them change at any time.
///
/// Call it once, after `SessionRequest::accept`, which is the first point at
/// which the application holds a [`wtransport::Connection`].
///
/// # How the window is chosen
///
/// A window is bytes in flight, so the rate it permits is `window / rtt`, and
/// the window sustaining a given rate is the bandwidth-delay product `rate ·
/// rtt`. quinn tracks the round trip per connection and it is re-read every
/// window, so a connection gets the window its distance calls for.
///
/// A floor and a ceiling bound the result. Below the floor a window stalls a
/// connection rather than pacing it, so on a short link, loopback especially,
/// this stops being a rate limit and becomes only a memory bound.
pub(crate) fn govern<P: ProvideGoalkeeper>(
    connection: &wtransport::Connection,
    conn: &Conn<P>,
) -> async_task::Task<()> {
    let quic = connection.quic_connection().clone();
    let conn = conn.clone();
    let priority = conn.priority().clone();
    // Subscribed before the task starts, so a tick between here and the first
    // park is seen rather than slept through.
    let mut controller = conn.provider().controller.subscribe();
    conn.provider().clone().spawn_with(priority, async move {
        // What the connection was last told, so it is only told again when the
        // target has moved a whole bucket. Zero means nothing has been applied.
        let mut applied_tx = 0u64;
        let mut applied_rx = 0u64;
        loop {
            // Not metering here. The streams meter themselves, see
            // `Throttled`, and doing both charged every byte twice: the
            // wire-level pass consumed the credit the stream had just leased,
            // throttling a connection to a standstill by its own accounting.
            //
            // Acknowledgements and retransmissions are therefore not attributed
            // per connection. They are still counted, since the socket meter
            // sees every byte and whatever connections do not claim is charged
            // to `Priority::New`. TCP is metered the same way.
            //
            // Sized from the level's whole allowance rather than what remains,
            // which shrinks as the connection sends: a window that shrinks
            // under data already in flight stalls rather than paces.
            //
            // The rate is the streams' job, so this is a memory bound and
            // `HEADROOM` keeps it clear of binding on rate.
            let window = bandwidth::window_of(conn.provider());
            let rtt = quic.rtt();
            let tx = flight(bandwidth::allowance(&conn, Direction::Tx), window, rtt) * HEADROOM;
            let rx = flight(bandwidth::allowance(&conn, Direction::Rx), window, rtt) * HEADROOM;

            // Two ledgers want this number: bandwidth wants the delay-bandwidth
            // product, memory a share of what is left of the budget. The
            // smaller wins, and the two stay ignorant of each other.
            //
            // Quantised and deadbanded, so a drifting window does not spend a
            // pair of syscalls every tick. See `crate::resource::memory`.
            // A session established since the last tick takes its memory with
            // it, before the ceiling below is computed from its level.
            conn.reconcile_ram();
            let ceiling = crate::resource::memory::window_ceiling(&conn);
            let tx = crate::resource::memory::quantise(tx.min(ceiling)).max(MIN_WINDOW);
            let rx = crate::resource::memory::quantise(rx.min(ceiling)).max(MIN_WINDOW);

            if crate::resource::memory::worth_applying(applied_tx, tx) {
                applied_tx = tx;
                quic.set_send_window(tx);
            }
            if crate::resource::memory::worth_applying(applied_rx, rx) {
                applied_rx = rx;
                quic.set_receive_window(quinn::VarInt::from_u64(rx).unwrap_or(quinn::VarInt::MAX));
            }

            // Parks until the controller runs again rather than on a timer of
            // its own; the deadband means a pass between ticks could only
            // recompute the number it just applied.
            //
            // `Err` is the sender gone, which cannot happen while `conn` holds
            // a provider, but a governor outliving its goalkeeper should stop
            // rather than spin.
            if controller.changed().await.is_err() {
                return;
            }
        }
    })
}

impl<P: ProvideGoalkeeper> Throttled<wtransport::SendStream, P> {
    /// wtransport's `write_all`, rationed.
    ///
    /// An inherent method shadowing `AsyncWriteExt::write_all`, since the trait
    /// would force this through `io::Error` and cost callers wtransport's
    /// `StreamWriteError`, which distinguishes a reset stream from a lost
    /// connection.
    ///
    /// Written in slices of whatever the ration allows, waiting between them.
    /// Every stream on the connection draws on the same ration.
    pub async fn write_all(
        &mut self,
        buf: &[u8],
    ) -> Result<(), wtransport::error::StreamWriteError> {
        let mut sent = 0;
        while sent < buf.len() {
            let allowed = self.conn().await_credit(Direction::Tx).await;
            let end = buf.len().min(sent + allowed as usize);
            let slice = &buf[sent..end];
            // `inner_mut`, since the ration was just waited for and the bytes
            // are counted below; the wrapper would double-count them.
            self.inner_mut().write_all(slice).await?;
            self.conn().record(Direction::Tx, slice.len() as u64);
            sent = end;
        }
        Ok(())
    }

    /// Closes the stream. Control rather than data, so it is not rationed.
    pub async fn finish(&mut self) -> Result<(), wtransport::error::StreamWriteError> {
        self.inner_mut().finish().await
    }
}

/// [`bandwidth::flight`] bounded to what a QUIC connection can use.
fn flight(ration: u64, window: Duration, rtt: Duration) -> u64 {
    bandwidth::flight(ration, window, rtt).clamp(MIN_WINDOW, MAX_WINDOW)
}

/// The smallest flow-control window a governed session is ever given.
///
/// Just under one datagram. QUIC requires a path to carry 1200-byte datagrams
/// and sizes its packets to fit, so a smaller window cannot hold one packet in
/// flight and stalls the connection instead of pacing it.
///
/// It is therefore the floor on what a window can express: one packet per round
/// trip, about 24kB/s at 50ms and 8kB/s at 150ms. A ration below that is a
/// memory bound rather than a rate limit. See [`govern`].
const MIN_WINDOW: u64 = 1_200;

/// How much slack a governed window is given over the bandwidth-delay product
/// of its allowance.
///
/// The window is a memory bound and [`Throttled`] does the rate, so it should
/// sit clear of the rate it would otherwise impose. Exactly at the product it
/// binds on rate too, and the two mechanisms fighting held WebTransport well
/// below what TCP managed.
const HEADROOM: u64 = 4;

/// The largest, so a connection on a long link cannot be granted an unbounded
/// buffer just because its round trip is slow.
const MAX_WINDOW: u64 = 8 * 1024 * 1024;

/// Reports the socket's wire totals, which the per-connection counts from
/// [`govern`] are reconciled against by subtraction.
struct Sampler {
    tx: Arc<AtomicU64>,
    rx: Arc<AtomicU64>,
}

impl Sampler {
    /// Records against `gk`, the instance this endpoint belongs to, rather than
    /// the process's: an endpoint on an [`ArcGoalkeeper`][crate::ArcGoalkeeper]
    /// must not charge its wire totals to the system ledger.
    fn sample(&mut self, gk: &Goalkeeper) {
        // The socket meter is an aggregate and connections report themselves,
        // so the difference is traffic belonging to no connection, which is
        // precisely the attack traffic.
        bandwidth::record_socket_total_of(gk, Direction::Tx, self.tx.load(Ordering::Relaxed));
        bandwidth::record_socket_total_of(gk, Direction::Rx, self.rx.load(Ordering::Relaxed));
    }
}

thread_local! {
    /// Where quinn's spawns should go during the current poll. `None` means
    /// [`Priority::Main`], which is correct for endpoint construction: the
    /// endpoint driver belongs to no connection and serves all of them.
    static ROUTE: RefCell<Option<SharedPriority>> = const { RefCell::new(None) };
}

/// Runs `future` with quinn's spawns routed to `priority`.
///
/// `Incoming::accept` calls `Runtime::spawn` synchronously, so an ambient route
/// set for the duration of a poll routes deterministically.
fn route<F>(priority: SharedPriority, future: F) -> Routed<F> {
    Routed { future, priority }
}

#[pin_project::pin_project]
struct Routed<F> {
    #[pin]
    future: F,
    priority: SharedPriority,
}

impl<F: Future> Future for Routed<F> {
    type Output = F::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        let restore = ROUTE.with(|route| route.borrow_mut().replace(this.priority.clone()));
        let guard = RouteGuard(Some(restore));
        let polled = this.future.poll(cx);
        drop(guard);
        polled
    }
}

/// Restores the previous route even if the wrapped poll panics.
struct RouteGuard(Option<Option<SharedPriority>>);

impl Drop for RouteGuard {
    fn drop(&mut self) {
        if let Some(previous) = self.0.take() {
            ROUTE.with(|route| *route.borrow_mut() = previous);
        }
    }
}

/// A [`quinn::Runtime`] that puts quinn's tasks on goalkeeper's executor and
/// meters the UDP socket.
///
/// Timers, clock and socket wrapping delegate to quinn's own Tokio runtime;
/// only `spawn` and the socket differ.
///
/// Generic over the provider even though quinn stores it as an `Arc<dyn
/// quinn::Runtime>`, so the concrete type still carries whichever goalkeeper
/// this endpoint serves. Otherwise an
/// [`ArcGoalkeeper`][crate::ArcGoalkeeper]'s QUIC drivers would be spawned onto
/// the process's executor, which nothing may be driving.
struct Runtime<P: ProvideGoalkeeper> {
    provider: P,
    inner: quinn::TokioRuntime,
    /// The socket's wire totals, shared with the [`Metered`] socket it wraps.
    ///
    /// Held here because quinn calls `wrap_udp_socket` during endpoint
    /// construction and its return value disappears into the endpoint, so
    /// counters created there would be written forever and read by nobody.
    tx: Arc<AtomicU64>,
    rx: Arc<AtomicU64>,
}

/// Hand-written because `derive` would demand `P: Debug`, which a provider has
/// no reason to be. quinn requires it of the trait; nothing reads it.
impl<P: ProvideGoalkeeper> std::fmt::Debug for Runtime<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Runtime").finish_non_exhaustive()
    }
}

impl<P: ProvideGoalkeeper> Runtime<P> {
    fn new(provider: P) -> Self {
        Self {
            provider,
            inner: quinn::TokioRuntime,
            tx: Arc::new(AtomicU64::new(0)),
            rx: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Handles on the socket's totals, for whoever reports on them.
    fn meters(&self) -> (Arc<AtomicU64>, Arc<AtomicU64>) {
        (Arc::clone(&self.tx), Arc::clone(&self.rx))
    }
}

impl<P: ProvideGoalkeeper> quinn::Runtime for Runtime<P> {
    fn new_timer(&self, at: Instant) -> Pin<Box<dyn quinn::AsyncTimer>> {
        self.inner.new_timer(at)
    }

    fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>) {
        match ROUTE.with(|route| route.borrow().clone()) {
            // A connection being handshaken: its driver is its own work.
            Some(priority) => self.provider.spawn_with(priority, future).detach(),
            // Endpoint construction and anything else quinn does on its own.
            // The endpoint driver serves every connection, so it is never a
            // stranger's work.
            None => self.provider.spawn(Priority::Main, future).detach(),
        }
    }

    fn wrap_udp_socket(
        &self,
        socket: std::net::UdpSocket,
    ) -> io::Result<Arc<dyn quinn::AsyncUdpSocket>> {
        Ok(Arc::new(Metered {
            inner: self.inner.wrap_udp_socket(socket)?,
            tx: Arc::clone(&self.tx),
            rx: Arc::clone(&self.rx),
        }))
    }

    fn now(&self) -> Instant {
        self.inner.now()
    }
}

/// Counts wire bytes at the shared UDP socket.
///
/// One counter update per batch rather than per datagram: with GSO and GRO a
/// single `try_send` carries up to 64 datagrams and a single `poll_recv` fills
/// several `RecvMeta`s, and both report the total directly.
#[derive(Debug)]
struct Metered {
    inner: Arc<dyn quinn::AsyncUdpSocket>,
    tx: Arc<AtomicU64>,
    rx: Arc<AtomicU64>,
}

impl quinn::AsyncUdpSocket for Metered {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn quinn::UdpPoller>> {
        Arc::clone(&self.inner).create_io_poller()
    }

    fn try_send(&self, transmit: &quinn::udp::Transmit) -> io::Result<()> {
        let sent = self.inner.try_send(transmit);
        if sent.is_ok() {
            self.tx
                .fetch_add(transmit.contents.len() as u64, Ordering::Relaxed);
        }
        sent
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [io::IoSliceMut<'_>],
        meta: &mut [quinn::udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let polled = self.inner.poll_recv(cx, bufs, meta);
        if let Poll::Ready(Ok(received)) = &polled {
            let bytes: u64 = meta[..*received].iter().map(|m| m.len as u64).sum();
            self.rx.fetch_add(bytes, Ordering::Relaxed);
        }
        polled
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        self.inner.max_transmit_segments()
    }

    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}

/// Logs what a refused endpoint could not do, at most as often as it is useful.
#[allow(dead_code)]
fn note(what: &str) {
    warn!("web_transport: {what}");
}
