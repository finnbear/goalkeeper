//! Serving HTTP and HTTPS with everything else already wired in.
//!
//! Accept, admit, handshake, serve, ordered so the cheapest refusals happen
//! first: the per-address limiter admits a connection before any crypto, and
//! under `tls` the handshake then takes a slot from `crate::resource::handshake`,
//! giving it up as soon as it resolves. A plaintext listener has no crypto to
//! ration and never reaches the pool.
//!
//! Accept loops run at [`Priority::Accept`] and connections start at
//! [`Priority::New`]. Raise a connection with `conn.set_base(..)` as
//! it establishes itself. The HTTP/1 and HTTP/2 limits here are DoS hardening
//! rather than caller policy; [`HttpServerBuilder::configure_hyper`] is for
//! everything else.
//!
//! [`HttpServer::stop`] is graceful: the accept loop is asked to finish, then
//! hyper writes in-flight responses and sends `GOAWAY` on HTTP/2. Dropping a
//! [`HttpServer`] without stopping it drops connections mid-response.

#[cfg(feature = "tls")]
pub mod tls;
#[cfg(feature = "tls")]
mod tls_stream;
#[cfg(feature = "web_socket")]
pub mod web_socket;

use crate::conn::{Conn, ConnIo};

#[cfg(feature = "tls")]
use crate::resource::handshake;
use crate::{ProvideGoalkeeper, SystemGoalkeeper};
#[cfg(feature = "tls")]
use tls_stream::TlsStream;

use crate::executor::priority::{Priority, SharedPriority};
use axum::Router;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::server::conn::auto;
use hyper_util::server::graceful::{GracefulShutdown, Watcher};
use hyper_util::service::TowerToHyperService;
use log::warn;
use std::future::{Future, IntoFuture};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::Notify;

/// Expires dead connections in seconds rather than at the OS default, which
/// holds file descriptors and permits against a peer that has gone away.
const KEEPALIVE: Duration = Duration::from_secs(10);
const KEEPALIVE_RETRIES: u32 = 2;

/// The longest an accept loop waits after a failure.
///
/// The loop never gives up; this only keeps a persistently failing `accept`
/// from spinning.
const ACCEPT_BACKOFF_CEILING: Duration = Duration::from_secs(1);

/// What an HTTPS listener offers, best first.
///
/// Set by goalkeeper rather than left to the caller, since it is what this
/// module serves rather than a preference: hyper's `auto` builder speaks both,
/// but over TLS the choice is ALPN's to make, and a configuration offering
/// nothing gets HTTP/1.1. That would quietly cost the HTTP/2 limits below and
/// the RFC 8441 WebSocket path with them.
#[cfg(feature = "tls")]
const ALPN: [&[u8]; 2] = [H2, b"http/1.1"];

/// HTTP/2's ALPN identifier.
#[cfg(feature = "tls")]
const H2: &[u8] = b"h2";

/// The caller's [`TlsConfig`][tls::TlsConfig] with [`ALPN`] applied and, when
/// SETTINGS are sent early, half-RTT data allowed, derived once per
/// certificate.
///
/// Half-RTT data is what lets HTTP/2's SETTINGS go out with the handshake; see
/// [`tls_stream`]. Without early SETTINGS nothing needs it, so the caller's choice
/// stands.
///
/// The accept loop re-reads the configuration per connection so a renewed
/// certificate is picked up at once, but applying these means cloning a
/// `rustls::ServerConfig`, which is not something to do per connection. The
/// source is compared by pointer, so that clone happens only when the
/// certificate actually changes, and not even then if the caller had already
/// set what this would set.
#[cfg(feature = "tls")]
struct DerivedTlsConfig {
    /// Whether to allow half-RTT data.
    half_rtt: bool,
    derived: Option<(Arc<rustls::ServerConfig>, Arc<rustls::ServerConfig>)>,
}

#[cfg(feature = "tls")]
impl DerivedTlsConfig {
    fn new(half_rtt: bool) -> Self {
        Self {
            half_rtt,
            derived: None,
        }
    }

    fn get(&mut self, tls: &tls::TlsConfig) -> Arc<rustls::ServerConfig> {
        let current = tls.current();
        if let Some((source, negotiating)) = &self.derived
            && Arc::ptr_eq(source, &current)
        {
            return Arc::clone(negotiating);
        }
        let negotiating = if (!self.half_rtt || current.send_half_rtt_data)
            && current
                .alpn_protocols
                .iter()
                .map(Vec::as_slice)
                .eq(ALPN.iter().copied())
        {
            Arc::clone(&current)
        } else {
            let mut config = current.as_ref().clone();
            config.alpn_protocols = ALPN.iter().map(|protocol| protocol.to_vec()).collect();
            if self.half_rtt {
                config.send_half_rtt_data = true;
            }
            Arc::new(config)
        };
        self.derived = Some((current, Arc::clone(&negotiating)));
        negotiating
    }
}

/// Constructors for [`HttpServerBuilder`], on the handle whose budgets the
/// server will serve against.
///
/// On the trait rather than on [`Goalkeeper`][crate::Goalkeeper] because a
/// server outlives the call that built it and has to remember which instance
/// rations it.
pub trait ServeHttp: ProvideGoalkeeper {
    /// Serves `router` on `listener`, in plaintext.
    fn serve_http(&self, listener: TcpListener, router: Router) -> HttpServerBuilder<Self> {
        HttpServerBuilder {
            provider: self.clone(),
            listener,
            router,
            #[cfg(feature = "tls")]
            tls: None,
            #[cfg(feature = "tls")]
            early_settings: true,
            hyper: None,
            label: "TCP connection",
        }
    }

    /// Serves `router` on `listener`, terminating TLS.
    #[cfg(feature = "tls")]
    fn serve_https(
        &self,
        listener: TcpListener,
        tls: crate::http::tls::TlsConfig,
        router: Router,
    ) -> HttpServerBuilder<Self> {
        HttpServerBuilder {
            provider: self.clone(),
            listener,
            router,
            tls: Some(tls),
            early_settings: true,
            hyper: None,
            label: "TLS connection",
        }
    }
}

impl<P: ProvideGoalkeeper> ServeHttp for P {}

/// `Fn` rather than `FnOnce`: a builder is made per connection, since hyper's
/// carries its executor as a type parameter.
type ConfigureHyper<P> = Arc<dyn Fn(&mut auto::Builder<PrioritisedExecutor<P>>) + Send + Sync>;

/// An HTTP server that has not started yet.
///
/// Await it, or [`HttpServerBuilder::spawn`] it.
pub struct HttpServerBuilder<P: ProvideGoalkeeper = SystemGoalkeeper> {
    provider: P,
    listener: TcpListener,
    router: Router,
    #[cfg(feature = "tls")]
    tls: Option<crate::http::tls::TlsConfig>,
    #[cfg(feature = "tls")]
    early_settings: bool,
    hyper: Option<ConfigureHyper<P>>,
    label: &'static str,
}

impl<P: ProvideGoalkeeper> HttpServerBuilder<P> {
    /// Whether an HTTPS listener sends HTTP/2's SETTINGS with the TLS
    /// handshake, which it does by default.
    ///
    /// Every HTTPS connection is served before its handshake has completed.
    /// On, one that negotiated `h2` is also served HTTP/2 from the start, so
    /// hyper writes its SETTINGS before anything is read. On TLS 1.3 they then
    /// leave in the same flight as the server's `Finished`, as half-RTT data. A
    /// client that sends HTTP/1.1 regardless is refused.
    ///
    /// Off, hyper reads the client's preface to tell which protocol it speaks
    /// before writing anything, so SETTINGS follow the client's `Finished`. A
    /// client that waits for them, which every RFC 8441 WebSocket must, then
    /// pays a round trip for it. For measuring that, or for a client that
    /// cannot take them early.
    ///
    /// On also sets the [`rustls::ServerConfig`]'s `send_half_rtt_data`, for
    /// every HTTPS connection: the caller's value cannot be told from rustls'
    /// default, which is off. Only what hyper writes before it has read
    /// anything goes out as half-RTT data, which is HTTP/2's SETTINGS alone,
    /// and rustls never sends any to a configuration that authenticates
    /// clients. To keep it off regardless, turn this off.
    ///
    /// No effect on plain HTTP, which has no handshake to send them with.
    #[cfg(feature = "tls")]
    pub fn early_settings(mut self, enabled: bool) -> Self {
        self.early_settings = enabled;
        self
    }

    /// Adjusts hyper's connection builder.
    ///
    /// Goalkeeper sets the limits that are about denial of service; this is for
    /// everything else.
    ///
    /// Except which protocol a connection speaks, which is not the builder's
    /// to say: hyper detects it, or over TLS, ALPN has chosen it. `http1_only`
    /// and `http2_only` have no effect where hyper detects it, and the only
    /// effect of `http1_only` otherwise is to keep an `h2` connection from
    /// sending its SETTINGS early (see `early_settings`).
    pub fn configure_hyper<F>(mut self, configure: F) -> Self
    where
        F: Fn(&mut auto::Builder<PrioritisedExecutor<P>>) + Send + Sync + 'static,
    {
        self.hyper = Some(Arc::new(configure));
        self
    }

    /// Starts the server on the executor, returning a handle to it.
    pub fn spawn(self) -> HttpServer {
        let stop = Arc::new(Notify::new());
        let graceful = Graceful::new();
        let task = self.provider.clone().spawn(
            Priority::Accept,
            self.run(Arc::clone(&stop), Arc::clone(&graceful)),
        );
        HttpServer {
            task: Some(task),
            stop,
            graceful,
        }
    }

    async fn run(self, stop: Arc<Notify>, graceful: Arc<Graceful>) {
        let provider = self.provider.clone();
        let Self {
            provider: _,
            listener,
            router,
            #[cfg(feature = "tls")]
            tls,
            #[cfg(feature = "tls")]
            early_settings,
            hyper,
            label,
        } = self;
        let mut backoff = Duration::from_millis(1);
        // Half-RTT data only when there is something to send in it.
        #[cfg(feature = "tls")]
        let mut derived_tls = DerivedTlsConfig::new(early_settings);

        loop {
            let accepted = tokio::select! {
                accepted = listener.accept() => accepted,
                // The loop returns under its own power, never cancelled from
                // outside.
                _ = stop.notified() => break,
            };

            let (stream, peer) = match accepted {
                Ok(accepted) => {
                    backoff = Duration::from_millis(1);
                    accepted
                }
                Err(e) => {
                    // `EMFILE`, an `RST` before accept, and the like must not
                    // take the listener down.
                    warn!("accept failed: {e}");
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(ACCEPT_BACKOFF_CEILING);
                    continue;
                }
            };
            // When it arrived, not when its task got a turn, so a handshake on
            // a busy host spends its own deadline rather than somebody else's.
            #[cfg(feature = "tls")]
            let accepted_at = std::time::Instant::now();

            // Before any crypto, so a refused connection costs a socket and
            // nothing else.
            let Some(permit) = provider.connection_permit(crate::conn::canonize(peer).ip(), label)
            else {
                // Abortive close: an `RST` rather than a `FIN` handshake, so a
                // refused peer leaves no socket of ours in `TIME_WAIT`.
                let _ = stream.set_zero_linger();
                continue;
            };

            crate::tokio_net::nodelay_keepalive(&stream, KEEPALIVE.as_secs(), KEEPALIVE_RETRIES);

            let (conn, killed) = Conn::new(peer, permit);
            // What this connection is authorised to buffer, charged now rather
            // than discovered later. A refusal here is the memory ledger's
            // backstop, so the connection is dropped rather than served in a
            // state nothing has budgeted for.
            let Some(_ram) = conn.try_reserve(PER_CONNECTION) else {
                let _ = stream.set_zero_linger();
                continue;
            };
            let router = router.clone();
            let hyper = hyper.clone();
            let watcher = graceful.watcher();
            // The configuration is built here rather than in the task below, so
            // it is derived once per certificate rather than once per
            // connection. The slot is claimed here too, like the refusals
            // above, so a handshake the pool turns away costs no task: it is
            // closed rather than allowed to handshake without a slot, which
            // would leave it with no deadline and nothing able to evict it.
            #[cfg(feature = "tls")]
            let secure = match &tls {
                Some(tls) => match provider.handshake_slot(conn.ip(), accepted_at, false) {
                    Ok(slot) => Some((derived_tls.get(tls), slot)),
                    Err(handshake::Refused) => {
                        let _ = stream.set_zero_linger();
                        continue;
                    }
                },
                None => None,
            };
            let priority = conn.priority().clone();

            provider
                .spawn_with(priority.clone(), async move {
                    let _ram = _ram;
                    let io = ConnIo::new(stream, conn.clone(), killed);
                    let service = TowerToHyperService::new(WithConn {
                        inner: router,
                        conn: conn.clone(),
                    });
                    let mut builder = auto::Builder::new(PrioritisedExecutor::new(
                        conn.provider().clone(),
                        priority,
                    ));
                    harden(&mut builder);
                    if let Some(configure) = &hyper {
                        configure(&mut builder);
                    }

                    #[cfg(feature = "tls")]
                    if let Some((tls_config, mut slot)) = secure {
                        // Keepalive reaps only a dead peer, and hyper's timeouts
                        // are not written with a handshake in mind, so without a
                        // slot a peer that stalls mid-handshake holds a task
                        // indefinitely.
                        let hello = slot.hello();
                        // In two halves, split at the ClientHello. A peer that
                        // has not sent one by the time it is slow is no browser
                        // on a slow link, whereas one that sent it and then
                        // stalled may be, so the pool evicts it last. See
                        // `handshake`.
                        let accept = async {
                            let start = tokio_rustls::LazyConfigAcceptor::new(
                                rustls::server::Acceptor::default(),
                                io,
                            )
                            .await?;
                            hello.heard();
                            let tokio_rustls::StartHandshake { accepted, io, .. } = start;
                            TlsStream::start(accepted, io, tls_config).await
                        };
                        // Failed, abandoned and evicted handshakes are the
                        // common case under attack; logging each one would be
                        // the louder denial of service.
                        let (stream, handshaken) = tokio::select! {
                            started = accept => match started {
                                Ok(started) => started,
                                Err(_) => return,
                            },
                            () = slot.evicted() => return,
                        };
                        // Served before the client's `Finished`, which the
                        // connection's own reads then complete. See
                        // `tls_stream`.
                        let h2 = stream.session().alpn_protocol() == Some(H2);
                        let io = TokioIo::new(stream);
                        // Unless `configure_hyper` ruled HTTP/2 out, which hyper
                        // detecting the protocol would ignore anyway.
                        if early_settings && h2 && builder.is_http2_available() {
                            // Without waiting to read which protocol the client
                            // speaks, so hyper's SETTINGS are the first thing
                            // it writes. Not with upgrades, which would wait
                            // anyway: those are HTTP/1's, and RFC 8441's
                            // WebSockets work without them.
                            //
                            // Only if not already said, since hyper-util
                            // panics on being told twice.
                            let builder = if builder.is_http1_available() {
                                builder.http2_only()
                            } else {
                                builder
                            };
                            let served = builder.serve_connection(io, service);
                            finish_handshake(watcher.watch(served), slot, handshaken).await;
                        } else {
                            let served = builder.serve_connection_with_upgrades(io, service);
                            finish_handshake(watcher.watch(served), slot, handshaken).await;
                        }
                        return;
                    }

                    let served = builder.serve_connection_with_upgrades(TokioIo::new(io), service);
                    let _ = watcher.watch(served).await;
                })
                .detach();
        }

        // Tells every watched connection to finish: in-flight responses are
        // written and HTTP/2 peers get a `GOAWAY`. Resolves once they have.
        graceful.shutdown().await;
    }
}

/// The [`GracefulShutdown`] shared between the accept loop and its handle.
///
/// Shared because it is also the connection count, see [`HttpServer::connections`].
/// An `Option` because [`GracefulShutdown::shutdown`] consumes it.
struct Graceful(Mutex<Option<GracefulShutdown>>);

impl Graceful {
    fn new() -> Arc<Self> {
        Arc::new(Self(Mutex::new(Some(GracefulShutdown::new()))))
    }

    /// Returns a watcher for one connection.
    fn watcher(&self) -> Watcher {
        self.0
            .lock()
            .unwrap()
            .as_ref()
            .expect("watched before shutdown")
            .watcher()
    }

    /// Returns the number of connections still watched.
    fn count(&self) -> usize {
        self.0
            .lock()
            .unwrap()
            .as_ref()
            .map_or(0, GracefulShutdown::count)
    }

    /// Signals every watched connection and waits for it.
    ///
    /// Idempotent; a second call returns at once.
    async fn shutdown(&self) {
        let taken = self.0.lock().unwrap().take();
        if let Some(graceful) = taken {
            graceful.shutdown().await;
        }
    }
}

impl<P: ProvideGoalkeeper> IntoFuture for HttpServerBuilder<P> {
    type Output = ();
    type IntoFuture = Pin<Box<dyn Future<Output = ()> + Send>>;

    fn into_future(self) -> Self::IntoFuture {
        // Awaited inline rather than spawned, so it runs until the caller drops
        // the future and nothing can ask it to stop.
        Box::pin(async move { self.run(Arc::new(Notify::new()), Graceful::new()).await })
    }
}

/// What one HTTP/2 connection is allowed to buffer.
///
/// Goalkeeper chooses these, so goalkeeper charges them to the memory ledger.
const HTTP2_SEND_BUF: usize = 64 * 1024;
const HTTP2_STREAMS: u32 = 16;
const HTTP2_HEADER_LIST: u64 = 512 * 1024;

/// What a connection is charged the moment it is accepted.
///
/// The send buffers it may fill, the header list it may accumulate, and a
/// rounded allowance for the TLS session and hyper's own per-connection state.
/// An authorisation rather than a measurement; see [`crate::memory`].
pub(crate) const PER_CONNECTION: u64 =
    HTTP2_SEND_BUF as u64 * HTTP2_STREAMS as u64 + HTTP2_HEADER_LIST + 32 * 1024;

/// The HTTP/1 and HTTP/2 limits goalkeeper insists on.
fn harden<P: ProvideGoalkeeper>(builder: &mut auto::Builder<PrioritisedExecutor<P>>) {
    builder
        .http1()
        .timer(TokioTimer::new())
        .keep_alive(true)
        // Applies to every request, not just the first.
        .header_read_timeout(Duration::from_secs(5))
        .max_buf_size(32768);
    builder
        .http2()
        .timer(TokioTimer::new())
        .enable_connect_protocol()
        .keep_alive_interval(Duration::from_secs(300))
        // Impossible to respond within nothing, so the interval effectively
        // becomes an idle timeout.
        .keep_alive_timeout(Duration::ZERO)
        .max_header_list_size(HTTP2_HEADER_LIST as u32)
        .max_send_buf_size(HTTP2_SEND_BUF)
        .max_local_error_reset_streams(256)
        .max_concurrent_streams(HTTP2_STREAMS);
}

/// Serves `connection` while it finishes its TLS handshake under `slot`, and
/// then without it.
///
/// The slot covers the handshake and no further, as it would if the handshake
/// were run under [`handshake::Slot::run`]; it cannot be here, since only the
/// connection's own reads complete it.
#[cfg(feature = "tls")]
async fn finish_handshake<P: ProvideGoalkeeper, F: Future>(
    connection: F,
    mut slot: handshake::Slot<P>,
    handshaken: tokio::sync::oneshot::Receiver<()>,
) {
    let mut connection = std::pin::pin!(connection);
    tokio::select! {
        _ = &mut connection => return,
        // Or the stream was dropped, which leaves nothing to cover either.
        _ = handshaken => {}
        // Dropping the connection closes it.
        () = slot.evicted() => return,
    }
    drop(slot);
    connection.await;
}

/// A running HTTP server.
///
/// Not generic over the provider: the task, the stop signal and the shutdown
/// watch belong to no instance in particular, and the accept loop already holds
/// whichever one admitted it.
pub struct HttpServer {
    task: Option<async_task::FallibleTask<()>>,
    stop: Arc<Notify>,
    graceful: Arc<Graceful>,
}

impl HttpServer {
    /// Stops accepting, tells hyper to shut its connections down, and waits for
    /// them to finish.
    ///
    /// The accept loop ends itself rather than being cancelled, so no
    /// connection is dropped mid-response.
    pub async fn stop(&mut self) {
        // `notify_one` rather than `notify_waiters`, so the signal is not lost
        // if the loop is busy accepting rather than waiting on it.
        self.stop.notify_one();
        if let Some(task) = self.task.take() {
            task.await;
        }
    }

    /// Returns how many connections are currently being served.
    ///
    /// Read off the shutdown watch, which a connection holds for exactly as
    /// long as it is served.
    pub fn connections(&self) -> usize {
        self.graceful.count()
    }
}

/// Dropping without stopping is abrupt by design: it is the crash path, not the
/// shutdown path.
impl Drop for HttpServer {
    fn drop(&mut self) {
        // `FallibleTask`'s own `Drop` cancels.
        self.task.take();
    }
}

/// Spawns hyper's own tasks, including the HTTP/2 connection driver, at their
/// connection's priority.
///
/// The driver pumps a WebSocket's frames, so it has to move with the connection
/// it belongs to. It carries the provider for the same reason: these tasks
/// belong to the instance that accepted the connection, and spawning them on
/// the process-global schedule instead would strand them wherever nothing is
/// driving it.
#[derive(Clone, Debug)]
pub struct PrioritisedExecutor<P: ProvideGoalkeeper = SystemGoalkeeper> {
    provider: P,
    priority: SharedPriority,
}

impl<P: ProvideGoalkeeper> PrioritisedExecutor<P> {
    /// Creates an executor that spawns on `provider` at `priority`, moving with
    /// it.
    pub fn new(provider: P, priority: SharedPriority) -> Self {
        Self { provider, priority }
    }
}

impl<P: ProvideGoalkeeper, F> hyper::rt::Executor<F> for PrioritisedExecutor<P>
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    fn execute(&self, future: F) {
        self.provider
            .clone()
            .spawn_with(self.priority.clone(), async move {
                future.await;
            })
            .detach();
    }
}

/// Supplies the per-connection request extension.
///
/// One insert rather than three, so a handler wanting the peer address, the
/// kill switch and the priority does a single lookup.
#[derive(Clone)]
struct WithConn<S, P: ProvideGoalkeeper> {
    inner: S,
    conn: Conn<P>,
}

impl<S, B, P: ProvideGoalkeeper> tower::Service<axum::http::Request<B>> for WithConn<S, P>
where
    S: tower::Service<axum::http::Request<B>>,
{
    type Error = S::Error;
    type Future = S::Future;
    type Response = S::Response;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut request: axum::http::Request<B>) -> Self::Future {
        request.extensions_mut().insert(self.conn.clone());
        self.inner.call(request)
    }
}
