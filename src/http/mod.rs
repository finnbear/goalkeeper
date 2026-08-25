//! Serving HTTP and HTTPS with everything else already wired in.
//!
//! Accept, admit, handshake, serve, ordered so the cheapest refusals happen
//! first: the per-address limiter admits a connection before any crypto, and
//! the handshake then takes a slot from [`crate::resource::handshake`], giving
//! it up as soon as it resolves.
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
#[cfg(feature = "web_socket")]
pub mod web_socket;

use crate::conn::{Conn, ConnIo};

#[cfg(feature = "tls")]
use crate::resource::handshake;
use crate::{ProvideGoalkeeper, SystemGoalkeeper};

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
const ALPN: [&[u8]; 2] = [b"h2", b"http/1.1"];

/// The caller's [`TlsConfig`][tls::TlsConfig] with [`ALPN`] applied, derived
/// once per certificate.
///
/// The accept loop re-reads the configuration per connection so a renewed
/// certificate is picked up at once, but applying the ALPN means cloning a
/// `rustls::ServerConfig`, which is not something to do per connection. The
/// source is compared by pointer, so that clone happens only when the
/// certificate actually changes, and not even then if the caller had already
/// set what this would set.
#[cfg(feature = "tls")]
#[derive(Default)]
struct Alpn(Option<(Arc<rustls::ServerConfig>, Arc<rustls::ServerConfig>)>);

#[cfg(feature = "tls")]
impl Alpn {
    fn negotiating(&mut self, tls: &tls::TlsConfig) -> Arc<rustls::ServerConfig> {
        let current = tls.current();
        if let Some((source, negotiating)) = &self.0
            && Arc::ptr_eq(source, &current)
        {
            return Arc::clone(negotiating);
        }
        let negotiating = if current
            .alpn_protocols
            .iter()
            .map(Vec::as_slice)
            .eq(ALPN.iter().copied())
        {
            Arc::clone(&current)
        } else {
            let mut config = current.as_ref().clone();
            config.alpn_protocols = ALPN.iter().map(|protocol| protocol.to_vec()).collect();
            Arc::new(config)
        };
        self.0 = Some((current, Arc::clone(&negotiating)));
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
    hyper: Option<ConfigureHyper<P>>,
    label: &'static str,
}

impl<P: ProvideGoalkeeper> HttpServerBuilder<P> {
    /// Adjusts hyper's connection builder.
    ///
    /// Goalkeeper sets the limits that are about denial of service; this is for
    /// everything else.
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
            hyper,
            label,
        } = self;
        let mut backoff = Duration::from_millis(1);
        #[cfg(feature = "tls")]
        let mut alpn = Alpn::default();

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
            // Built here rather than in the task below, so the configuration is
            // derived once per certificate rather than once per connection.
            #[cfg(feature = "tls")]
            let acceptor = tls
                .as_ref()
                .map(|tls| tokio_rustls::TlsAcceptor::from(alpn.negotiating(tls)));
            let priority = conn.priority().clone();
            // Moved into the task, so a handshake takes its slot from the same
            // instance that admitted the connection.
            #[cfg(feature = "tls")]
            let handshake_provider = provider.clone();

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
                    if let Some(acceptor) = acceptor {
                        // Keepalive reaps only a dead peer, and hyper's header
                        // read timeout starts once TLS is up, so without a slot
                        // a peer that stalls mid-handshake holds a task
                        // indefinitely.
                        let slot = handshake_provider.handshake_slot(conn.ip(), accepted_at);
                        #[allow(
                            clippy::single_match,
                            reason = "the empty arm is where the reasoning lives"
                        )]
                        match handshake::bounded(slot, acceptor.accept(io)).await {
                            Some(Ok(stream)) => {
                                let served = builder
                                    .serve_connection_with_upgrades(TokioIo::new(stream), service);
                                let _ = watcher.watch(served).await;
                            }
                            // Failed, abandoned and evicted handshakes are the
                            // common case under attack; logging each one would
                            // be the louder denial of service.
                            Some(Err(_)) | None => {}
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

/// A running HTTP server.
///
/// Not generic over the provider: the task, the stop signal and the shutdown
/// watch belong to no instance in particular, and the accept loop already holds
/// whichever one admitted it.
pub struct HttpServer {
    task: Option<async_task::Task<()>>,
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
        // `Task`'s own `Drop` cancels.
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
