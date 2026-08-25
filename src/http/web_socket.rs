//! A WebSocket extractor that keeps its connection's scheduling honest.
//!
//! [`WebSocketUpgrade::on_upgrade`] joins the socket task to the connection's
//! [`SharedPriority`][crate::executor::priority::SharedPriority] and hands back
//! a [`GovernedSocket`], whose boost lifts the whole connection for as long as
//! it is held. Over HTTP/2 the socket is a stream inside a longer-lived
//! connection (RFC 8441), so hyper's driver must be raised with it.

use crate::conn::Conn;
use crate::executor::priority::Priority;
use crate::resource::ip_limiter::ActiveSession;
use crate::{ProvideGoalkeeper, SystemGoalkeeper};
use axum::extract::FromRequestParts;
use axum::http::StatusCode;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

pub use axum_tws::{CloseCode, Limits, Message, WebSocket, WebSocketError};

/// An offered WebSocket upgrade, with the connection it arrived on.
pub struct WebSocketUpgrade<P: ProvideGoalkeeper = SystemGoalkeeper> {
    inner: axum_tws::WebSocketUpgrade,
    conn: Conn<P>,
}

/// Why an upgrade could not be extracted.
pub enum UpgradeError {
    /// The request was not a WebSocket upgrade.
    NotAnUpgrade(WebSocketError),
    /// The request did not arrive through [`crate::http`], so there is no
    /// connection to attach the socket to.
    NoConnection,
}

impl IntoResponse for UpgradeError {
    fn into_response(self) -> Response {
        match self {
            Self::NotAnUpgrade(rejection) => rejection.into_response(),
            Self::NoConnection => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "not served by goalkeeper",
            )
                .into_response(),
        }
    }
}

impl<S: Send + Sync, P: ProvideGoalkeeper> FromRequestParts<S> for WebSocketUpgrade<P> {
    type Rejection = UpgradeError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        // Taken before the upgrade, which consumes the parts' extensions in
        // some axum versions.
        let conn = parts
            .extensions
            .get::<Conn<P>>()
            .cloned()
            .ok_or(UpgradeError::NoConnection)?;
        let inner = axum_tws::WebSocketUpgrade::from_request_parts(parts, state)
            .await
            .map_err(UpgradeError::NotAnUpgrade)?;
        Ok(Self { inner, conn })
    }
}

impl<P: ProvideGoalkeeper> WebSocketUpgrade<P> {
    /// Bounds what a peer may send in one message.
    pub fn limits(mut self, limits: Limits) -> Self {
        self.inner = self.inner.limits(limits);
        self
    }

    /// Returns the connection this upgrade arrived on.
    pub fn conn(&self) -> &Conn<P> {
        &self.conn
    }

    /// Completes the upgrade, running `callback` at `priority`.
    ///
    /// The socket task joins the connection's priority handle, so everything
    /// serving that connection is held at `priority` for as long as the
    /// [`GovernedSocket`] lives.
    ///
    /// Takes an [`ActiveSession`] for the peer's address, widening that
    /// address's bandwidth allowance. Taken at the upgrade rather than at
    /// accept, so an address cannot mint headroom with offers it never
    /// completes.
    pub fn on_upgrade<F, Fut>(self, priority: Priority, callback: F) -> Response
    where
        F: FnOnce(GovernedSocket<P>) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let Self { inner, conn } = self;
        let shared = conn.priority().clone();
        // `axum_tws` would otherwise `tokio::spawn` this, leaving the socket
        // the one task in the process outside the schedule.
        let executor =
            crate::http::PrioritisedExecutor::new(conn.provider().clone(), shared.clone());
        inner.on_upgrade_with(executor, move |socket| {
            callback(GovernedSocket {
                socket,
                _boost: shared.boost(priority),
                _active: conn.provider().clone().active_session(conn.ip()),
                conn,
            })
        })
    }
}

/// An upgraded WebSocket, governed for as long as it is held.
///
/// Used exactly like the [`WebSocket`] it derefs to. Dropping it returns the
/// connection to being a stranger and gives back the address's extra bandwidth
/// allowance, so hold it for the whole session.
pub struct GovernedSocket<P: ProvideGoalkeeper = SystemGoalkeeper> {
    socket: WebSocket,
    conn: Conn<P>,
    _boost: crate::executor::priority::Boost,
    _active: ActiveSession<P>,
}

impl<P: ProvideGoalkeeper> GovernedSocket<P> {
    /// Returns the connection this socket runs on, for re-levelling it as the
    /// peer becomes more or less established.
    pub fn conn(&self) -> &Conn<P> {
        &self.conn
    }

    /// The bare socket, giving up the boost and the active session.
    pub fn into_inner(self) -> WebSocket {
        self.socket
    }
}

impl<P: ProvideGoalkeeper> std::ops::Deref for GovernedSocket<P> {
    type Target = WebSocket;

    fn deref(&self) -> &Self::Target {
        &self.socket
    }
}

impl<P: ProvideGoalkeeper> std::ops::DerefMut for GovernedSocket<P> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.socket
    }
}

// `WebSocket` is driven through these as often as through its inherent methods,
// and `Deref` forwards only the latter.
impl<P: ProvideGoalkeeper> futures_core::Stream for GovernedSocket<P> {
    type Item = Result<Message, WebSocketError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.get_mut().socket).poll_next(cx)
    }
}

impl<P: ProvideGoalkeeper> futures_sink::Sink<Message> for GovernedSocket<P> {
    type Error = WebSocketError;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.get_mut().socket).poll_ready(cx)
    }

    fn start_send(self: Pin<&mut Self>, item: Message) -> Result<(), Self::Error> {
        Pin::new(&mut self.get_mut().socket).start_send(item)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.get_mut().socket).poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.get_mut().socket).poll_close(cx)
    }
}
