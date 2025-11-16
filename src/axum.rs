//! `axum` + `axum_server` DoS mitigation utilities.

use crate::tokio_net::nodelay_keepalive;

use super::ip_limiter::ConnectionPermit;
use axum::extract::Request;
use axum_server::accept::Accept;
use std::future::Future;
use std::io::{self, ErrorKind};
use std::marker::PhantomData;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tower::Service;

/// Wraps an `axum_server` acceptor for configuring TCP keepalive and installing a [TcpStream]
/// kill switch that can be activated from an [axum::Router].
#[derive(Clone, Copy, Debug, Default)]
pub struct AxumServerAcceptor<S, I>(I, PhantomData<S>);

impl<S, I> AxumServerAcceptor<S, I> {
    /// Wrap an `axum_server` acceptor.
    pub fn new(inner: I) -> Self {
        Self(inner, PhantomData)
    }
}

/// A combinator that polls a future or immediately results in a value.
#[pin_project::pin_project(project = FutureOrImmediateProj)]
pub enum FutureOrImmediate<F: Future> {
    /// Poll this future.
    Future(#[pin] F),
    /// Poll will take this value.
    Immediate(Option<F::Output>),
}

impl<F: Future> Future for FutureOrImmediate<F> {
    type Output = F::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        match this {
            FutureOrImmediateProj::Future(future) => future.poll(cx),
            FutureOrImmediateProj::Immediate(immediate) => Poll::Ready(
                immediate
                    .take()
                    .expect("FutureOrImmediate polled after returned immediate"),
            ),
        }
    }
}

impl<S, I: Accept<KillSwitchStream<TcpStream>, AddExtension<S, KillSwitch>>>
    axum_server::accept::Accept<TcpStream, S> for AxumServerAcceptor<S, I>
{
    type Future = FutureOrImmediate<I::Future>;
    type Service = <I as Accept<KillSwitchStream<TcpStream>, AddExtension<S, KillSwitch>>>::Service;
    type Stream = <I as Accept<KillSwitchStream<TcpStream>, AddExtension<S, KillSwitch>>>::Stream;

    fn accept(&self, stream: TcpStream, service: S) -> FutureOrImmediate<I::Future> {
        let Some(_permit) = stream
            .peer_addr()
            .ok()
            .map(|s| s.ip())
            .and_then(|ip| ConnectionPermit::new(ip, "TCP connection"))
        else {
            return FutureOrImmediate::Immediate(Some(Err(io::Error::from(
                ErrorKind::ConnectionRefused,
            ))));
        };

        nodelay_keepalive(&stream, 10, 2);

        let (kill, killed) = mpsc::channel::<()>(1);

        FutureOrImmediate::Future(self.0.accept(
            KillSwitchStream {
                stream,
                killed,
                _permit,
            },
            AddExtension {
                service,
                value: KillSwitch { kill },
            },
        ))
    }
}

/// An extension allowing the underlying TCP stream to be terminated, i.e.
/// based on abusive requests or delays.
#[derive(Clone)]
pub struct KillSwitch {
    kill: mpsc::Sender<()>,
}

impl KillSwitch {
    /// Pwn the TCP stream before it pwns the server.
    pub fn kill(&self) {
        let _ = self.kill.try_send(());
    }
}

/// A wrapper that adds an extension to an axum tower service.
// TODO: get Axum to make this public.
#[derive(Clone)]
pub struct AddExtension<S, T> {
    pub(crate) service: S,
    pub(crate) value: T,
}

impl<ResBody, S, T> Service<Request<ResBody>> for AddExtension<S, T>
where
    S: Service<Request<ResBody>>,
    T: Clone + Send + Sync + 'static,
{
    type Error = S::Error;
    type Future = S::Future;
    type Response = S::Response;

    #[inline]
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<ResBody>) -> Self::Future {
        req.extensions_mut().insert(self.value.clone());
        self.service.call(req)
    }
}

/// A stream that may be killed via a channel.
#[pin_project::pin_project]
pub struct KillSwitchStream<S> {
    #[pin]
    stream: S,
    #[pin]
    killed: mpsc::Receiver<()>,
    _permit: ConnectionPermit,
}

#[inline(always)]
/// Only call on the read side (it should be sufficient to prevent DoS).
fn check_killed(mut killed: Pin<&mut mpsc::Receiver<()>>, cx: &mut Context<'_>) -> io::Result<()> {
    if !killed.is_closed() && matches!(killed.poll_recv(cx), Poll::Ready(Some(_))) {
        //warn!("forcibly killing a connection");
        Err(io::Error::from(io::ErrorKind::ConnectionAborted))
    } else {
        Ok(())
    }
}

impl<S: AsyncRead> AsyncRead for KillSwitchStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.project();
        check_killed(this.killed, cx)?;
        this.stream.poll_read(cx, buf)
    }
}

impl<S: AsyncWrite> AsyncWrite for KillSwitchStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.project();
        //check_killed(this.killed, cx)?;
        this.stream.poll_write(cx, buf)
    }

    fn is_write_vectored(&self) -> bool {
        self.stream.is_write_vectored()
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.project();
        //check_killed(this.killed, cx)?;
        this.stream.poll_write_vectored(cx, bufs)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.project();
        //check_killed(this.killed, cx)?;
        this.stream.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.project().stream.poll_shutdown(cx)
    }
}
