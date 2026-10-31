//! A server TLS stream that is served before its handshake is over.
//!
//! RFC 8441 forbids a client from opening a WebSocket over HTTP/2 until it has
//! seen `SETTINGS_ENABLE_CONNECT_PROTOCOL` in the server's SETTINGS, and some
//! clients wait for those SETTINGS before sending anything at all. TLS 1.3 lets
//! the server send application data straight after its own `Finished`, in the
//! same flight ("half-RTT data"), so they can reach the client a round trip
//! sooner than if they waited on the client's `Finished`.
//!
//! `tokio-rustls` cannot send any: its stream exists only once the handshake
//! has completed, which for a server means once the client's `Finished` has
//! arrived, and that is exactly when half-RTT is over. A [`TlsStream`] is
//! handed to hyper as soon as the ClientHello has been answered instead, and
//! reading from it finishes the handshake. What hyper writes before then goes
//! out as half-RTT data where rustls allows it. Where it does not (TLS 1.2, or
//! a configuration that authenticates clients), rustls holds it until the
//! handshake completes, which is no later than it would have been sent anyway.
//!
//! Half-RTT data reaches a client that has not yet proven it completed the
//! handshake. That is harmless here: nothing authenticates clients, rustls
//! refuses half-RTT data when something does, and until hyper has read a
//! request, which completes the handshake first, all it can write is its
//! SETTINGS, which are the same for every client.

use rustls::ServerConfig;
use rustls::ServerConnection;
use rustls::server::{Accepted, AcceptedAlert};
use std::future::poll_fn;
use std::io::{self, BufRead, IoSlice, Read, Write};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::oneshot;

/// A server TLS connection over `IO`, usable mid-handshake.
pub(super) struct TlsStream<IO> {
    io: IO,
    session: ServerConnection,
    /// Fired, and taken, once the handshake completes.
    handshaken: Option<oneshot::Sender<()>>,
    /// Whether reading sends too, which it does only until the handshake is
    /// over and all it queued has gone. After that, sending is writing's
    /// alone: a transport keeps one waker for writing, and a reader on another
    /// task, as an upgraded connection split in two has, would take the
    /// writer's.
    reads_send: bool,
    /// The peer has closed its half of the transport.
    eof: bool,
    /// `close_notify` has been queued.
    closed: bool,
}

impl<IO: AsyncRead + AsyncWrite + Unpin> TlsStream<IO> {
    /// Answers `accepted`'s ClientHello with `config`, returning the stream
    /// and what resolves once its handshake has completed.
    ///
    /// Nothing is sent yet: the server's flight leaves with whatever is first
    /// written or read, and for HTTP/2 that is SETTINGS, which it then carries.
    pub(super) async fn start(
        accepted: Accepted,
        mut io: IO,
        config: Arc<ServerConfig>,
    ) -> io::Result<(Self, oneshot::Receiver<()>)> {
        match accepted.into_connection(config) {
            Ok(session) => {
                let (handshaken, receiver) = oneshot::channel();
                let stream = Self {
                    io,
                    session,
                    handshaken: Some(handshaken),
                    reads_send: true,
                    eof: false,
                    closed: false,
                };
                Ok((stream, receiver))
            }
            Err((error, alert)) => {
                send_alert(&mut io, alert).await;
                Err(io::Error::new(io::ErrorKind::InvalidData, error))
            }
        }
    }

    pub(super) fn session(&self) -> &ServerConnection {
        &self.session
    }

    /// Writes out what rustls has queued. Pending until all of it has gone.
    fn poll_send(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.session.wants_write() {
            let mut writer = SyncWriter {
                io: &mut self.io,
                cx,
            };
            match self.session.write_tls(&mut writer) {
                Ok(0) => return Poll::Ready(Err(io::ErrorKind::WriteZero.into())),
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Poll::Pending,
                Err(e) => return Poll::Ready(Err(e)),
            }
        }
        Poll::Ready(Ok(()))
    }

    /// Reads and processes what the peer has sent, until rustls has plaintext
    /// or the end of the stream to hand out. Pending while the transport
    /// stands in the way, whether of reading or of sending, and then it is the
    /// transport's to wake.
    ///
    /// Sends as it goes, for as long as the handshake needs it to (see
    /// `reads_send`). Until it may send application data, rustls reads nothing
    /// more while it has anything queued, so the server's flight has to go
    /// before the client's `Finished` can be read. Completing the handshake
    /// queues more: session tickets, a TLS 1.2 `Finished`, plaintext the
    /// handshake was holding back. Some of that the client waits on, and
    /// hyper, having written it, will not write again until it hears back.
    ///
    /// The one place the handshake progresses, so the one place it completes.
    fn poll_receive(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            let sent = if self.reads_send {
                let sent = self.poll_send(cx)?;
                if sent.is_ready() && !self.session.is_handshaking() {
                    self.reads_send = false;
                }
                sent
            } else {
                Poll::Ready(())
            };
            if self.eof || !self.session.wants_read() {
                if self.eof && self.session.is_handshaking() {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "TLS handshake eof",
                    )));
                }
                // Either way there is something to hand out, unless what
                // rustls wants first is to send, which the transport will
                // wake us for.
                return sent.map(Ok);
            }
            let mut reader = SyncReader {
                io: &mut self.io,
                cx,
            };
            match self.session.read_tls(&mut reader) {
                Ok(0) => self.eof = true,
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Poll::Pending,
                Err(e) => return Poll::Ready(Err(e)),
            }
            if let Err(error) = self.session.process_new_packets() {
                // The alert describing it, as a last gasp.
                let _ = self.poll_send(cx);
                return Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData, error)));
            }
            if !self.session.is_handshaking()
                && let Some(handshaken) = self.handshaken.take()
            {
                let _ = handshaken.send(());
            }
        }
    }

    /// A write, `write` being how rustls takes the plaintext.
    fn poll_write_with(
        &mut self,
        cx: &mut Context<'_>,
        mut write: impl FnMut(&mut rustls::Writer<'_>) -> io::Result<usize>,
    ) -> Poll<io::Result<usize>> {
        loop {
            let taken = write(&mut self.session.writer())?;
            let queued = self.session.wants_write();
            match self.poll_send(cx) {
                // Taken is as good as written, since rustls bounds what it
                // buffers. A transport that failed fails the next call too,
                // so it waits for that rather than hide that these were taken.
                _ if taken > 0 => return Poll::Ready(Ok(taken)),
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
                // Refused because rustls' buffer was full, and that has just
                // gone out, so there is room now.
                Poll::Ready(Ok(())) if queued => continue,
                Poll::Ready(Ok(())) => {}
            }
            // Refused with nothing queued to send: the plaintext rustls holds
            // back for the handshake has filled its buffer, and only the rest
            // of the handshake frees it. Past the handshake nothing else
            // refuses a write with room to spare, short of a buffer limit of
            // nothing, which no amount of waiting would get past.
            if !self.session.is_handshaking() {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            let received = self.poll_receive(cx)?;
            match (received, self.session.is_handshaking()) {
                (Poll::Pending, true) => return Poll::Pending,
                // Received all there will be, and still not done.
                (Poll::Ready(()), true) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "TLS handshake ended unfinished",
                    )));
                }
                // Done, even if nothing more is coming: what rustls held back
                // has been released, so there is room again. Waiting on the
                // read instead would wait on a peer that is waiting on us.
                (_, false) => {}
            }
        }
    }
}

impl<IO: AsyncRead + AsyncWrite + Unpin> AsyncRead for TlsStream<IO> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let received = this.poll_receive(cx)?;
        let taken = match this.session.reader().into_first_chunk() {
            Ok(chunk) => {
                let taken = chunk.len().min(buf.remaining());
                buf.put_slice(&chunk[..taken]);
                taken
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                // Ready means rustls had something to hand out, so this should
                // not happen. If it does, the transport is not going to wake
                // us, so try again rather than wait on nothing.
                if received.is_ready() {
                    cx.waker().wake_by_ref();
                }
                return Poll::Pending;
            }
            Err(e) => return Poll::Ready(Err(e)),
        };
        this.session.reader().consume(taken);
        Poll::Ready(Ok(()))
    }
}

impl<IO: AsyncRead + AsyncWrite + Unpin> AsyncWrite for TlsStream<IO> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        self.get_mut()
            .poll_write_with(cx, |writer| writer.write(buf))
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        if bufs.iter().all(|buf| buf.is_empty()) {
            return Poll::Ready(Ok(0));
        }
        self.get_mut()
            .poll_write_with(cx, |writer| writer.write_vectored(bufs))
    }

    fn is_write_vectored(&self) -> bool {
        true
    }

    /// Mid-handshake, plaintext rustls is holding back stays held: it goes
    /// once the handshake completes, which only reading can bring about.
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.session.writer().flush()?;
        ready!(this.poll_send(cx))?;
        Pin::new(&mut this.io).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.closed {
            this.session.send_close_notify();
            this.closed = true;
        }
        ready!(this.poll_send(cx))?;
        match ready!(Pin::new(&mut this.io).poll_shutdown(cx)) {
            // Not connected is as shut down as it gets.
            Err(e) if e.kind() == io::ErrorKind::NotConnected => Poll::Ready(Ok(())),
            result => Poll::Ready(result),
        }
    }
}

/// Sends the alert rustls composed for a ClientHello it could not answer,
/// as far as the transport will take it.
async fn send_alert<IO: AsyncWrite + Unpin>(io: &mut IO, mut alert: AcceptedAlert) {
    poll_fn(|cx| {
        loop {
            let mut writer = SyncWriter { io: &mut *io, cx };
            match alert.write(&mut writer) {
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Poll::Pending,
                Ok(0) | Err(_) => return Poll::Ready(()),
                Ok(_) => {}
            }
        }
    })
    .await;
}

/// The transport as rustls reads it: pending is `WouldBlock`.
struct SyncReader<'a, 'b, IO> {
    io: &'a mut IO,
    cx: &'a mut Context<'b>,
}

impl<IO: AsyncRead + Unpin> Read for SyncReader<'_, '_, IO> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut buf = ReadBuf::new(buf);
        match Pin::new(&mut *self.io).poll_read(self.cx, &mut buf) {
            Poll::Ready(Ok(())) => Ok(buf.filled().len()),
            Poll::Ready(Err(e)) => Err(e),
            Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
        }
    }
}

/// The transport as rustls writes it: pending is `WouldBlock`.
///
/// Vectored, since rustls writes its records that way, and so does whatever
/// paces the transport.
struct SyncWriter<'a, 'b, IO> {
    io: &'a mut IO,
    cx: &'a mut Context<'b>,
}

impl<IO: AsyncWrite + Unpin> Write for SyncWriter<'_, '_, IO> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match Pin::new(&mut *self.io).poll_write(self.cx, buf) {
            Poll::Ready(result) => result,
            Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
        }
    }

    fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        match Pin::new(&mut *self.io).poll_write_vectored(self.cx, bufs) {
            Poll::Ready(result) => result,
            Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
        }
    }

    /// Nothing: the stream flushes the transport itself, in `poll_flush`.
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Wake, Waker};

    /// A transport that is never ready, as one held back by its bandwidth
    /// allowance is.
    struct Stalled;

    impl AsyncRead for Stalled {
        fn poll_read(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }

    impl AsyncWrite for Stalled {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Pending
        }

        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// Counts its wakes.
    #[derive(Default)]
    struct Wakes(AtomicUsize);

    impl Wake for Wakes {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref();
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// A server for `localhost`, and a client that trusts it.
    fn configs(half_rtt: bool) -> (Arc<ServerConfig>, Arc<rustls::ClientConfig>) {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let identity = wtransport::Identity::self_signed(["localhost"]).unwrap();
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
        let mut server = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .unwrap();
        server.send_half_rtt_data = half_rtt;
        let client = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        (Arc::new(server), Arc::new(client))
    }

    /// A server that has answered a real ClientHello over [`Stalled`], so its
    /// flight is queued and none of it can be sent.
    async fn stalled_mid_handshake(half_rtt: bool) -> TlsStream<Stalled> {
        let (server, client) = configs(half_rtt);
        let mut client =
            rustls::ClientConnection::new(client, "localhost".try_into().unwrap()).unwrap();
        let mut hello = Vec::new();
        client.write_tls(&mut hello).unwrap();
        let mut acceptor = rustls::server::Acceptor::default();
        acceptor.read_tls(&mut &hello[..]).unwrap();
        let accepted = match acceptor.accept() {
            Ok(Some(accepted)) => accepted,
            _ => panic!("the ClientHello was not accepted"),
        };
        let (stream, _) = TlsStream::start(accepted, Stalled, server).await.unwrap();
        stream
    }

    /// A transport that refuses writes while its gate is shut, as a full
    /// socket does, and wakes the writer when it opens.
    struct Gated {
        inner: tokio::io::DuplexStream,
        gate: Arc<Gate>,
    }

    #[derive(Default)]
    struct Gate {
        shut: std::sync::atomic::AtomicBool,
        waker: std::sync::Mutex<Option<Waker>>,
    }

    impl Gate {
        fn open(&self) {
            self.shut.store(false, Ordering::Relaxed);
            if let Some(waker) = self.waker.lock().unwrap().take() {
                waker.wake();
            }
        }
    }

    impl AsyncRead for Gated {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for Gated {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let this = self.get_mut();
            if this.gate.shut.load(Ordering::Relaxed) {
                *this.gate.waker.lock().unwrap() = Some(cx.waker().clone());
                return Poll::Pending;
            }
            Pin::new(&mut this.inner).poll_write(cx, buf)
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_flush(cx)
        }

        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
        }
    }

    /// When the transport takes writes again, rustls' buffer can drain in one
    /// go, leaving a write that took nothing with nothing left to send. That
    /// is room to retry in, not plaintext held back for a handshake that only
    /// a read can finish: waiting on a read stalls the write until the peer
    /// happens to send something, which a client downloading never does.
    ///
    /// Written without flushing between writes, as an upgraded WebSocket
    /// writes; hyper's own flushes happen to drain the buffer first.
    #[tokio::test]
    async fn a_write_retries_once_the_transport_drains() {
        const LENGTH: usize = 1024 * 1024;
        let (server_config, client_config) = configs(true);
        // Room for everything once open, so the buffer drains whole.
        let (server_io, client_io) = tokio::io::duplex(4 * LENGTH);
        let gate = Arc::new(Gate::default());
        let server_io = Gated {
            inner: server_io,
            gate: Arc::clone(&gate),
        };

        let client = tokio::spawn(async move {
            let connector = tokio_rustls::TlsConnector::from(client_config);
            let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
            connector.connect(name, client_io).await.unwrap()
        });
        let start =
            tokio_rustls::LazyConfigAcceptor::new(rustls::server::Acceptor::default(), server_io)
                .await
                .unwrap();
        let (mut server, handshaken) = TlsStream::start(start.accepted, start.io, server_config)
            .await
            .unwrap();
        // Only reading completes the handshake, and the client sends nothing
        // after it, so the read stays pending.
        let mut byte = [0; 1];
        tokio::select! {
            handshaken = handshaken => handshaken.unwrap(),
            _ = tokio::io::AsyncReadExt::read(&mut server, &mut byte) => panic!("read data"),
        }
        let _client = client.await.unwrap();

        gate.shut.store(true, Ordering::Relaxed);
        let writer = tokio::spawn(async move {
            tokio::io::AsyncWriteExt::write_all(&mut server, &vec![0; LENGTH]).await
        });
        // Until rustls' buffer is full and the write is waiting on the gate.
        while gate.waker.lock().unwrap().is_none() {
            tokio::task::yield_now().await;
        }
        gate.open();
        tokio::time::timeout(std::time::Duration::from_secs(5), writer)
            .await
            .expect("the write stalled once the transport drained")
            .unwrap()
            .unwrap();
    }

    /// An upgraded connection split into a reader and a writer on tasks of
    /// their own: the reader must not send, since a transport keeps one
    /// waker for writing, and the reader's would take the place of the
    /// writer's, leaving the writer parked when the transport takes writes
    /// again.
    #[tokio::test]
    async fn a_reader_does_not_take_the_writers_wakeup() {
        const LENGTH: usize = 1024 * 1024;
        let (server_config, client_config) = configs(true);
        let (server_io, client_io) = tokio::io::duplex(4 * LENGTH);
        let gate = Arc::new(Gate::default());
        let server_io = Gated {
            inner: server_io,
            gate: Arc::clone(&gate),
        };

        let client = tokio::spawn(async move {
            let connector = tokio_rustls::TlsConnector::from(client_config);
            let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
            connector.connect(name, client_io).await.unwrap()
        });
        let start =
            tokio_rustls::LazyConfigAcceptor::new(rustls::server::Acceptor::default(), server_io)
                .await
                .unwrap();
        let (mut server, handshaken) = TlsStream::start(start.accepted, start.io, server_config)
            .await
            .unwrap();
        let mut byte = [0; 1];
        tokio::select! {
            handshaken = handshaken => handshaken.unwrap(),
            _ = tokio::io::AsyncReadExt::read(&mut server, &mut byte) => panic!("read data"),
        }
        let _client = client.await.unwrap();

        let (mut reader, mut writer) = tokio::io::split(server);
        gate.shut.store(true, Ordering::Relaxed);
        let writing = tokio::spawn(async move {
            tokio::io::AsyncWriteExt::write_all(&mut writer, &vec![0; LENGTH]).await
        });
        while gate.waker.lock().unwrap().is_none() {
            tokio::task::yield_now().await;
        }
        // Parked on a read the client will never satisfy, having been polled
        // while rustls had the writer's records queued.
        let reading = tokio::spawn(async move {
            let mut byte = [0; 1];
            let _ = tokio::io::AsyncReadExt::read(&mut reader, &mut byte).await;
        });
        for _ in 0..16 {
            tokio::task::yield_now().await;
        }
        gate.open();
        tokio::time::timeout(std::time::Duration::from_secs(5), writing)
            .await
            .expect("the writer was never woken")
            .unwrap()
            .unwrap();
        reading.abort();
    }

    /// Without half-RTT data, rustls holds back what is written mid-handshake,
    /// and refuses more once it holds a buffer's worth. The write then waits
    /// on the handshake, and must go on once that completes, rather than wait
    /// on a read the client, waiting on the response, has no reason to send.
    #[tokio::test]
    async fn a_write_held_back_by_the_handshake_resumes_when_it_completes() {
        const LENGTH: usize = 256 * 1024;
        let (server_config, client_config) = configs(false);
        let (server_io, client_io) = tokio::io::duplex(4 * LENGTH);

        let client = tokio::spawn(async move {
            let connector = tokio_rustls::TlsConnector::from(client_config);
            let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
            let mut stream = connector.connect(name, client_io).await.unwrap();
            let mut received = vec![0; LENGTH];
            tokio::io::AsyncReadExt::read_exact(&mut stream, &mut received)
                .await
                .unwrap();
        });
        let start =
            tokio_rustls::LazyConfigAcceptor::new(rustls::server::Acceptor::default(), server_io)
                .await
                .unwrap();
        let (mut server, _) = TlsStream::start(start.accepted, start.io, server_config)
            .await
            .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            tokio::io::AsyncWriteExt::write_all(&mut server, &vec![0; LENGTH])
                .await
                .unwrap();
            tokio::io::AsyncWriteExt::flush(&mut server).await.unwrap();
            client.await.unwrap();
        })
        .await
        .expect("the write stalled once the handshake completed");
    }

    /// Without half-RTT data, rustls reads nothing more until its flight is
    /// out. A transport that cannot take it yet will wake the stream when it
    /// can, so the stream must wait for that rather than wake itself, which
    /// would spin a core for as long as the transport is held back.
    #[tokio::test]
    async fn a_read_waits_on_a_stalled_send() {
        for half_rtt in [false, true] {
            let mut stream = stalled_mid_handshake(half_rtt).await;
            let wakes = Arc::new(Wakes::default());
            let waker = Waker::from(Arc::clone(&wakes));
            let mut cx = Context::from_waker(&waker);
            let mut buf = [0; 16];
            let mut buf = ReadBuf::new(&mut buf);
            assert!(
                Pin::new(&mut stream)
                    .poll_read(&mut cx, &mut buf)
                    .is_pending()
            );
            assert_eq!(
                wakes.0.load(Ordering::Relaxed),
                0,
                "woke itself with nothing it could do (half-RTT {half_rtt})"
            );
        }
    }
}
