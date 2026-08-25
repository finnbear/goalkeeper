//! Per-connection state, in one allocation.
//!
//! A [`Conn`] carries four things: the permit that says the connection may
//! exist, the priority its tasks run at, the switch that destroys it, and the
//! bytes it has moved. Together, so a request handler does one extension lookup
//! instead of three and [`ConnIo`] does the kill check, the bandwidth gate and
//! the byte count against a single cache line.

use crate::executor::priority::{Boost, Priority, SharedPriority};
use crate::resource::bandwidth::{self, Direction};
use crate::resource::ip_limiter::ConnectionPermit;
use crate::{ProvideGoalkeeper, SystemGoalkeeper};
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::pin::Pin;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::oneshot;

/// Bytes a connection may move before it settles up with the ledger.
///
/// The locks are taken once per this many bytes rather than once per read, and
/// the verdict is cached for the same span, so this is the one knob for how
/// stale the accounting may be.
///
/// Chosen against the per-address allowance, the tighter of the two limits: a
/// sixty-fourth of the shipped 500KB/s, so a connection can overshoot by about
/// 1.5% of one address's second before it finds out.
const FLUSH_BYTES: u64 = 8 * 1024;

/// The smallest receive window a connection is clamped to.
///
/// A segment and a little, so a clamped connection crawls rather than stalls.
/// It is also the floor on what a clamp can express: below a round trip's worth
/// of one segment, the window stops being a rate limit and the application gate
/// is the only thing still rationing.
const MIN_CLAMP: u64 = 4 * 1024;
/// The largest, so a connection on a long link is not authorised an unbounded
/// buffer just because its round trip is slow.
const MAX_CLAMP: u64 = 8 * 1024 * 1024;

/// One connection's shared state. Cheap to clone; clones are the same
/// connection.
#[derive(Clone, Debug)]
pub struct Conn<P: ProvideGoalkeeper = SystemGoalkeeper>(Arc<ConnState<P>>);

#[derive(Debug)]
struct ConnState<P: ProvideGoalkeeper> {
    peer: SocketAddr,
    ip: IpAddr,
    priority: SharedPriority,
    /// Taken once, to destroy the connection, or never.
    ///
    /// Behind a mutex because [`Conn`] is `Clone`, so [`Conn::kill`] cannot own
    /// the sender. Touched at most once in a connection's life.
    kill: Mutex<Option<oneshot::Sender<()>>>,
    tx: AtomicU64,
    rx: AtomicU64,
    /// Bytes moved but not yet reported to the ledger, by [`Direction`].
    ///
    /// The ledger and the per-address limiter are process-global and behind
    /// locks, so consulting them per socket operation costs several
    /// acquisitions to maintain a verdict that changes once per window.
    /// Settling every [`FLUSH_BYTES`] reaches the same answer over a fraction
    /// of the traffic.
    pending: [AtomicU64; 2],
    /// Bytes this connection may still move in each [`Direction`] before it
    /// must consult the ledger again.
    ///
    /// A lease rather than a cached yes-or-no, since a verdict refreshed every
    /// [`FLUSH_BYTES`] is far too coarse when a level's whole share of a window
    /// is a few hundred bytes. The ledger sizes the lease from what is left, so
    /// the granularity tightens when it has to.
    credit: [AtomicU64; 2],
    /// The outstanding [`bandwidth::Grant`], as `(bytes, level, epoch)`.
    ///
    /// A lease is charged when granted rather than when spent, so it must be
    /// given back to the level and window it was taken from, either of which
    /// may have moved on. `bytes` of zero means nothing is outstanding.
    reserved: [AtomicU64; 2],
    reserved_level: [AtomicU8; 2],
    reserved_epoch: [AtomicU64; 2],
    /// How many consecutive windows this connection has been throttled in, so
    /// backpressure can escalate to a kill for a peer that ignores it.
    strikes: bandwidth::Strikes,
    /// RAM reserved through this connection, and the level it is booked at.
    ///
    /// Booked against the connection rather than frozen into each
    /// [`Reservation`][crate::resource::memory::Reservation], since a
    /// connection outlives its level. See [`Conn::reconcile_ram`], which moves
    /// them.
    ram: AtomicU64,
    ram_level: AtomicU8,
    /// Dropped with the connection, releasing its slot with the IP limiter.
    _permit: ConnectionPermit<P>,
}

impl<P: ProvideGoalkeeper> Conn<P> {
    /// Creates a connection from `peer` holding `permit`, starting at
    /// [`Priority::New`].
    ///
    /// Returns the connection and the receiver [`ConnIo`] needs.
    pub fn new(peer: SocketAddr, permit: ConnectionPermit<P>) -> (Self, oneshot::Receiver<()>) {
        let (kill, killed) = oneshot::channel();
        let peer = canonize(peer);
        (
            Self(Arc::new(ConnState {
                peer,
                ip: peer.ip(),
                priority: SharedPriority::new(Priority::New),
                kill: Mutex::new(Some(kill)),
                tx: AtomicU64::new(0),
                rx: AtomicU64::new(0),
                pending: Default::default(),
                credit: Default::default(),
                reserved: Default::default(),
                reserved_level: Default::default(),
                reserved_epoch: Default::default(),
                strikes: bandwidth::Strikes::new(),
                ram: AtomicU64::new(0),
                ram_level: AtomicU8::new(Priority::New.level()),
                _permit: permit,
            })),
            killed,
        )
    }

    /// Records that this connection was throttled in `window`, returning how
    /// many consecutive windows that makes.
    pub(crate) fn strike(&self, window: u64) -> u32 {
        self.0.strikes.strike(window)
    }

    /// Forgives past throttling, because this connection is within its ration.
    pub(crate) fn clear_strike(&self) {
        self.0.strikes.clear();
    }

    /// Returns where the connection came from, with any IPv4-in-IPv6 mapping
    /// undone.
    pub fn peer(&self) -> SocketAddr {
        self.0.peer
    }

    /// Returns the peer's address, which everything per-address is keyed on.
    pub fn ip(&self) -> IpAddr {
        self.0.ip
    }

    /// Returns this connection's priority, shared with every task serving it,
    /// so re-levelling here re-levels all of them.
    pub fn priority(&self) -> &SharedPriority {
        &self.0.priority
    }

    /// Changes what this connection is, absent anything depending on it.
    ///
    /// [`SharedPriority::set_base`], with this connection's booked RAM moved to
    /// the new level.
    pub fn set_base(&self, base: Priority) {
        self.0.priority.set_base(base);
        self.reconcile_ram();
    }

    /// Holds this connection at `level` until the guard falls.
    ///
    /// [`SharedPriority::boost`], with this connection's booked RAM moved to
    /// the new level. Dropping the guard gives the level back, and the booking
    /// follows within a window.
    #[must_use = "dropping the guard immediately gives the level back"]
    pub fn boost(&self, level: Priority) -> Boost {
        let boost = self.0.priority.boost(level);
        self.reconcile_ram();
        boost
    }

    /// Destroys the connection.
    ///
    /// Takes effect on the connection's next read. Idempotent, and a no-op if
    /// it is already gone.
    ///
    /// Reserved for a peer that has ignored being throttled; see
    /// [`crate::resource::bandwidth`].
    pub fn kill(&self) {
        if let Some(kill) = self.0.kill.lock().unwrap().take() {
            let _ = kill.send(());
        }
    }

    /// Returns bytes sent and received on this connection.
    pub fn bytes(&self) -> (u64, u64) {
        (
            self.0.tx.load(Ordering::Relaxed),
            self.0.rx.load(Ordering::Relaxed),
        )
    }

    /// Returns the instance this connection was admitted by, and gives its
    /// permit back to.
    pub fn provider(&self) -> &P {
        self.0._permit.provider()
    }

    /// Reserves `bytes` of RAM at this connection's level, or refuses.
    ///
    /// The guard releases them when it drops, and gives them back to the level
    /// they were taken from even if the connection has been re-levelled since.
    ///
    /// Coarse by design: one reservation per connection, buffer or session,
    /// never one per message. The bookkeeping is an atomic pair, which is
    /// nothing at connection granularity and ruinous per byte.
    pub fn try_reserve(&self, bytes: u64) -> Option<crate::resource::memory::Reservation<P>> {
        crate::resource::memory::reserve_for(self, bytes)
    }

    /// Where this connection's RAM is currently booked.
    pub(crate) fn ram_level(&self) -> u8 {
        self.0.ram_level.load(Ordering::Relaxed)
    }

    /// Charges `bytes` at the level this connection's RAM is booked at,
    /// reconciling that with its actual level first.
    pub(crate) fn charge_ram(&self, bytes: u64) -> Option<()> {
        self.reconcile_ram();
        let level = self.ram_level();
        self.provider()
            .limiter
            .with_process(|_, _, memory| memory.reserve(level, bytes))?;
        self.0.ram.fetch_add(bytes, Ordering::Relaxed);
        Some(())
    }

    /// Gives `bytes` back to wherever this connection's RAM is booked.
    pub(crate) fn release_ram(&self, bytes: u64) {
        let level = self.ram_level();
        self.0.ram.fetch_sub(bytes, Ordering::Relaxed);
        self.provider()
            .limiter
            .with_process(|_, _, memory| memory.release(level, bytes));
    }

    /// Moves everything this connection holds to the level it is now at.
    ///
    /// Cheap enough for any path that already touches the ledger. Called by
    /// [`Self::boost`] and [`Self::set_base`], and by the per-window socket
    /// reconfiguration, so a connection re-levelled by any other route still
    /// corrects within a window of doing anything at all.
    ///
    /// Safe to call from several threads at once: the booking and the amount
    /// are read under the ledger's lock rather than out here, so a concurrent
    /// [`Self::charge_ram`] cannot have its bytes moved to a level they were
    /// never charged at.
    ///
    /// An idle connection's booking may be stale until it next does something,
    /// which is harmless: its buffers are ones the controller may shrink
    /// freely.
    pub(crate) fn reconcile_ram(&self) {
        crate::resource::memory::rebook(
            self.provider(),
            &self.0.ram_level,
            &self.0.ram,
            self.priority().level(),
        );
    }

    /// The whole of this connection's level's allowance in `dir` this window,
    /// spent or not.
    ///
    /// Distinct from [`Self::ration`], which is what remains. For a caller
    /// sizing something that should be stable across a window, such as a
    /// flow-control window, which stalls in-flight data if it shrinks under it.
    pub fn allowance(&self, dir: Direction) -> u64 {
        bandwidth::allowance(self, dir)
    }

    /// What this connection's level may still move in `dir` this window.
    pub fn ration(&self, dir: Direction) -> u64 {
        bandwidth::ration(self, dir)
    }

    /// The rate the kernel should be told to hold this connection to, floored
    /// so that being outranked slows it rather than stopping it.
    pub fn paced_rate(&self, dir: Direction) -> u64 {
        bandwidth::paced_rate(self, dir)
    }

    /// Reserves bytes to move in `dir`, or registers `cx` to be woken when the
    /// ledger next has some. See [`crate::resource::bandwidth::Grant`].
    pub fn lease(&self, dir: Direction, cx: &mut Context<'_>) -> Option<bandwidth::Grant> {
        bandwidth::lease(self, dir, cx)
    }

    /// Records `bytes` moved in `dir` against this connection, and, once a few
    /// kilobytes have gathered, against whatever ration applies to it.
    pub fn record(&self, dir: Direction, bytes: u64) {
        match dir {
            Direction::Tx => self.0.tx.fetch_add(bytes, Ordering::Relaxed),
            Direction::Rx => self.0.rx.fetch_add(bytes, Ordering::Relaxed),
        };
        let index = dir as usize;
        // Spends the lease. Saturating, since a single write may overshoot what
        // was left of it, bounded by that one write.
        self.0.credit[index].update(Ordering::Relaxed, Ordering::Relaxed, |credit| {
            credit.saturating_sub(bytes)
        });
        let pending = self.0.pending[index].fetch_add(bytes, Ordering::Relaxed) + bytes;
        if pending >= FLUSH_BYTES || self.0.credit[index].load(Ordering::Relaxed) == 0 {
            self.settle(dir);
        }
    }

    /// Reports what this connection moved, gives back what it reserved and did
    /// not, and ends the lease.
    ///
    /// Ending the lease matters: refunding the reservation while leaving the
    /// credit standing would let the connection write against an allowance
    /// nobody is holding for it.
    fn settle(&self, dir: Direction) {
        let index = dir as usize;
        let moved = self.0.pending[index].swap(0, Ordering::Relaxed);
        let bytes = self.0.reserved[index].swap(0, Ordering::Relaxed);
        self.0.credit[index].store(0, Ordering::Relaxed);
        if moved == 0 && bytes == 0 {
            return;
        }
        // With a reservation outstanding, the bytes belong where it was taken
        // from. Without one, they belong at the connection's current level;
        // a stale reservation's level may be somewhere it has never been.
        let grant = if bytes > 0 {
            bandwidth::Grant {
                bytes,
                level: self.0.reserved_level[index].load(Ordering::Relaxed),
                epoch: self.0.reserved_epoch[index].load(Ordering::Relaxed),
            }
        } else {
            bandwidth::Grant {
                bytes: 0,
                level: self.0.priority.level(),
                epoch: 0,
            }
        };
        bandwidth::settle_raw(self.provider(), grant, self.0.ip, dir, moved);
    }

    /// Whether this connection should stop moving bytes in `dir` for now.
    ///
    /// Answers from the outstanding lease while there is one, which is the
    /// common case and one relaxed load. Otherwise it settles up and asks the
    /// ledger for another, which is also what registers `cx` to be woken when
    /// the ration refills.
    pub fn throttled(&self, dir: Direction, cx: &mut Context<'_>) -> bool {
        let index = dir as usize;
        if self.0.credit[index].load(Ordering::Relaxed) > 0 {
            return false;
        }
        // Asked with the books straight, so the ledger sizes the next lease
        // against what this connection has really moved.
        self.settle(dir);
        match bandwidth::lease(self, dir, cx) {
            Some(grant) => {
                self.0.credit[index].store(grant.bytes, Ordering::Relaxed);
                self.0.reserved[index].store(grant.bytes, Ordering::Relaxed);
                self.0.reserved_level[index].store(grant.level, Ordering::Relaxed);
                self.0.reserved_epoch[index].store(grant.epoch, Ordering::Relaxed);
                false
            }
            None => true,
        }
    }

    /// Waits until this connection may move bytes in `dir`, then says how many.
    ///
    /// The `async` face of [`Self::throttled`], for a transport whose write
    /// method is an `async fn` rather than a `poll_write`, such as a QUIC
    /// stream. An `AsyncWrite` wrapper would force every error through
    /// `io::Error` and cost the caller the transport's own error type.
    pub async fn await_credit(&self, dir: Direction) -> u64 {
        std::future::poll_fn(|cx| {
            if self.throttled(dir, cx) {
                Poll::Pending
            } else {
                // At least one, so a caller always makes progress rather than
                // spinning on a zero-length write.
                Poll::Ready(self.credit(dir).max(1))
            }
        })
        .await
    }

    /// Bytes still leased in `dir`, which is the most a single write may carry.
    ///
    /// Clamping the write to the lease is what makes the accounting mean
    /// anything at low bandwidth. Otherwise a connection moving a kilobyte per
    /// window would write eight at a time and report nothing in the four
    /// windows either side, leaving the ledger to conclude the level is idle.
    pub(crate) fn credit(&self, dir: Direction) -> u64 {
        self.0.credit[dir as usize].load(Ordering::Relaxed)
    }
}

impl<P: ProvideGoalkeeper> Drop for ConnState<P> {
    /// Settles up.
    ///
    /// Without this a peer could move [`FLUSH_BYTES`] and hang up, over and
    /// over, and never be metered at all.
    fn drop(&mut self) {
        for dir in [Direction::Tx, Direction::Rx] {
            let index = dir as usize;
            let moved = self.pending[index].swap(0, Ordering::Relaxed);
            let bytes = self.reserved[index].swap(0, Ordering::Relaxed);
            if moved == 0 && bytes == 0 {
                continue;
            }
            // Refunds the outstanding lease as well as reporting the bytes, so
            // a connection dying mid-lease does not leave its level charged for
            // capacity nobody will use.
            let grant = if bytes > 0 {
                bandwidth::Grant {
                    bytes,
                    level: self.reserved_level[index].load(Ordering::Relaxed),
                    epoch: self.reserved_epoch[index].load(Ordering::Relaxed),
                }
            } else {
                bandwidth::Grant {
                    bytes: 0,
                    level: self.priority.level(),
                    epoch: 0,
                }
            };
            bandwidth::settle_raw(self._permit.provider(), grant, self.ip, dir, moved);
        }
    }
}

/// Undoes an IPv4-to-IPv6 mapping, so an address matches what other transports
/// report for the same peer, notably when used as a limiter key.
pub fn canonize(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V6(v6) => {
            if let Some(v4) = v6.ip().to_ipv4_mapped() {
                SocketAddr::V4(SocketAddrV4::new(v4, v6.port()))
            } else if v6.ip().is_loopback() {
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, v6.port()))
            } else {
                addr
            }
        }
        addr => addr,
    }
}

/// A stream that answers to its [`Conn`]: killable, metered, and throttled.
///
/// Wraps the transport below TLS, so a kill destroys the whole connection
/// rather than one HTTP/2 stream, and so the byte counts are wire bytes rather
/// than plaintext.
///
/// Concrete over [`TcpStream`] rather than generic, since holding the socket is
/// what lets the ration be handed to the kernel as a pacing rate and a window
/// clamp. TLS layers above this, not below it.
#[pin_project::pin_project]
pub struct ConnIo<P: ProvideGoalkeeper = SystemGoalkeeper> {
    #[pin]
    stream: TcpStream,
    conn: Conn<P>,
    #[pin]
    killed: oneshot::Receiver<()>,
    /// Once fired, reads fail forever rather than being re-checked.
    dead: bool,
    /// What the kernel was last told, so it is only told again when it changes.
    /// A `setsockopt` per write would cost more than the pacing saves.
    applied: Applied,
}

/// The socket options currently set, as far as this stream knows.
///
/// Reconfigured once per bandwidth window rather than per operation, since a
/// ration is a per-window quantity and a `setsockopt` on every write costs more
/// than the precision is worth. `epoch` is what enforces that cadence.
#[derive(Default)]
struct Applied {
    /// The window each direction was last configured for.
    epoch: [Option<u64>; 2],
    /// Whether the kernel accepted the job. When it did, the application-level
    /// gate stands down: the kernel is doing the rationing, and more evenly.
    /// Parking on top would only add latency.
    kernel: [bool; 2],
    nodelay: Option<bool>,
}

impl<P: ProvideGoalkeeper> ConnIo<P> {
    /// Wraps `stream` for `conn`.
    pub fn new(stream: TcpStream, conn: Conn<P>, killed: oneshot::Receiver<()>) -> Self {
        Self {
            stream,
            conn,
            killed,
            dead: false,
            applied: Applied::default(),
        }
    }

    /// The connection this stream belongs to.
    pub fn conn(&self) -> &Conn<P> {
        &self.conn
    }
}

impl<P: ProvideGoalkeeper> AsyncRead for ConnIo<P> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut this = self.project();

        // Read side only, which suffices: anything worth killing is waiting to
        // be read from.
        if *this.dead {
            return Poll::Ready(Err(io::Error::from(io::ErrorKind::ConnectionAborted)));
        }
        if let Poll::Ready(Ok(())) = this.killed.as_mut().poll(cx) {
            *this.dead = true;
            return Poll::Ready(Err(io::Error::from(io::ErrorKind::ConnectionAborted)));
        }

        // Once per window: tell the peer how much it may have outstanding, so
        // it slows at the source rather than discovering the limit when our
        // socket buffer fills.
        let index = Direction::Rx as usize;
        let epoch = bandwidth::epoch();
        if this.applied.epoch[index] != Some(epoch) {
            // A connection re-levelled since the last window takes its memory
            // with it. Here, because this is the one place a live connection
            // reliably reaches once per window.
            this.conn.reconcile_ram();
            // Both ledgers bound this: bandwidth says how fast the peer may
            // send, memory how much the process can afford to have outstanding.
            // The smaller wins. Quantising keeps a drifting number from
            // spending a `setsockopt` a window; see `crate::memory`.
            //
            // The ration is per window and a clamp is bytes in flight, so it
            // only becomes one through the round trip. Without a measurement
            // there is no conversion to make, and the gate below rations
            // instead.
            this.applied.kernel[index] = match crate::tokio_net::round_trip(&this.stream) {
                Some(rtt) => {
                    let ration = bandwidth::ration(this.conn, Direction::Rx);
                    let flight = bandwidth::flight(ration, bandwidth::window(), rtt);
                    let room = crate::resource::memory::window_ceiling(this.conn);
                    let clamp = crate::resource::memory::quantise(flight.min(room))
                        .clamp(MIN_CLAMP, MAX_CLAMP) as u32;
                    crate::tokio_net::clamp_receive_window(&this.stream, clamp)
                }
                None => false,
            };
            this.applied.epoch[index] = Some(epoch);
        }

        if this.applied.kernel[index] {
            // The kernel is holding the peer to the advertised window, so reads
            // are not gated here. The bytes are still counted below.
        } else if this.conn.throttled(Direction::Rx, cx) {
            // Backpressure, not loss: over its ration, the connection simply is
            // not read, and the peer's own flow control slows it at the source.
            // The waker is held by the bandwidth ledger and fired when the
            // ration refills, so this is a park rather than a spin.
            return Poll::Pending;
        }

        let before = buf.filled().len();
        let polled = this.stream.poll_read(cx, buf);
        if polled.is_ready() {
            let read = buf.filled().len().saturating_sub(before);
            if read > 0 {
                this.conn.record(Direction::Rx, read as u64);
            }
        }
        polled
    }
}

impl<P: ProvideGoalkeeper> AsyncWrite for ConnIo<P> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.project();

        // The uplink, rationed the same way the downlink is, since egress is
        // usually the scarcer direction.
        //
        // Once per window, hand the rate to the kernel, which spaces the
        // packets out itself rather than sending a window's worth and stopping.
        //
        // Nagle goes with it: a connection keeping up wants its writes out now,
        // but one held to a low rate is better off coalescing them.
        let index = Direction::Tx as usize;
        let epoch = bandwidth::epoch();
        if this.applied.epoch[index] != Some(epoch) {
            let rate = bandwidth::paced_rate(this.conn, Direction::Tx);
            this.applied.kernel[index] = crate::tokio_net::pace(&this.stream, rate);
            this.applied.epoch[index] = Some(epoch);

            let nodelay = rate > bandwidth::MIN_PACED_RATE;
            if this.applied.nodelay != Some(nodelay) {
                crate::tokio_net::set_nodelay(&this.stream, nodelay);
                this.applied.nodelay = Some(nodelay);
            }
        }

        if this.applied.kernel[index] {
            // Paced by the kernel, so the write is neither parked nor
            // truncated; a short write here would only fragment it.
            let polled = this.stream.poll_write(cx, buf);
            if let Poll::Ready(Ok(written)) = &polled {
                this.conn.record(Direction::Tx, *written as u64);
            }
            return polled;
        }

        // Parking a write leaves the data buffered above rather than dropping
        // it, and the waker fires when the ration refills.
        if this.conn.throttled(Direction::Tx, cx) {
            return Poll::Pending;
        }

        // A short write, which `AsyncWrite` permits and every caller handles.
        // See [`Conn::credit`].
        let allowed = this.conn.credit(Direction::Tx).max(1) as usize;
        let buf = &buf[..buf.len().min(allowed)];

        let polled = this.stream.poll_write(cx, buf);
        if let Poll::Ready(Ok(written)) = &polled {
            this.conn.record(Direction::Tx, *written as u64);
        }
        polled
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().stream.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().stream.poll_shutdown(cx)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.project();
        if this.conn.throttled(Direction::Tx, cx) {
            return Poll::Pending;
        }

        // The longest prefix of whole buffers the lease covers, so a vectored
        // write stays vectored where it can. Measured in bytes; counting
        // buffers instead would let one oversized buffer through.
        let allowed = this.conn.credit(Direction::Tx).max(1) as usize;
        let mut fits = 0usize;
        let mut total = 0usize;
        for slice in bufs {
            if total + slice.len() > allowed {
                break;
            }
            total += slice.len();
            fits += 1;
        }

        let polled = if total > 0 {
            this.stream.poll_write_vectored(cx, &bufs[..fits])
        } else {
            // Not even the first buffer fits, so respect the lease with one
            // truncated write. `AsyncWrite` permits a short write and the
            // caller comes back for the rest.
            let first = bufs
                .iter()
                .find(|slice| !slice.is_empty())
                .map(|slice| &slice[..slice.len().min(allowed)])
                .unwrap_or(&[]);
            this.stream.poll_write(cx, first)
        };
        if let Poll::Ready(Ok(written)) = &polled {
            this.conn.record(Direction::Tx, *written as u64);
        }
        polled
    }

    fn is_write_vectored(&self) -> bool {
        self.stream.is_write_vectored()
    }
}

/// Anything byte-oriented, rationed against a [`Conn`].
///
/// [`ConnIo`] for transports that do not hand out a socket, notably QUIC
/// streams: `SO_MAX_PACING_RATE` cannot be set on one, and flow-control windows
/// pace by bytes in flight, so what they permit depends on the round trip and
/// below one datagram they stall rather than slow. Delaying the write is the
/// same lever TCP gets.
///
/// Every stream on a connection wraps the same `Conn` and shares one ration, so
/// a peer cannot buy bandwidth by opening more streams.
#[pin_project::pin_project]
pub struct Throttled<S, P: ProvideGoalkeeper = SystemGoalkeeper> {
    #[pin]
    stream: S,
    conn: Conn<P>,
}

impl<S, P: ProvideGoalkeeper> Throttled<S, P> {
    /// Rations `stream` against `conn`.
    pub fn new(stream: S, conn: Conn<P>) -> Self {
        Self { stream, conn }
    }

    /// The connection this stream is rationed against.
    pub fn conn(&self) -> &Conn<P> {
        &self.conn
    }

    /// The stream underneath, giving up the rationing.
    pub fn into_inner(self) -> S {
        self.stream
    }

    /// The stream underneath, for an operation this does not wrap, such as
    /// closing a QUIC stream.
    ///
    /// Bytes moved through here are neither counted nor rationed, so this is
    /// for control rather than for data.
    pub fn inner_mut(&mut self) -> &mut S
    where
        S: Unpin,
    {
        &mut self.stream
    }
}

impl<S: AsyncRead, P: ProvideGoalkeeper> AsyncRead for Throttled<S, P> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.project();
        if this.conn.throttled(Direction::Rx, cx) {
            return Poll::Pending;
        }
        let before = buf.filled().len();
        let polled = this.stream.poll_read(cx, buf);
        if polled.is_ready() {
            let read = buf.filled().len().saturating_sub(before);
            if read > 0 {
                this.conn.record(Direction::Rx, read as u64);
            }
        }
        polled
    }
}

impl<S: AsyncWrite, P: ProvideGoalkeeper> AsyncWrite for Throttled<S, P> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.project();
        if this.conn.throttled(Direction::Tx, cx) {
            return Poll::Pending;
        }
        // Clamped to the lease, so the ledger sees what was really moved
        // several times a window rather than one lump per lease. A short write
        // is permitted and every caller handles it.
        let allowed = this.conn.credit(Direction::Tx).max(1) as usize;
        let buf = &buf[..buf.len().min(allowed)];

        let polled = this.stream.poll_write(cx, buf);
        if let Poll::Ready(Ok(written)) = &polled {
            this.conn.record(Direction::Tx, *written as u64);
        }
        polled
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().stream.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().stream.poll_shutdown(cx)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.project();
        if this.conn.throttled(Direction::Tx, cx) {
            return Poll::Pending;
        }

        // The longest prefix of whole buffers the lease covers, measured in
        // *bytes*. Counting buffers instead would let one oversized buffer
        // through, and the clamp would never bite.
        let allowed = this.conn.credit(Direction::Tx).max(1) as usize;
        let mut fits = 0usize;
        let mut total = 0usize;
        for slice in bufs {
            if total + slice.len() > allowed {
                break;
            }
            total += slice.len();
            fits += 1;
        }

        let polled = if total > 0 {
            this.stream.poll_write_vectored(cx, &bufs[..fits])
        } else {
            // Not even the first buffer fits, so respect the lease with one
            // short write; the caller comes back for the rest.
            let first = bufs
                .iter()
                .find(|slice| !slice.is_empty())
                .map(|slice| &slice[..slice.len().min(allowed)])
                .unwrap_or(&[]);
            this.stream.poll_write(cx, first)
        };
        if let Poll::Ready(Ok(written)) = &polled {
            this.conn.record(Direction::Tx, *written as u64);
        }
        polled
    }

    fn is_write_vectored(&self) -> bool {
        self.stream.is_write_vectored()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;
    use std::sync::atomic::AtomicU16;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// A fresh address per connection, since these all share
    /// [`SystemGoalkeeper`]'s limiter and must not ration each other.
    fn conn() -> (Conn, oneshot::Receiver<()>) {
        static NEXT: AtomicU16 = AtomicU16::new(1);
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let ip = IpAddr::from([10, 1, (n >> 8) as u8, n as u8]);
        let permit = SystemGoalkeeper
            .connection_permit(ip, "test")
            .expect("a first connection is always permitted");
        Conn::new(SocketAddr::new(ip, 4000), permit)
    }

    #[test]
    fn ipv4_mapped_addresses_are_canonized() {
        let mapped = SocketAddr::new(
            IpAddr::V6(Ipv6Addr::from([0, 0, 0, 0, 0, 0xffff, 0x0102, 0x0304])),
            9,
        );
        assert_eq!(canonize(mapped).ip(), IpAddr::from([1, 2, 3, 4]));
        // Loopback too, so a local client looks the same over either family.
        let loopback = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 9);
        assert_eq!(canonize(loopback).ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        // And an ordinary v6 address is left alone.
        let real = SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            9,
        );
        assert_eq!(canonize(real), real);
    }

    /// A connected pair of real sockets.
    ///
    /// `tokio::io::duplex` would be lighter, but [`ConnIo`] is concrete over
    /// `TcpStream`, so a test that wants one has to have one.
    async fn socket_pair() -> (TcpStream, TcpStream) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (client, accepted) = tokio::join!(TcpStream::connect(addr), listener.accept());
        (client.unwrap(), accepted.unwrap().0)
    }

    #[tokio::test]
    async fn a_stream_counts_what_passes_through_it() {
        let (client, server) = socket_pair().await;
        let (conn, killed) = conn();
        let mut io = ConnIo::new(server, conn.clone(), killed);

        let mut client = client;
        client.write_all(b"hello").await.unwrap();
        let mut buf = [0u8; 5];
        io.read_exact(&mut buf).await.unwrap();
        io.write_all(b"goodbye!").await.unwrap();

        let (tx, rx) = conn.bytes();
        assert_eq!(rx, 5);
        assert_eq!(tx, 8);
    }

    #[tokio::test]
    async fn killing_aborts_the_next_read() {
        let (client, server) = socket_pair().await;
        let (conn, killed) = conn();
        let mut io = ConnIo::new(server, conn.clone(), killed);
        let _client = client;

        conn.kill();
        let mut buf = [0u8; 1];
        let error = io.read(&mut buf).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
        // And stays dead rather than recovering.
        let again = io.read(&mut buf).await.unwrap_err();
        assert_eq!(again.kind(), io::ErrorKind::ConnectionAborted);
    }

    #[tokio::test]
    async fn killing_twice_is_harmless() {
        let (_client, server) = socket_pair().await;
        let (conn, killed) = conn();
        let _io = ConnIo::new(server, conn.clone(), killed);
        conn.kill();
        conn.kill();
    }

    #[test]
    fn a_connection_starts_as_a_stranger_and_can_be_raised() {
        let (conn, _killed) = conn();
        assert_eq!(conn.priority().effective(), Priority::New);
        conn.set_base(Priority::User(crate::executor::priority::UserPriority::L0));
        assert_eq!(
            conn.priority().effective(),
            Priority::User(crate::executor::priority::UserPriority::L0)
        );
    }

    /// A connection's RAM follows it when it stops being a stranger.
    ///
    /// Freezing the level into the reservation, as a bandwidth grant does,
    /// would leave every established player holding its baseline buffers
    /// against `New` for life: strangers cut off early by memory that players
    /// hold, and the controller shrinking the players it was protecting.
    #[test]
    fn a_reservation_follows_its_connection_out_of_being_a_stranger() {
        use crate::executor::priority::UserPriority::L0;

        let (conn, _killed) = conn();
        let held = SystemGoalkeeper.memory_usage();
        let stranger_before = held.held(Priority::New);
        let player_before = held.held(Priority::User(L0));

        let _ram = conn.try_reserve(64 * 1024).expect("an idle ledger admits");
        assert_eq!(
            SystemGoalkeeper.memory_usage().held(Priority::New) - stranger_before,
            64 * 1024,
            "a stranger's reservation was not charged to strangers"
        );

        // The connection authenticates.
        conn.set_base(Priority::User(L0));
        conn.reconcile_ram();

        let after = SystemGoalkeeper.memory_usage();
        assert_eq!(
            after.held(Priority::New),
            stranger_before,
            "an established player left its memory booked against strangers"
        );
        assert_eq!(
            after.held(Priority::User(L0)) - player_before,
            64 * 1024,
            "the player's memory did not arrive at the player's level"
        );
    }
}
