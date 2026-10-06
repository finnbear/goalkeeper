//! [`Batched`], a UDP socket that sends many connections' packets with one
//! `sendmmsg`.
//!
//! A prototype. See
//! [`batch_sends`][crate::web_transport::WebTransportServerBuilder::batch_sends].

use crate::executor::TurnHook;
use log::{info, warn};
use std::collections::VecDeque;
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};
use tokio::io::Interest;
use tokio::io::unix::AsyncFd;

/// Packets per `sendmmsg`, and the most ever queued.
///
/// A full batch is sent as soon as it is queued, so one can stay queued only
/// behind a socket that would not take it, and then `try_send` refuses more:
/// quinn waits, as it would have on its own send, rather than this buffering
/// behind the kernel's buffer where congestion control cannot see it.
///
/// Tiny in debug builds, so that a turn sending more than a batch is common
/// and a full queue is not rare; see also [`DEBUG_SEND_BUFFER`].
const MAX_BATCH: usize = if cfg!(debug_assertions) { 3 } else { 64 };

/// The socket's send buffer in debug builds, so small the kernel rounds it up
/// to its minimum, a few packets' worth: a tick to a handful of clients fills
/// it, and the wait on a full socket actually runs.
const DEBUG_SEND_BUFFER: usize = 0;

/// Buffers kept for reuse, so a queued packet costs no allocation.
const MAX_SPARE: usize = 2 * MAX_BATCH;

/// How often a failed send is logged, at most.
const ERROR_LOG_INTERVAL: Duration = Duration::from_secs(60);

/// Runs a future on the executor, for the rare wait on a full socket.
type Spawn = Box<dyn Fn(Pin<Box<dyn Future<Output = ()> + Send>>) + Send + Sync>;

/// A UDP socket that queues what quinn sends, and sends it with one `sendmmsg`
/// per batch rather than one `sendmsg` per packet.
///
/// quinn's connections each send on their own, so a server that sends every
/// client a little at once — a game's tick — makes a system call per client,
/// and on a virtual machine an exit to the hypervisor per client besides. GSO
/// cannot help, since it only combines packets to one destination; this
/// combines packets to many.
///
/// The batch is whatever the executor's turn sent: quinn's drivers are its
/// tasks, so every `try_send` happens in one, and the end of the turn — see
/// [`TurnHook`] — is when they have all run and the reactor, which would carry
/// anything out, has not. So nothing waits on a timer, and a packet is sent
/// before the executor sleeps, as it would have been anyway. A turn sending
/// [`MAX_BATCH`] packets sends them at once rather than waiting for its end.
///
/// Each packet keeps everything quinn's own send would have given it:
/// destination, source address, ECN and GSO segment size.
pub(crate) struct Batched {
    /// quinn's own wrapping of the socket, which receives, polls, and reports
    /// what the socket supports.
    inner: Arc<dyn quinn::AsyncUdpSocket>,
    /// A duplicate of the same socket, for `sendmmsg`.
    fd: AsyncFd<std::net::UdpSocket>,
    queue: Mutex<Queue>,
    /// This, for the task that waits on a full socket.
    this: Weak<Self>,
    spawn: Spawn,
    /// Whether a task is waiting on a full socket, so there is one at most.
    waiting: AtomicBool,
    /// When a failed send was last logged.
    last_error: Mutex<Option<Instant>>,
    /// Segments per GSO transmit, as quinn's own socket reports it, until a
    /// send suggests the network adapter cannot segment after all.
    max_gso_segments: AtomicUsize,
    /// Whether a send failed with `EINVAL`, after which IPv4 packets go without
    /// `IP_TOS`, the argument some systems refuse.
    sendmsg_einval: AtomicBool,
}

#[derive(Default)]
struct Queue {
    packets: VecDeque<Packet>,
    spare: Vec<Vec<u8>>,
    /// quinn's drivers waiting for room; see [`RoomPoller`].
    waiting_for_room: Vec<Waker>,
}

impl Queue {
    /// Takes the oldest `count` packets off the queue, keeping their buffers,
    /// and wakes whoever was waiting for room.
    fn retire(&mut self, count: usize) {
        for packet in self.packets.drain(..count) {
            if self.spare.len() < MAX_SPARE {
                self.spare.push(packet.contents);
            }
        }
        if count > 0 && self.packets.len() < MAX_BATCH {
            for waker in self.waiting_for_room.drain(..) {
                waker.wake();
            }
        }
    }
}

struct Packet {
    destination: SocketAddr,
    ecn: Option<quinn::udp::EcnCodepoint>,
    src_ip: Option<IpAddr>,
    segment_size: Option<usize>,
    contents: Vec<u8>,
}

impl std::fmt::Debug for Batched {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Batched").finish_non_exhaustive()
    }
}

impl Batched {
    /// Wraps `socket` as quinn's `runtime` would, to send at the end of each of
    /// `executor`'s turns. `spawn` runs a task on `executor`, needed only when
    /// the socket is full.
    pub(crate) fn wrap(
        socket: std::net::UdpSocket,
        runtime: &quinn::TokioRuntime,
        executor: &crate::executor::Executor,
        spawn: Spawn,
    ) -> io::Result<Arc<Self>> {
        use quinn::Runtime;
        // A duplicate shares the socket, so the options quinn sets on its copy —
        // the packet info that makes a source address mean anything, among them
        // — apply to this one too, as does non-blocking.
        let fd = AsyncFd::with_interest(socket.try_clone()?, Interest::WRITABLE)?;
        let inner = runtime.wrap_udp_socket(socket)?;
        if cfg!(debug_assertions) {
            // After quinn's own setup, so nothing it sets overrides this.
            socket2::SockRef::from(fd.get_ref()).set_send_buffer_size(DEBUG_SEND_BUFFER)?;
        }
        let batched = Arc::new_cyclic(|this| Self {
            inner,
            fd,
            queue: Mutex::new(Queue::default()),
            this: this.clone(),
            spawn,
            waiting: AtomicBool::new(false),
            last_error: Mutex::new(None),
            max_gso_segments: AtomicUsize::new(usize::MAX),
            sendmsg_einval: AtomicBool::new(false),
        });
        executor.on_turn_end(Arc::<Batched>::downgrade(&batched));
        Ok(batched)
    }

    /// Sends what is queued, or as much as the socket will take and the rest
    /// once it will take more.
    fn flush(&self) {
        // A task is already waiting for the socket, which was full, so trying
        // now would most likely cost a system call to learn that again.
        if self.waiting.load(Ordering::Acquire) {
            return;
        }
        if let Err(e) = self.send_queued(self.fd.get_ref())
            && e.kind() == io::ErrorKind::WouldBlock
        {
            self.drain_later();
        }
    }

    /// Has a task wait for the socket and send what is queued, unless one
    /// already is.
    fn drain_later(&self) {
        if self.waiting.swap(true, Ordering::AcqRel) {
            return;
        }
        let this = self.this.clone();
        (self.spawn)(Box::pin(async move {
            let Some(this) = this.upgrade() else {
                return;
            };
            loop {
                this.drain().await;
                this.waiting.store(false, Ordering::Release);
                // A flush on another thread may have found the socket full
                // between the last send above and the store, and left what it
                // queued to this task, which it thought was still waiting.
                if this.queue.lock().unwrap().packets.is_empty()
                    || this.waiting.swap(true, Ordering::AcqRel)
                {
                    return;
                }
            }
        }));
    }

    /// Ready once the queue has room, which is when quinn may send again.
    fn poll_room(&self, cx: &mut Context) -> Poll<io::Result<()>> {
        let mut queue = self.queue.lock().unwrap();
        if queue.packets.len() < MAX_BATCH {
            return Poll::Ready(Ok(()));
        }
        if !queue
            .waiting_for_room
            .iter()
            .any(|waker| waker.will_wake(cx.waker()))
        {
            queue.waiting_for_room.push(cx.waker().clone());
        }
        drop(queue);
        // Full only because the socket is, so a task is most likely waiting
        // for it already; if not, this is what makes room.
        self.drain_later();
        Poll::Pending
    }

    /// Sends everything queued, until the socket would block.
    ///
    /// The lock is held throughout, so packets go out in the order they were
    /// queued even when two threads flush at once.
    fn send_queued(&self, socket: &std::net::UdpSocket) -> io::Result<()> {
        let mut queue = self.queue.lock().unwrap();
        while !queue.packets.is_empty() {
            let count = queue.packets.len().min(MAX_BATCH);
            let packets = &queue.packets.make_contiguous()[..count];
            let sendmsg_einval = self.sendmsg_einval.load(Ordering::Relaxed);
            match sendmmsg(socket, packets, sendmsg_einval) {
                Ok(sent) => queue.retire(sent),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Err(e),
                Err(e) => {
                    // The first packet failed, and is answered as quinn's own
                    // send answers it.
                    //
                    // Some network adapters cannot segment, and say so only by
                    // failing a send with `EIO` or `EINVAL`. GSO stops for new
                    // transmits; those already queued may fail the same way.
                    if let Some(libc::EIO | libc::EINVAL) = e.raw_os_error()
                        && quinn::AsyncUdpSocket::max_transmit_segments(self) > 1
                    {
                        info!("`libc::sendmmsg` failed with {e}; halting segmentation offload");
                        self.max_gso_segments.store(1, Ordering::Relaxed);
                    }
                    // Some argument is unsupported: leave out the one that can
                    // be, and try the packet again without it, once.
                    if e.raw_os_error() == Some(libc::EINVAL) && !sendmsg_einval {
                        self.sendmsg_einval.store(true, Ordering::Relaxed);
                        continue;
                    }
                    // Otherwise dropped: an unreachable destination, a
                    // firewall, an MTU probe too large, all of which QUIC
                    // recovers from.
                    if e.raw_os_error() != Some(libc::EMSGSIZE) {
                        self.log_error(&e, &queue.packets[0]);
                    }
                    queue.retire(1);
                }
            }
        }
        Ok(())
    }

    /// Sends everything queued, waiting for the socket as long as it takes.
    async fn drain(&self) {
        loop {
            let Ok(mut ready) = self.fd.writable().await else {
                return;
            };
            if ready.try_io(|fd| self.send_queued(fd.get_ref())).is_ok() {
                return;
            }
        }
    }

    fn log_error(&self, error: &io::Error, packet: &Packet) {
        let now = Instant::now();
        let mut last = self.last_error.lock().unwrap();
        let previous = *last;
        if previous.is_none_or(|previous| now.duration_since(previous) > ERROR_LOG_INTERVAL) {
            *last = Some(now);
            warn!(
                "sendmmsg error: {error}, destination: {}, src_ip: {:?}, ecn: {:?}, len: {}, segment_size: {:?}",
                packet.destination,
                packet.src_ip,
                packet.ecn,
                packet.contents.len(),
                packet.segment_size
            );
        }
    }
}

impl TurnHook for Batched {
    fn turn_ended(&self) {
        self.flush();
    }
}

/// What quinn waits on after a `try_send` that was refused for want of room in
/// the queue: ready once there is some.
#[derive(Debug)]
struct RoomPoller(Arc<Batched>);

impl quinn::UdpPoller for RoomPoller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        self.0.poll_room(cx)
    }
}

impl quinn::AsyncUdpSocket for Batched {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn quinn::UdpPoller>> {
        Box::pin(RoomPoller(self))
    }

    fn try_send(&self, transmit: &quinn::udp::Transmit) -> io::Result<()> {
        let mut queue = self.queue.lock().unwrap();
        if queue.packets.len() >= MAX_BATCH {
            // A whole batch still queued is one the socket would not take; see
            // `MAX_BATCH`. quinn waits on `create_io_poller`'s poller, which is
            // ready again once there is room. Not the inner socket's: nothing
            // is sent through that, so it would always say writable, and quinn
            // would retry without ever yielding.
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let mut contents = queue.spare.pop().unwrap_or_default();
        contents.clear();
        contents.extend_from_slice(transmit.contents);
        queue.packets.push_back(Packet {
            destination: transmit.destination,
            ecn: transmit.ecn,
            src_ip: transmit.src_ip,
            segment_size: transmit.segment_size,
            contents,
        });
        let full = queue.packets.len() >= MAX_BATCH;
        drop(queue);
        if full {
            // A whole batch has no reason to wait for the turn to end.
            self.flush();
        }
        Ok(())
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [io::IoSliceMut<'_>],
        meta: &mut [quinn::udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        self.inner.poll_recv(cx, bufs, meta)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        self.inner
            .max_transmit_segments()
            .min(self.max_gso_segments.load(Ordering::Relaxed))
    }

    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}

/// Room for the control messages one packet carries, as in `quinn-udp`.
const CONTROL_LEN: usize = 88;

/// A control buffer aligned for `cmsghdr`.
#[derive(Clone, Copy)]
#[repr(align(8))]
struct Control([u8; CONTROL_LEN]);

/// Sends `packets` with one `sendmmsg`, returning how many went.
///
/// An error is about the first packet: the kernel reports one only when it
/// sent none, and otherwise the count of those before it.
///
/// Each message is built as `quinn-udp`'s `prepare_msg` builds one, so a packet
/// goes out exactly as quinn would have sent it alone.
///
/// Allocates nothing: what the headers point into is on the stack, sized for
/// [`MAX_BATCH`], about 20KB of it.
#[allow(
    unsafe_code,
    reason = "`sendmmsg` and its control messages have no safe wrapper in `std` or `socket2`"
)]
fn sendmmsg(
    socket: &std::net::UdpSocket,
    packets: &[Packet],
    sendmsg_einval: bool,
) -> io::Result<usize> {
    use std::mem::MaybeUninit;
    use std::os::fd::AsRawFd;

    debug_assert!(packets.len() <= MAX_BATCH);
    let packets = &packets[..packets.len().min(MAX_BATCH)];

    // Everything a header points into, filled first and never moved after,
    // so the pointers taken below stay valid.
    let mut names = [const { MaybeUninit::<socket2::SockAddr>::uninit() }; MAX_BATCH];
    let mut iovecs = [libc::iovec {
        iov_base: std::ptr::null_mut(),
        iov_len: 0,
    }; MAX_BATCH];
    let mut controls = [Control([0; CONTROL_LEN]); MAX_BATCH];
    // SAFETY: `mmsghdr` is a plain C struct, for which zero is a valid value
    // (null pointers, zero lengths).
    let mut headers: [libc::mmsghdr; MAX_BATCH] = unsafe { std::mem::zeroed() };

    for (i, packet) in packets.iter().enumerate() {
        let name = names[i].write(socket2::SockAddr::from(packet.destination));
        iovecs[i] = libc::iovec {
            iov_base: packet.contents.as_ptr() as *mut libc::c_void,
            iov_len: packet.contents.len(),
        };
        let hdr = &mut headers[i].msg_hdr;
        // `sendmmsg` does not write through the name; it is `*mut` only
        // because `recvmmsg` shares the type.
        hdr.msg_name = name.as_ptr() as *mut libc::c_void;
        hdr.msg_namelen = name.len();
        hdr.msg_iov = &mut iovecs[i];
        hdr.msg_iovlen = 1;
        hdr.msg_control = controls[i].0.as_mut_ptr().cast();
        hdr.msg_controllen = CONTROL_LEN as _;
        // SAFETY: `hdr` points at a zeroed control buffer of `CONTROL_LEN`
        // bytes, which holds the three messages below with room to spare (as
        // `quinn-udp` sizes it), and `controls[i]` outlives `hdr`.
        let used = unsafe { encode_control(hdr, packet, sendmsg_einval) };
        hdr.msg_controllen = used as _;
    }

    loop {
        // SAFETY: the first `packets.len()` headers point into `names`,
        // `iovecs`, `controls` and `packets`, all alive and unmoved until this
        // returns.
        let sent = unsafe {
            libc::sendmmsg(
                socket.as_raw_fd(),
                headers.as_mut_ptr(),
                packets.len() as _,
                0,
            )
        };
        if sent >= 0 {
            return Ok(sent as usize);
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

/// Writes `packet`'s control messages into `hdr`'s control buffer, returning
/// how many bytes they took: ECN, the source address, and the GSO segment size.
///
/// # Safety
///
/// `hdr.msg_control` must point at `hdr.msg_controllen` zeroed bytes, aligned
/// for `cmsghdr` and large enough for all three.
#[allow(unsafe_code, reason = "see `sendmmsg`")]
unsafe fn encode_control(hdr: &mut libc::msghdr, packet: &Packet, sendmsg_einval: bool) -> usize {
    let mut encoder = Encoder {
        // SAFETY: per this function's contract.
        cmsg: unsafe { libc::CMSG_FIRSTHDR(hdr) },
        hdr,
        len: 0,
    };

    // As `quinn-udp`: an IPv4 destination, mapped or not, takes `IP_TOS`, and
    // anything else `IPV6_TCLASS`. Sent even without ECN, as zero.
    let ecn = packet.ecn.map_or(0, |ecn| ecn as u8 as libc::c_int);
    let ipv4 = match packet.destination.ip() {
        IpAddr::V4(_) => true,
        IpAddr::V6(ip) => ip.to_ipv4_mapped().is_some(),
    };
    // SAFETY: room for each, per this function's contract.
    unsafe {
        if ipv4 {
            // Unless a send has failed with `EINVAL`, after which this is the
            // argument left out.
            if !sendmsg_einval {
                encoder.push(libc::IPPROTO_IP, libc::IP_TOS, ecn);
            }
        } else {
            encoder.push(libc::IPPROTO_IPV6, libc::IPV6_TCLASS, ecn);
        }

        // As `quinn-udp`, not for one segment: some drivers refuse GSO that
        // would not split anything.
        if let Some(segment_size) = packet
            .segment_size
            .filter(|segment_size| *segment_size < packet.contents.len())
        {
            encoder.push(libc::SOL_UDP, libc::UDP_SEGMENT, segment_size as u16);
        }

        match packet.src_ip {
            Some(IpAddr::V4(ip)) => encoder.push(
                libc::IPPROTO_IP,
                libc::IP_PKTINFO,
                libc::in_pktinfo {
                    ipi_ifindex: 0,
                    ipi_spec_dst: libc::in_addr {
                        s_addr: u32::from_ne_bytes(ip.octets()),
                    },
                    ipi_addr: libc::in_addr { s_addr: 0 },
                },
            ),
            Some(IpAddr::V6(ip)) => encoder.push(
                libc::IPPROTO_IPV6,
                libc::IPV6_PKTINFO,
                libc::in6_pktinfo {
                    ipi6_ifindex: 0,
                    ipi6_addr: libc::in6_addr {
                        s6_addr: ip.octets(),
                    },
                },
            ),
            None => {}
        }
    }
    encoder.len
}

/// Appends control messages to a `msghdr`'s control buffer.
struct Encoder<'a> {
    hdr: &'a libc::msghdr,
    cmsg: *mut libc::cmsghdr,
    len: usize,
}

impl Encoder<'_> {
    /// # Safety
    ///
    /// The control buffer must have room for this message after those before
    /// it.
    #[allow(unsafe_code, reason = "see `sendmmsg`")]
    unsafe fn push<T>(&mut self, level: libc::c_int, ty: libc::c_int, value: T) {
        assert!(!self.cmsg.is_null(), "control buffer too small");
        let size = size_of::<T>() as libc::c_uint;
        // SAFETY: `cmsg` is a header within the control buffer, with room for
        // `value` after it, per this function's contract.
        unsafe {
            (*self.cmsg).cmsg_level = level;
            (*self.cmsg).cmsg_type = ty;
            (*self.cmsg).cmsg_len = libc::CMSG_LEN(size) as _;
            std::ptr::write_unaligned(libc::CMSG_DATA(self.cmsg).cast::<T>(), value);
            self.len += libc::CMSG_SPACE(size) as usize;
            self.cmsg = libc::CMSG_NXTHDR(self.hdr, self.cmsg);
        }
    }
}
