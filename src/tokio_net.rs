//! Networking DoS mitigation utilities.
//!
//! [`pace`] and [`clamp_receive_window`] hand the rationing to the kernel,
//! which spaces packets out evenly instead of making the application the
//! buffer. Both are Linux only and both report whether they took, so a caller
//! can keep the portable path when they do not.

use log::error;
#[cfg(feature = "http")]
use socket2::{SockRef, TcpKeepalive};
use std::time::Duration;
use tokio::net::TcpStream;

/// Paces this connection's egress at `bytes_per_second`, in the kernel.
///
/// `SO_MAX_PACING_RATE`, applied per socket by the fair-queue scheduler. Zero
/// means unpaced, following the kernel's own convention.
///
/// Returns whether it took. It will not without fair queueing available, nor on
/// any platform but Linux.
#[allow(
    unsafe_code,
    reason = "`setsockopt` has no safe wrapper in `std` or `socket2`"
)]
pub fn pace(stream: &TcpStream, bytes_per_second: u64) -> bool {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        // The option is a `u32` of bytes per second, and past 4GB/s "unpaced"
        // is the only sensible reading.
        let rate = bytes_per_second.min(u32::MAX as u64) as u32;
        // SAFETY: a valid fd for the duration of the call, and a correctly
        // sized and aligned value for this option.
        let set = unsafe {
            libc::setsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_MAX_PACING_RATE,
                std::ptr::from_ref(&rate).cast(),
                size_of_val(&rate) as libc::socklen_t,
            )
        };
        set == 0
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (stream, bytes_per_second);
        false
    }
}

/// Holds this connection's *advertised* receive window to `bytes`, so the peer
/// slows at the source.
///
/// `TCP_WINDOW_CLAMP`, the ingress counterpart of [`pace`]. Tells the peer up
/// front how much it may have outstanding, rather than waiting for the socket
/// buffer to fill.
///
/// Returns whether it took; see [`pace`].
#[allow(
    unsafe_code,
    reason = "`setsockopt` has no safe wrapper in `std` or `socket2`"
)]
pub fn clamp_receive_window(stream: &TcpStream, bytes: u32) -> bool {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        // Below a segment the connection stalls rather than slows.
        let clamp = bytes.max(1_200);
        // SAFETY: as in `pace`.
        let set = unsafe {
            libc::setsockopt(
                stream.as_raw_fd(),
                libc::IPPROTO_TCP,
                libc::TCP_WINDOW_CLAMP,
                std::ptr::from_ref(&clamp).cast(),
                size_of_val(&clamp) as libc::socklen_t,
            )
        };
        set == 0
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (stream, bytes);
        false
    }
}

/// This connection's smoothed round trip, as the kernel measures it.
///
/// What turns a rate into a window: a flow-control limit bounds bytes in
/// flight, so the rate it permits is the limit over the round trip. See
/// [`crate::resource::bandwidth::flight`].
///
/// [`None`] before the kernel has a measurement, on a connection with no
/// samples yet, and on any platform but Linux. A caller with no round trip
/// cannot size a window and should ration in the application instead.
#[allow(
    unsafe_code,
    reason = "`getsockopt` has no safe wrapper in `std` or `socket2`"
)]
pub fn round_trip(stream: &TcpStream) -> Option<Duration> {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        let mut info: libc::tcp_info = unsafe { std::mem::zeroed() };
        let mut len = size_of_val(&info) as libc::socklen_t;
        // SAFETY: a valid fd, and a correctly sized destination for this
        // option, whose length is passed by reference as `getsockopt` requires.
        let read = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::IPPROTO_TCP,
                libc::TCP_INFO,
                std::ptr::from_mut(&mut info).cast(),
                &mut len,
            )
        };
        // Zero means no sample yet rather than an instant link, and dividing a
        // rate by it would authorise everything.
        (read == 0 && info.tcpi_rtt > 0).then(|| Duration::from_micros(u64::from(info.tcpi_rtt)))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = stream;
        None
    }
}

/// Turns Nagle's algorithm on or off for this connection.
///
/// Worth modulating rather than setting once: nodelay while unthrottled, so
/// input does not wait on a coalescing timer, and Nagle while throttled, since
/// coalescing is itself a reduction in what the peer sends.
pub fn set_nodelay(stream: &TcpStream, nodelay: bool) {
    if let Err(e) = stream.set_nodelay(nodelay) {
        error!("failed to set TCP nodelay: {e}");
    }
}

/// Enables `TCP_NODELAY` and configures TCP keepalive, so dead connections are
/// expired rather than lingering for minutes or hours.
#[cfg(feature = "http")]
pub fn nodelay_keepalive(stream: &TcpStream, seconds: u64, retries: u32) {
    if let Err(e) = stream.set_nodelay(true) {
        error!("failed to set TCP nodelay: {e}");
    }

    let sock_ref = SockRef::from(&stream);
    #[cfg_attr(windows, allow(unused_mut))]
    let mut params = TcpKeepalive::new()
        .with_time(Duration::from_secs(seconds))
        .with_interval(Duration::from_secs(seconds));
    #[cfg(windows)]
    {
        let _ = retries;
    }
    #[cfg(not(windows))]
    {
        params = params.with_retries(retries);
    }
    if let Err(e) = sock_ref.set_tcp_keepalive(&params) {
        error!("failed to set TCP keepalive: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn socket() -> TcpStream {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (client, _accepted) = tokio::join!(TcpStream::connect(addr), listener.accept());
        client.unwrap()
    }

    /// The kernel took the rate, and reports back the same one.
    ///
    /// Read back rather than trusting the return value, since `setsockopt` can
    /// succeed without the option meaning what was intended.
    #[tokio::test]
    #[cfg(target_os = "linux")]
    async fn a_pacing_rate_reaches_the_kernel() {
        use std::os::fd::AsRawFd;

        let stream = socket().await;
        assert!(pace(&stream, 125_000), "the kernel refused the rate");

        let mut got: u32 = 0;
        let mut len = size_of_val(&got) as libc::socklen_t;
        #[allow(unsafe_code, reason = "`getsockopt` has no safe wrapper either")]
        // SAFETY: a valid fd, and a correctly sized destination for this option.
        let read = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_MAX_PACING_RATE,
                std::ptr::from_mut(&mut got).cast(),
                &mut len,
            )
        };
        assert_eq!(read, 0, "could not read the pacing rate back");
        assert_eq!(got, 125_000, "the kernel kept a different rate");

        // Zero means unpaced, which is how a connection is released.
        assert!(pace(&stream, 0));
    }

    /// A clamp is accepted, including one below the floor, which is raised
    /// rather than refused.
    #[tokio::test]
    #[cfg(target_os = "linux")]
    async fn a_receive_window_clamp_is_accepted() {
        let stream = socket().await;
        assert!(clamp_receive_window(&stream, 64 * 1024));
        assert!(
            clamp_receive_window(&stream, 1),
            "a clamp under one segment should be raised, not refused"
        );
    }
}
