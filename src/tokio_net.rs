//! Networking DoS mitigation utilities.

use log::error;
use socket2::{SockRef, TcpKeepalive};
use std::time::Duration;
use tokio::net::TcpStream;

/// Configure TCP keepalive on a `TcpStream`, which helps dead connections get
/// expired rather than lingering for minutes or hours. Also enables `TCP_NODELAY`.
pub fn nodelay_keepalive(stream: &TcpStream, seconds: u64, retries: u32) {
    if let Err(e) = stream.set_nodelay(true) {
        error!("failed to set TCP nodelay: {e}");
    }

    // If I made a mistake and this doesn't work on windows, just remove it ;)
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
