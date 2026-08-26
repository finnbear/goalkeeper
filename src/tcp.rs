//! TCP options worth setting on a socket, whoever opened it.
//!
//! Everything else in this crate is about connections goalkeeper admitted and
//! rations. This is not: a peer that vanishes without saying so is the same
//! problem on a connection the process dialled out on, and the option that
//! notices is the same one.

use socket2::{SockRef, TcpKeepalive};
use std::time::Duration;
use tokio::net::TcpStream;

/// Enables TCP keepalive, so a peer that vanishes is noticed in seconds rather
/// than whenever the OS gets around to it.
///
/// `idle` is both how long the connection may go quiet before the first probe
/// and how long between probes after that; `retries` is how many go unanswered
/// before the connection is declared dead. Worst case, a dead peer is noticed
/// after `idle * (retries + 1)`.
///
/// Worth setting on any long-lived socket that is mostly idle, where the
/// default is minutes or hours and the process spends all of it believing the
/// peer is still there.
///
/// Windows has no per-socket probe count, so `retries` is ignored there.
pub fn keepalive(stream: &TcpStream, idle: Duration, retries: u32) -> std::io::Result<()> {
    #[cfg_attr(windows, allow(unused_mut))]
    let mut params = TcpKeepalive::new().with_time(idle).with_interval(idle);
    #[cfg(windows)]
    {
        let _ = retries;
    }
    #[cfg(not(windows))]
    {
        params = params.with_retries(retries);
    }
    SockRef::from(stream).set_tcp_keepalive(&params)
}
