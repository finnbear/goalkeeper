//! Whether the per-level byte ration actually holds a peer to it, over real
//! loopback TCP.
//!
//! # This needs a delayed loopback
//!
//! A receive window bounds bytes in flight, so the rate it permits is that
//! window over the round trip. On bare loopback the round trip is tens of
//! microseconds, so the window that would express any sane rate is smaller than
//! a segment and [`MIN_CLAMP`] floors it — at which point the kernel is no
//! longer rationing and only the application gate is, which is a different
//! thing to test. Give loopback a realistic delay and the clamp becomes the
//! rate limit it is meant to be.
//!
//! No root, and no interface the host uses is touched:
//!
//! ```text
//! cargo test --features tls --no-run
//! unshare -Urn sh -c 'ip link set lo up \
//!   && /sbin/tc qdisc add dev lo root netem delay 50ms \
//!   && target/debug/deps/throughput-<hash> --nocapture'
//! ```
//!
//! 50ms each way is the 100ms round trip this is written for. Without it the
//! test reports why and returns, rather than asserting something loopback
//! cannot demonstrate.
//!
//! A shorter delay is the sharper test. The conversion is the ration times
//! `rtt / window`, so at a round trip of exactly one window it is the identity
//! and a version that skipped it would pass anyway. `delay 10ms` is a fifth of
//! a window, where skipping it authorises five times the ration and this fails
//! by that much.
//!
//! [`MIN_CLAMP`]: https://docs.rs/goalkeeper

#![cfg(feature = "http")]

use goalkeeper::executor::priority::{Priority, UserPriority};
use goalkeeper::{ArcGoalkeeper, ProvideGoalkeeper};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Bytes per second the one level under test is allowed to receive.
///
/// Chosen so a 100ms round trip needs a window of `LIMIT / 10`, which is far
/// enough above the clamp's floor for the clamp to be what binds.
const LIMIT: u64 = 4 * 1024 * 1024;

/// Long enough to cross tens of ration windows, so a burst at the start is not
/// most of the measurement.
const RUN: Duration = Duration::from_secs(3);

/// Below this the clamp cannot express `LIMIT` and the test has nothing to say.
const NEEDS_RTT: Duration = Duration::from_millis(20);

/// What the client uploads, sized well over one window's ration so it is the
/// ration that paces it rather than the write size.
const CHUNK: usize = 256 * 1024;

/// Measures the round trip to `addr` the way a peer experiences it: connect,
/// then time a byte there and back.
async fn round_trip(addr: std::net::SocketAddr) -> Option<Duration> {
    let mut client = TcpStream::connect(addr).await.ok()?;
    client.set_nodelay(true).ok()?;
    let started = Instant::now();
    client.write_all(&[0u8; 1]).await.ok()?;
    let mut byte = [0u8; 1];
    client.read_exact(&mut byte).await.ok()?;
    Some(started.elapsed())
}

/// Echoes one byte, so a client can time a round trip against it.
async fn echo_once(listener: &TcpListener) {
    if let Ok((mut stream, _)) = listener.accept().await {
        let mut byte = [0u8; 1];
        if stream.read_exact(&mut byte).await.is_ok() {
            let _ = stream.write_all(&byte).await;
        }
    }
}

#[test]
fn a_peer_is_held_to_its_receive_ration() {
    let gk = ArcGoalkeeper::new();
    let driven = gk.clone();

    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(driven.run_until(async move {
            // One level, so the whole budget is this connection's and the
            // measurement is against `LIMIT` rather than a share of it.
            gk.set_bandwidth_limits(LIMIT, LIMIT);
            gk.set_bandwidth_floor(0.0);

            let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let probe_addr = probe.local_addr().unwrap();
            let (rtt, _) = tokio::join!(round_trip(probe_addr), echo_once(&probe));
            let Some(rtt) = rtt else {
                eprintln!("could not measure a round trip; skipping");
                return;
            };
            if rtt < NEEDS_RTT {
                eprintln!(
                    "loopback round trip is {rtt:?}, under the {NEEDS_RTT:?} this needs: \
                     a window expressing {LIMIT} B/s would be under the clamp's floor, so \
                     the kernel would not be the thing rationing. See the module docs for \
                     how to run this under a delayed loopback."
                );
                return;
            }

            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let stop = Arc::new(AtomicBool::new(false));
            let read = Arc::new(AtomicU64::new(0));

            // The server half: admit the connection through goalkeeper, then
            // read it as fast as it will go. `ConnIo` is what rations it.
            let server = {
                let stop = Arc::clone(&stop);
                let read = Arc::clone(&read);
                let gk = gk.clone();
                gk.clone()
                    .spawn(Priority::User(UserPriority::L0), async move {
                        let Ok((stream, peer)) = listener.accept().await else {
                            return;
                        };
                        let Some(permit) = gk.connection_permit(peer.ip(), "throughput test")
                        else {
                            return;
                        };
                        let (conn, killed) = goalkeeper::conn::Conn::new(peer, permit);
                        conn.set_base(Priority::User(UserPriority::L0));
                        let mut io = goalkeeper::conn::ConnIo::new(stream, conn, killed);
                        let mut buffer = vec![0u8; CHUNK];
                        while !stop.load(Ordering::Relaxed) {
                            match io.read(&mut buffer).await {
                                Ok(0) | Err(_) => break,
                                Ok(n) => {
                                    read.fetch_add(n as u64, Ordering::Relaxed);
                                }
                            }
                        }
                    })
            };

            // The client half: a plain socket, writing as hard as it can. It is
            // deliberately outside goalkeeper, so nothing but the receive
            // window slows it.
            let client = {
                let stop = Arc::clone(&stop);
                tokio::spawn(async move {
                    let Ok(mut stream) = TcpStream::connect(addr).await else {
                        return;
                    };
                    let chunk = vec![0u8; CHUNK];
                    while !stop.load(Ordering::Relaxed) {
                        if stream.write_all(&chunk).await.is_err() {
                            return;
                        }
                    }
                })
            };

            // Measured after a settling window, so the receive buffer the
            // kernel starts with is not counted as throughput.
            tokio::time::sleep(Duration::from_millis(500)).await;
            let from = read.load(Ordering::Relaxed);
            let started = Instant::now();
            tokio::time::sleep(RUN).await;
            let moved = read.load(Ordering::Relaxed) - from;
            let elapsed = started.elapsed();

            stop.store(true, Ordering::Relaxed);
            server.await;
            let _ = client.await;

            let rate = moved as f64 / elapsed.as_secs_f64();
            let ceiling = LIMIT as f64 * 1.5;
            eprintln!(
                "round trip {rtt:?}, {:.2} MB/s against a {:.2} MB/s ration",
                rate / 1e6,
                LIMIT as f64 / 1e6
            );
            assert!(
                moved > 0,
                "nothing arrived, so this measured a broken connection rather than a ration"
            );
            assert!(
                rate < ceiling,
                "a peer moved {:.2} MB/s against a {:.2} MB/s ration, so the receive window \
                 is not holding it: a per-window byte count handed to a flow-control limit \
                 authorises `window / rtt` times what was meant",
                rate / 1e6,
                LIMIT as f64 / 1e6
            );
        }));
}
