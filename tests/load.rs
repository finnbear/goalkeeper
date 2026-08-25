//! Synthetic load, entirely in memory.
//!
//! Every test here runs innocent traffic and hostile traffic side by side and
//! asserts the innocent traffic is unharmed, which is the whole claim of the
//! crate. The unit tests check one mechanism in isolation; these check what
//! happens under the load that mechanism was built for.
//!
//! No sockets are opened. Bytes move through `tokio::io::duplex`, connections
//! are `Conn`s over made-up addresses, and time is real but short, so the tests
//! are deterministic enough to assert on and fast enough to run always.
//!
//! The two shapes of attack:
//!
//! - **Frequency**: many peers each doing very little, very often. Cheap for
//!   the attacker, expensive for a scheduler, and invisible to any limit
//!   denominated in bytes.
//! - **Throughput**: few peers each moving as much as they can, which a
//!   frequency limit does not see at all.
//!
//! The limiters are process-wide, so tests that read them take [`serial`] and
//! run against the shipped defaults. Reconfiguring would leak between tests
//! whenever one failed.

use goalkeeper::conn::{Conn, ConnIo};
use goalkeeper::resource::bandwidth::Direction;
use goalkeeper::{ArcGoalkeeper, ProvideGoalkeeper, SystemGoalkeeper};

use goalkeeper::executor::priority::{Priority, UserPriority, UserPriority::*};
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Held by tests that read a process-wide ledger, so a concurrent test's bytes
/// cannot be mistaken for the traffic under examination.
static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    // A previous test panicking while holding this poisons it but leaves the
    // ledgers no more shared than they already are.
    SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Distinct per test, since the address limiter is process-wide and the tests
/// must not ration each other.
fn addr(block: u8, n: u16) -> SocketAddr {
    SocketAddr::new(
        IpAddr::from([10, block, (n >> 8) as u8, n as u8]),
        1024 + (n % 60000),
    )
}

/// `priority` is what the connection has established itself as, or `None` for a
/// stranger, which is where goalkeeper starts one and the one level a caller
/// cannot ask for by name.
fn conn(
    block: u8,
    n: u16,
    priority: Option<UserPriority>,
) -> (Conn, tokio::sync::oneshot::Receiver<()>) {
    let peer = addr(block, n);
    let permit = SystemGoalkeeper
        .connection_permit(peer.ip(), "load test")
        .expect("a fresh address is admitted");
    let (conn, killed) = Conn::new(peer, permit);
    if let Some(priority) = priority {
        conn.set_base(Priority::User(priority));
    }
    (conn, killed)
}

/// Runs `body` on a goalkeeper of its own, and a runtime of its own.
///
/// A brisk schedule, so a test crosses several windows in a few hundred
/// milliseconds rather than tens of seconds.
fn drive<F, Fut, T>(body: F) -> T
where
    F: FnOnce(ArcGoalkeeper) -> Fut,
    Fut: Future<Output = T>,
{
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let gk = ArcGoalkeeper::new();
    gk.set_schedule_window(Duration::from_millis(20));
    gk.set_aging_base(Duration::from_millis(5));
    let driven = gk.clone();
    runtime.block_on(driven.run_until(body(gk)))
}

/// How long an innocent client's round of work takes, with and without a flood
/// of hostile clients alongside it.
///
/// This is the headline claim: a player already in the game should not be able
/// to tell that the host is under attack.
#[test]
fn a_frequency_flood_does_not_slow_an_established_player() {
    /// Rounds of work the innocent client does.
    const ROUNDS: usize = 200;
    /// Hostile clients, each doing the cheapest possible thing as often as
    /// possible, which is the shape that costs an attacker nothing.
    const ATTACKERS: usize = 1000;

    async fn innocent_round_trip(gk: &ArcGoalkeeper) -> Duration {
        let started = Instant::now();
        for _ in 0..ROUNDS {
            gk.spawn(Priority::User(L0), async {
                tokio::task::yield_now().await;
            })
            .await;
        }
        started.elapsed()
    }

    let alone = drive(|gk| async move { innocent_round_trip(&gk).await });

    let (under_attack, hostile_polls) = drive(|gk| async move {
        let polls = Arc::new(AtomicUsize::new(0));
        for _ in 0..ATTACKERS {
            let polls = Arc::clone(&polls);
            // Never finishes, always ready: the worst case for a scheduler that
            // cannot choose what to poll.
            gk.spawn(Priority::New, async move {
                loop {
                    polls.fetch_add(1, Ordering::Relaxed);
                    tokio::task::yield_now().await;
                }
            })
            .detach();
        }
        let elapsed = innocent_round_trip(&gk).await;
        (elapsed, polls.load(Ordering::Relaxed))
    });

    assert!(
        hostile_polls > 0,
        "the flood never ran at all, so this proves nothing"
    );
    // Generous, because CI machines are noisy and the point is orders of
    // magnitude: a scheduler that walked the flood would be a thousand times
    // slower, not four.
    assert!(
        under_attack < alone * 4 + Duration::from_millis(50),
        "an established player was slowed by a flood of strangers: \
         {under_attack:?} against {alone:?} alone"
    );
}

/// Strangers must not be starved outright either: they have to make progress,
/// or handshakes never finish, permits are never released and the host spirals.
#[test]
fn a_flood_still_makes_progress_while_a_player_is_busy() {
    let served = drive(|gk| async move {
        let served = Arc::new(AtomicUsize::new(0));
        for _ in 0..200 {
            let served = Arc::clone(&served);
            gk.spawn(Priority::New, async move {
                served.fetch_add(1, Ordering::Relaxed);
            })
            .detach();
        }
        // A player keeps the good level permanently occupied.
        let busy = gk.spawn(Priority::User(L0), async {
            loop {
                tokio::task::yield_now().await;
            }
        });
        tokio::time::sleep(Duration::from_millis(300)).await;
        drop(busy);
        served.load(Ordering::Relaxed)
    });

    assert!(
        served > 0,
        "strict priority starved the strangers completely; aging did not fire"
    );
}

/// Throughput, not frequency: peers moving as much as they can.
///
/// The claim is that the ledger cuts the worst levels off first, so a player's
/// bytes are carried and a stranger's are not, rather than the two sharing the
/// shortfall as a limit without priorities would.
#[test]
fn a_throughput_flood_is_cut_off_before_a_player_is() {
    let _serial = serial();
    // Against the shipped defaults: 100MB/s over a 100ms window is a 10MB
    // budget, so the flood below is an order of magnitude past it.
    let budget = 10_000_000u64;

    let (player, _p) = conn(21, 1, Some(L0));
    let strangers: Vec<_> = (0..8).map(|n| conn(21, 100 + n, None)).collect();

    // The player moves a modest amount; the strangers move everything they can.
    player.record(Direction::Tx, budget / 100);
    for (stranger, _) in &strangers {
        stranger.record(Direction::Tx, budget);
    }

    let usage = SystemGoalkeeper.bandwidth_usage();
    let cutoff = usage.cutoff(Direction::Tx);
    assert!(
        Priority::User(L0) < cutoff,
        "the player was cut off at {cutoff:?} despite sending a hundredth of the budget"
    );
    assert!(Priority::New >= cutoff, "the flood was not cut off at all");
}

/// The same, through a real stream: bytes are counted where they actually move,
/// not where a caller remembers to report them.
#[tokio::test]
async fn bytes_are_counted_through_the_stream_itself() {
    // Real sockets, since `ConnIo` is concrete over `TcpStream`, which is what
    // lets it hand the ration to the kernel rather than enforce it by
    // withholding data.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (client, accepted) = tokio::join!(tokio::net::TcpStream::connect(addr), listener.accept());
    let (mut client, server) = (client.unwrap(), accepted.unwrap().0);
    let (conn, killed) = conn(22, 1, Some(L0));
    let mut io = ConnIo::new(server, conn.clone(), killed);

    let sent = Arc::new(AtomicU64::new(0));
    let writer = {
        let sent = Arc::clone(&sent);
        tokio::spawn(async move {
            let payload = vec![0u8; 4096];
            for _ in 0..16 {
                client.write_all(&payload).await.unwrap();
                sent.fetch_add(payload.len() as u64, Ordering::Relaxed);
            }
            drop(client);
        })
    };

    let mut drained = 0u64;
    let mut buf = vec![0u8; 8192];
    loop {
        match io.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(read) => drained += read as u64,
        }
    }
    writer.await.unwrap();

    let (_, rx) = conn.bytes();
    assert_eq!(drained, sent.load(Ordering::Relaxed));
    assert_eq!(rx, drained, "the connection counted exactly what it read");
}

/// A connection-rate flood from one address, against innocent clients arriving
/// from their own.
///
/// Frequency again, but at the connection layer rather than the poll layer:
/// what an attacker with a small botnet and a large socket budget does.
#[test]
fn a_connection_flood_from_one_address_is_refused_while_others_get_through() {
    let _serial = serial();
    let hostile = IpAddr::from([10, 30, 0, 1]);
    let mut admitted = Vec::new();
    let mut refused = 0;
    for _ in 0..200 {
        match SystemGoalkeeper.connection_permit(hostile, "flood") {
            Some(permit) => admitted.push(permit),
            None => refused += 1,
        }
    }
    assert!(
        refused > admitted.len(),
        "one address opened {} connections and was refused only {refused} times",
        admitted.len()
    );

    // Meanwhile, innocent clients from their own addresses are unaffected.
    let mut innocents = Vec::new();
    for n in 0..50u16 {
        if let Some(permit) = SystemGoalkeeper
            .connection_permit(IpAddr::from([10, 31, (n >> 8) as u8, n as u8]), "client")
        {
            innocents.push(permit);
        }
    }
    assert_eq!(
        innocents.len(),
        50,
        "innocent clients were shed alongside the flood"
    );
}

/// A slow-handshake flood: sockets that start a handshake and then dawdle,
/// which costs an attacker almost nothing and would otherwise hold the pool
/// open indefinitely.
#[test]
fn a_slow_handshake_flood_cannot_hold_the_pool() {
    let _serial = serial();
    let start = Instant::now();
    let hostile = IpAddr::from([10, 40, 0, 1]);

    // The attacker opens handshakes and never finishes them, staggered so each
    // has gone slow by the time the next arrives. Its own slots are held, but
    // being evicted is invisible from here. What matters is whether the pool
    // is still usable, which is what the next block asks.
    let _held: Vec<_> = (0..50u64)
        .filter_map(|n| {
            SystemGoalkeeper.handshake_slot(hostile, start + Duration::from_secs(n * 2))
        })
        .collect();

    // Held, not dropped: releasing each before asking for the next would make
    // this pass no matter how the pool behaved.
    let innocents: Vec<_> = (0..16u8)
        .filter_map(|n| {
            SystemGoalkeeper.handshake_slot(
                IpAddr::from([10, 41, 0, n]),
                start + Duration::from_secs(100),
            )
        })
        .collect();
    assert_eq!(
        innocents.len(),
        16,
        "innocent handshakes were refused because one address was dawdling"
    );
}

/// An address that has proved it carries many sessions gets more bandwidth than
/// one that has not: the NAT case, which a flat per-address limit gets wrong.
#[test]
fn a_busy_address_is_allowed_more_than_a_bare_one() {
    let _serial = serial();
    // Defaults: 500KB/s with a 1MB burst, widened by one allowance per active
    // session. Ten sessions therefore buy eleven times the room.
    let bare = IpAddr::from([10, 50, 0, 1]);
    let busy = IpAddr::from([10, 50, 0, 2]);
    let sessions: Vec<_> = (0..10)
        .map(|_| SystemGoalkeeper.active_session(busy))
        .collect();

    // Sent as traffic rather than as one number, because a token bucket always
    // admits the first spend and charges it forward, so one big record would
    // say nothing about either address.
    //
    // Three megabytes each: past a bare address's burst, comfortably inside a
    // busy one's.
    for _ in 0..10 {
        SystemGoalkeeper.record_address_bandwidth(bare, Direction::Rx, 300_000);
        SystemGoalkeeper.record_address_bandwidth(busy, Direction::Rx, 300_000);
    }

    assert!(
        SystemGoalkeeper.address_over_bandwidth(bare, Direction::Rx),
        "a lone address well over its allowance was not throttled"
    );
    assert!(
        !SystemGoalkeeper.address_over_bandwidth(busy, Direction::Rx),
        "an address with ten sessions was held to one session's allowance"
    );

    drop(sessions);
}

/// A loop that cannot get back to its schedule reports itself as under CPU
/// pressure, without anyone being asked.
///
/// Deliberately end to end: the arithmetic has unit tests, but they cannot say
/// whether the probe is wired to a clock that actually moves. This blocks the
/// dispatch loop outright, which is the one thing goalkeeper's own rationing
/// cannot prevent, and asks whether that became visible.
#[test]
fn a_blocked_loop_becomes_cpu_pressure_on_its_own() {
    let _serial = serial();

    // Read from the instance being driven, which is the one the probe reports
    // to. Rises rather than crosses a threshold, because smoothing moves it by
    // a fraction of the lateness rather than to it.
    let (before, after) = drive(|gk| async move {
        let before = gk.internal_pressure().cpu;
        gk.spawn(Priority::User(L0), async {
            // Not `tokio::time::sleep`: sleeping yields, and a loop that yields
            // is a loop that is keeping up. Occupying the thread is the case
            // that matters and the case a percentage of whole-machine CPU would
            // report as nearly idle.
            std::thread::sleep(Duration::from_millis(300));
        })
        .await;
        // Lets the loop come back around so the probe is polled and can notice
        // how late it now is.
        tokio::time::sleep(Duration::from_millis(50)).await;
        (before, gk.internal_pressure().cpu)
    });

    assert!(
        after > before + 0.5,
        "300ms of a blocked loop went unnoticed: {before:.2} -> {after:.2}"
    );
}

/// A lease is charged the moment it is granted, not when it is spent.
///
/// Without that, a connection holding an unspent lease is invisible: every
/// other connection computes its allowance as though that capacity were free,
/// and the level as a whole overshoots its ration by one lease per connection.
/// With eight busy connections that was a quarter of the budget.
#[test]
///
/// Also the one test here that owns its goalkeeper outright, which is what
/// instances are for. It needs a *tight* budget to lease against, and setting
/// one on the process's would leave every sibling measuring a link a hundredth
/// of the size they were written for. It used to restore the limits afterwards
/// and got that wrong, restoring a value that was not the shipped default, so a
/// sibling failed and blamed the ledger. An instance removes that failure mode,
/// and needs no [`serial`] since there is nothing here to share.
fn an_unspent_lease_is_already_charged() {
    let gk = ArcGoalkeeper::new();
    gk.set_bandwidth_limits(1_000_000, 1_000_000);

    let peer = addr(23, 1);
    let permit = gk
        .connection_permit(peer.ip(), "load test")
        .expect("a fresh instance admits");
    let (holder, _h) = Conn::new(peer, permit);
    holder.set_base(Priority::User(L0));

    // Rolls the window before measuring: `ration` rolls, `usage` only reads.
    std::thread::sleep(gk.bandwidth_window() + Duration::from_millis(20));
    let _ = holder.ration(Direction::Tx);
    let before = gk
        .bandwidth_usage()
        .moved(Direction::Tx, Priority::User(L0));

    // Takes a lease and spends none of it.
    let waker = futures_util::task::noop_waker();
    let mut cx = std::task::Context::from_waker(&waker);
    let grant = holder
        .lease(Direction::Tx, &mut cx)
        .expect("an idle link leases");
    assert!(grant.bytes > 0);

    let after = gk
        .bandwidth_usage()
        .moved(Direction::Tx, Priority::User(L0));
    assert_eq!(
        after - before,
        grant.bytes,
        "the ledger did not see the lease until it was spent"
    );
}

/// Admits a connection to `gk`, optionally already established.
fn admitted(
    gk: &ArcGoalkeeper,
    block: u8,
    n: u16,
    priority: Option<UserPriority>,
) -> (Conn<ArcGoalkeeper>, tokio::sync::oneshot::Receiver<()>) {
    let peer = addr(block, n);
    let permit = gk
        .connection_permit(peer.ip(), "load test")
        .expect("a fresh instance admits");
    let (conn, killed) = Conn::new(peer, permit);
    if let Some(priority) = priority {
        conn.set_base(Priority::User(priority));
    }
    (conn, killed)
}

/// A flood cannot take the RAM an established player has not asked for yet.
///
/// The throughput claim, for the other scarce thing. A refused byte is never
/// sent, but a refused allocation reclaims nothing, so a flood that got in first
/// would hold what it took until it chose to let go. The premium pool being
/// served best-first is what stops that.
///
/// Its own instance, because a tight limit is the whole point and setting one
/// on the process's would leave every sibling test measuring a budget a
/// thousandth of the size they were written for.
#[test]
fn a_flood_cannot_take_the_ram_a_player_has_not_claimed() {
    const CHUNK: u64 = 64 * 1024;

    let gk = ArcGoalkeeper::new();
    gk.set_memory_limit(16 * 1024 * 1024);

    // A flood of strangers reserves everything it can get.
    let strangers: Vec<_> = (0..64).map(|n| admitted(&gk, 24, 100 + n, None)).collect();
    let mut taken = Vec::new();
    'flood: loop {
        for (stranger, _) in &strangers {
            match stranger.try_reserve(CHUNK) {
                Some(reservation) => taken.push(reservation),
                None => break 'flood,
            }
        }
    }
    assert!(
        !taken.is_empty(),
        "the flood reserved nothing, so this proves nothing"
    );

    // A player arrives afterwards and still gets a real amount of memory.
    let (player, _p) = admitted(&gk, 24, 1, Some(L0));
    let mut player_took = Vec::new();
    for _ in 0..16 {
        let Some(reservation) = player.try_reserve(CHUNK) else {
            break;
        };
        player_took.push(reservation);
    }
    assert_eq!(
        player_took.len(),
        16,
        "a flood of strangers denied an established player its buffers"
    );

    // The limit is a limit, whoever is asking.
    let usage = gk.memory_usage();
    assert!(
        usage.held_total() <= usage.limit(),
        "the ledger authorised {} against a limit of {}",
        usage.held_total(),
        usage.limit()
    );

    // And releasing gives it back to the level that was holding it.
    let before = gk.memory_usage().held(Priority::User(L0));
    drop(player_took);
    let after = gk.memory_usage().held(Priority::User(L0));
    assert_eq!(
        before - after,
        16 * CHUNK,
        "released memory did not return to the level holding it"
    );
}

/// Memory follows a connection when it stops being a stranger, under load.
///
/// The unit test proves one reservation moves. This proves the accounting stays
/// consistent when many move at once: nothing lost, nothing duplicated, nothing
/// left behind at the level the connection was admitted at.
#[test]
fn established_players_do_not_leave_their_ram_with_the_strangers() {
    const CHUNK: u64 = 32 * 1024;
    const CLIENTS: u16 = 32;

    let gk = ArcGoalkeeper::new();
    gk.set_memory_limit(64 * 1024 * 1024);

    let mut conns = Vec::new();
    let mut reservations = Vec::new();
    for n in 0..CLIENTS {
        let (conn, killed) = admitted(&gk, 25, n, None);
        reservations.push(conn.try_reserve(CHUNK).expect("an idle ledger admits"));
        conns.push((conn, killed));
    }

    assert_eq!(
        gk.memory_usage().held(Priority::New),
        CLIENTS as u64 * CHUNK,
        "strangers' reservations were not charged to strangers"
    );

    // Every one of them authenticates.
    for (conn, _) in &conns {
        conn.set_base(Priority::User(L0));
    }

    let usage = gk.memory_usage();
    assert_eq!(
        usage.held(Priority::New),
        0,
        "established players left their memory booked against strangers"
    );
    assert_eq!(
        usage.held(Priority::User(L0)),
        CLIENTS as u64 * CHUNK,
        "memory was lost or duplicated in the move"
    );
    assert_eq!(
        usage.held_total(),
        CLIENTS as u64 * CHUNK,
        "the move left bytes at some third level"
    );

    // Dropping releases from where they ended up, not where they started.
    drop(reservations);
    assert_eq!(
        gk.memory_usage().held_total(),
        0,
        "releasing after a re-levelling left the ledger overdrawn"
    );
}
