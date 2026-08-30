//! Rationing bytes, by priority and by address.
//!
//! Two independent limits. The **congestion limit** is global: the budget is
//! spent best levels first, and everything worse than the level it runs out at
//! stops being read. The **per-address allowance** is per IP and scales with
//! how many active sessions that address holds, so a carrier-grade NAT
//! presenting a hundred players is not held to one player's ration.
//!
//! # Backpressure, not refusal
//!
//! Nothing here returns a verdict for a caller to act on. Over its ration a
//! connection is simply not read: [`crate::conn::ConnIo`] returns `Pending` and
//! the peer's own flow control slows it at the source, dropping no bytes and
//! destroying no connection. On HTTP/2 that stalls writes too, since
//! `WINDOW_UPDATE` goes unseen; still throttling, but blunter than on HTTP/1.
//!
//! Killing is the escalation, for a connection still exceeding its ration
//! despite being unable to send. Optional; see
//! [`set_bandwidth_kill_after`][crate::Goalkeeper::set_bandwidth_kill_after].

use crate::conn::Conn;
use crate::executor::priority::Priority;
use crate::{Goalkeeper, ProvideGoalkeeper};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};

use std::task::{Context, Waker};
use std::time::{Duration, Instant};

/// Which way bytes went.
///
/// Rationed separately, since they are not chosen by the same party: `Rx` is
/// what the peer decided to send, `Tx` mostly what the application decided to
/// send it. Pooling the two would let ordinary egress drown out the upload
/// flood the limit is looking for, and let a peer be dropped for receiving what
/// it was sent.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Direction {
    /// Out, towards the peer.
    Tx,
    /// In, from the peer.
    Rx,
}

/// How bytes are rationed.
///
/// Set through [`Goalkeeper`]'s per-field setters rather than as a struct, so
/// changing one number cannot silently revert another.
#[derive(Copy, Clone, Debug)]
pub(crate) struct Config {
    /// Bytes per second out, before the process is considered congested.
    ///
    /// Not a hard cap on the link, but the point past which goalkeeper starts
    /// choosing whose bytes to carry. Set it a little under what the host can
    /// sustain, so the choosing happens here rather than in a queue below.
    pub max_tx_bytes_per_second: u64,
    /// As [`Self::max_tx_bytes_per_second`], for bytes in.
    ///
    /// Separate because links are: consumer uplinks and downlinks differ by an
    /// order of magnitude. One number for both would have to be the smaller,
    /// throttling the wider direction against a limit it never had.
    pub max_rx_bytes_per_second: u64,
    /// Fraction of the budget kept back for levels the better ones have
    /// crowded out, split evenly among them.
    ///
    /// Strict priority alone would leave every worse level with nothing, where
    /// a dead player's socket should still drain and a new connection should
    /// still finish its handshake. The same bargain the executor strikes for
    /// poll time with [`crate::executor::Config::override_budget`].
    ///
    /// Costs nothing when unneeded: a level short of the whole budget is
    /// allowed the unshared remainder too, so a link with one talker on it is
    /// not held to `1 - floor`.
    pub floor: f32,
    /// How long a ration lasts. Shorter reacts faster and parks for less time;
    /// longer tolerates burstier traffic.
    pub window: Duration,
    /// How long a connection may spend over its ration, while being throttled,
    /// before it is destroyed rather than merely slowed.
    ///
    /// [`None`] never kills, leaving backpressure as the only answer.
    pub kill_after: Option<Duration>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            // Most of the 40/1 Gbps a cheap VPS is typically allocated: 900
            // Mbps out and 32 Gbps in. Under the link rather than at it, since
            // the budget has to run out before the wire does. See
            // `Goalkeeper::set_bandwidth_limits`.
            //
            // Egress is the metered, scarce direction, so it is the one worth
            // dividing by priority. Ingress this wide effectively never
            // throttles, leaving inbound floods to the per-address allowance.
            max_tx_bytes_per_second: 112_500_000,
            max_rx_bytes_per_second: 4_000_000_000,
            floor: 0.1,
            window: Duration::from_millis(100),
            kill_after: Some(Duration::from_secs(5)),
        }
    }
}

/// How many windows fit in `span`, at least one.
fn windows_in(span: Duration, window: Duration) -> u32 {
    if window.is_zero() {
        return 1;
    }
    (span.as_nanos() / window.as_nanos()).max(1) as u32
}

/// Adjusts one configured variable, leaving the rest alone.
pub(crate) fn set_config(gk: &Goalkeeper, f: impl FnOnce(&mut Config)) {
    gk.limiter
        .with_process(|_, ledger, _| f(&mut ledger.config));
}

/// Records `bytes` moved in `dir` by `conn`.
///
/// Returns nothing: a caller checking a verdict every few bytes would be
/// deciding policy at the wrong granularity.
#[allow(
    dead_code,
    reason = "the public path is Conn::record; this is its shape for a caller that has no Conn"
)]
pub(crate) fn record<P: ProvideGoalkeeper>(conn: &Conn<P>, dir: Direction, bytes: u64) {
    record_raw(
        conn.provider(),
        conn.priority().level(),
        conn.ip(),
        dir,
        bytes,
    );
}

/// As [`record`], for a caller that has the level and address but no longer the
/// [`Conn`], such as its own destructor settling what it never reported.
#[allow(dead_code, reason = "settling without a Conn, kept beside settle_raw")]
pub(crate) fn record_raw(gk: &Goalkeeper, level: u8, ip: IpAddr, dir: Direction, bytes: u64) {
    let now = Instant::now();
    gk.limiter.with_process(|limiter, ledger, _| {
        let config = ledger.config;
        ledger.roll(gk, now, &config);
        let level = level as usize;
        match dir {
            Direction::Tx => ledger.tx[level] = ledger.tx[level].saturating_add(bytes),
            Direction::Rx => ledger.rx[level] = ledger.rx[level].saturating_add(bytes),
        }
        ledger.attributed(dir, bytes);

        // The per-address ration. Recorded rather than consulted; whether it
        // bites is asked on the read path, by `throttled`.
        limiter.record_bandwidth(ip, dir, bytes.min(u32::MAX as u64) as u32, now);
    });
}

/// Rolls the window if it is due, waking whatever is parked waiting for it.
///
/// Every other path into the ledger is driven by traffic, which suffices for
/// reads: a parked reader waits on a peer that is still sending. Writes have no
/// such guarantee, and with every connection parked on one, nothing would roll
/// the window and the process would wedge.
///
/// The executor calls this once per window. Rolling before the window is up
/// does nothing.
pub(crate) fn tick_of(gk: &Goalkeeper) {
    let now = Instant::now();
    gk.limiter.with_process(|_, ledger, _| {
        let config = ledger.config;
        ledger.roll(gk, now, &config);
    });
}

/// Bytes the whole process may move in `dir` in one window.
///
/// For a caller dividing that among connections rather than asking about one,
/// such as [`crate::web_transport`], which bounds a session before it has moved
/// anything and so has no ration to consult.
pub(crate) fn budget_per_window_of(gk: &Goalkeeper, dir: Direction) -> u64 {
    gk.limiter.with_process(|_, ledger, _| {
        let config = ledger.config;
        Ledger::budget(dir, &config)
    })
}

/// Bytes a connection may move, and the ledger entry they were charged to.
///
/// The level and window travel with the grant, since a connection may be
/// re-levelled and a window may roll before the lease is settled, and a
/// reservation can only be given back to the entry it was taken from.
#[derive(Copy, Clone, Debug, Default)]
pub struct Grant {
    /// How many bytes may be moved before asking again.
    pub bytes: u64,
    /// The level charged, as the ledger's own index. Callers read
    /// [`Self::priority`].
    pub(crate) level: u8,
    /// The window charged.
    pub epoch: u64,
}

impl Grant {
    /// The level this was charged to.
    pub fn priority(&self) -> Priority {
        Priority::from_level(self.level)
    }
}

/// Reports what a [`Grant`] was actually used for, and gives back the rest.
///
/// `moved` is what went over the wire, against what [`lease`] charged in
/// advance. The difference is refunded, so the ledger converges on the truth
/// rather than on the guess.
pub(crate) fn settle_raw(gk: &Goalkeeper, grant: Grant, ip: IpAddr, dir: Direction, moved: u64) {
    let now = Instant::now();
    gk.limiter.with_process(|limiter, ledger, _| {
        let config = ledger.config;
        ledger.roll(gk, now, &config);

        let at = (grant.level as usize).min(Priority::LEVELS - 1);
        let counts = match dir {
            Direction::Tx => &mut ledger.tx,
            Direction::Rx => &mut ledger.rx,
        };
        if ledger.epoch == grant.epoch {
            // Same window, so the reservation still stands; replace it with
            // what was moved.
            counts[at] = counts[at].saturating_sub(grant.bytes).saturating_add(moved);
        } else {
            // The window rolled and took the reservation with it. Nothing to
            // refund, and the bytes belong to the window they landed in.
            counts[at] = counts[at].saturating_add(moved);
        }

        // Only real bytes, never the reservation: this is reconciled against
        // the socket's own totals by subtraction, and a guess would skew it.
        ledger.attributed(dir, moved);

        // Likewise the per-address ration, which does its own forward charging.
        limiter.record_bandwidth(ip, dir, moved.min(u32::MAX as u64) as u32, now);
    });
}

/// Smallest lease worth the lock it costs to take.
const MIN_LEASE: u64 = 64;
/// Largest, so a connection cannot take a whole window's budget in one go and
/// leave its peers at the same level nothing until the refill.
///
/// Generous, since a lease also bounds how much one write may carry. What keeps
/// a lease small when it matters is the quarter-of-remaining above.
const MAX_LEASE: u64 = 64 * 1024;

/// How many bytes `conn` may move in `dir` before it must ask again, or `None`
/// if it may not move any.
///
/// A lease rather than a yes-or-no, since asking costs a lock. Its size comes
/// from what is left of the level's allowance, so it is generous on an idle
/// link and tight on a saturated one.
///
/// Registers `cx`'s waker against the next refill, so a caller may return
/// `Pending` rather than spin.
pub(crate) fn lease<P: ProvideGoalkeeper>(
    conn: &Conn<P>,
    dir: Direction,
    cx: &mut Context<'_>,
) -> Option<Grant> {
    let level = conn.priority().level();
    let now = Instant::now();

    enum Outcome {
        Lease(Grant),
        Throttle,
        Kill,
    }

    let outcome = conn.provider().limiter.with_process(|limiter, ledger, _| {
        let over_ip = limiter.over_bandwidth(conn.ip(), dir);
        let config = ledger.config;
        ledger.roll(conn.provider(), now, &config);
        let remaining = ledger.remaining(level, dir, &config);

        if !over_ip && remaining > 0 {
            if dir == Direction::Rx {
                conn.clear_strike();
            }
            // A quarter of what is left, so several connections at one level
            // interleave instead of the first taking everything.
            //
            // Capped at a sixteenth of the window's budget, so every busy
            // connection reports several times per window. Otherwise the ledger
            // sees one level's lump arrive while the others look idle and
            // throttles nobody.
            let cap = (Ledger::budget(dir, &config) / 16).max(MIN_LEASE);
            let bytes = (remaining / 4)
                .clamp(MIN_LEASE, MAX_LEASE)
                .min(remaining)
                .min(cap);

            // Charged now, not when spent. An unreported lease is capacity
            // nobody else can see, so with one outstanding per connection the
            // level as a whole would overshoot its ration by that much.
            // `settle_raw` gives back whatever went unused.
            let counts = match dir {
                Direction::Tx => &mut ledger.tx,
                Direction::Rx => &mut ledger.rx,
            };
            let at = (level as usize).min(Priority::LEVELS - 1);
            counts[at] = counts[at].saturating_add(bytes);

            return Outcome::Lease(Grant {
                bytes,
                level,
                epoch: ledger.epoch,
            });
        }

        // Strikes are about the peer ignoring backpressure, so they apply only
        // to what the peer sends. Being outranked on the uplink is goalkeeper's
        // own decision, and killing over it would disconnect a player for
        // traffic they never asked to be slowed.
        if dir == Direction::Rx
            && let Some(after) = config.kill_after
        {
            let windows = windows_in(after, config.window);
            if conn.strike(ledger.epoch) >= windows {
                // Unable to send for that long and still trying: not chatty,
                // abusive.
                return Outcome::Kill;
            }
        }

        ledger.wakers.push(cx.waker().clone());
        Outcome::Throttle
    });

    match outcome {
        Outcome::Lease(grant) => Some(grant),
        Outcome::Throttle => None,
        Outcome::Kill => {
            conn.kill();
            None
        }
    }
}

/// How long a ration lasts, for a caller pacing itself against one.
pub(crate) fn window_of(gk: &Goalkeeper) -> Duration {
    gk.limiter.with_process(|_, ledger, _| ledger.config.window)
}

/// Which window the ledger is in.
///
/// For a caller that reconfigures something once per window rather than once
/// per operation, such as a socket option whose syscall costs more than the
/// precision is worth.
pub(crate) fn epoch_of(gk: &Goalkeeper) -> u64 {
    let now = Instant::now();
    gk.limiter.with_process(|_, ledger, _| {
        let config = ledger.config;
        ledger.roll(gk, now, &config);
        ledger.epoch
    })
}

/// The rate the kernel should be told to hold this connection to: what
/// [`ration`] leaves it, spread over a [`window`], floored so that being
/// outranked slows a connection rather than stopping it.
///
/// Zero is not usable: `SO_MAX_PACING_RATE` reads it as unpaced, which would
/// release a throttled connection rather than restrain it.
pub(crate) fn paced_rate<P: ProvideGoalkeeper>(conn: &Conn<P>, dir: Direction) -> u64 {
    let window = window_of(conn.provider()).as_secs_f64();
    let remaining = ration(conn, dir);
    let rate = if window > 0.0 {
        (remaining as f64 / window) as u64
    } else {
        u64::MAX
    };
    rate.max(MIN_PACED_RATE)
}

/// The slowest a paced connection is ever held to: a segment per window at the
/// shipped cadence. Crawling, but not stopped.
pub(crate) const MIN_PACED_RATE: u64 = 12_000;

/// The bytes in flight that sustain `ration` per `window` over a link with this
/// `rtt`.
///
/// The bandwidth-delay product, and the only correct way to turn a rate into a
/// flow-control limit: such a limit bounds bytes outstanding, so the rate it
/// permits is itself over the round trip. Handing a per-window byte count
/// straight to one authorises `window / rtt` times what was meant, which for
/// any peer closer than a window is more than the ration rather than less.
///
/// Unbounded here. What a stalled connection looks like differs by transport,
/// so each caller clamps with its own floor and ceiling.
pub(crate) fn flight(ration: u64, window: Duration, rtt: Duration) -> u64 {
    let seconds = window.as_secs_f64();
    if seconds <= 0.0 {
        return u64::MAX;
    }
    let rate = ration as f64 / seconds;
    (rate * rtt.as_secs_f64()) as u64
}

/// The whole of `conn`'s level's allowance in `dir` this window, spent or not.
///
/// Distinct from [`ration`], which is what remains. For a caller sizing
/// something that should be stable across a window, such as a flow-control
/// window, which stalls in-flight data if it shrinks under it.
pub(crate) fn allowance<P: ProvideGoalkeeper>(conn: &Conn<P>, dir: Direction) -> u64 {
    let level = conn.priority().level();
    let now = Instant::now();
    conn.provider().limiter.with_process(|_, ledger, _| {
        let config = ledger.config;
        ledger.roll(conn.provider(), now, &config);
        ledger.allowance(level, dir, &config)
    })
}

/// What is left of `conn`'s level's ration in `dir` this window.
///
/// A read, not a claim: nothing is reserved and no waker is registered, so this
/// is for a caller that paces itself rather than being parked, such as
/// [`crate::web_transport`] handing the number to QUIC's flow control.
pub(crate) fn ration<P: ProvideGoalkeeper>(conn: &Conn<P>, dir: Direction) -> u64 {
    let level = conn.priority().level();
    let now = Instant::now();
    conn.provider().limiter.with_process(|_, ledger, _| {
        let config = ledger.config;
        ledger.roll(conn.provider(), now, &config);
        ledger.remaining(level, dir, &config)
    })
}

/// Whether `conn` should stop moving bytes in `dir` for now.
///
/// [`lease`] without the credit, for a caller that does not want to track one.
#[allow(
    dead_code,
    reason = "lease without the credit, for a caller that wants no lease"
)]
pub(crate) fn throttled<P: ProvideGoalkeeper>(
    conn: &Conn<P>,
    dir: Direction,
    cx: &mut Context<'_>,
) -> bool {
    lease(conn, dir, cx).is_none()
}

/// Records wire bytes seen at a shared socket, which may or may not belong to a
/// connection goalkeeper knows about.
///
/// For QUIC, where one UDP socket carries every connection. Established
/// connections report their own bytes exactly, so this is for the remainder:
/// handshake floods, spoofed sources, and packets for connections that do not
/// exist, which nothing else can see.
///
/// The remainder is this total minus what connections reported, so the two are
/// subtracted rather than added and cannot double count.
#[cfg(feature = "web_transport")]
pub(crate) fn record_socket_total_of(gk: &Goalkeeper, dir: Direction, total: u64) {
    let now = Instant::now();
    gk.limiter
        .with_process(|_, inner, _| inner.record_socket_total(gk, dir, total, now));
}

/// What the ledger has seen this window, for whoever reports on the process.
///
/// Read through the methods below rather than as arrays, so a report is written
/// in terms of [`Priority`]. See [`crate::executor::Tasks`].
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct Usage {
    tx: [u64; Priority::LEVELS],
    rx: [u64; Priority::LEVELS],
    cutoff_tx: u8,
    cutoff_rx: u8,
}

impl Usage {
    /// Bytes moved in `dir` at `priority` this window.
    pub fn moved(&self, dir: Direction, priority: Priority) -> u64 {
        self.counts(dir)[priority.level() as usize]
    }

    /// Bytes moved in `dir` this window, at every level together.
    pub fn moved_total(&self, dir: Direction) -> u64 {
        self.counts(dir).iter().sum()
    }

    /// Bytes moved in `dir` this window, level by level, most urgent first.
    ///
    /// Every level is yielded, including empty ones.
    pub fn moved_by_priority(&self, dir: Direction) -> impl Iterator<Item = (Priority, u64)> + '_ {
        self.counts(dir)
            .iter()
            .enumerate()
            .map(|(level, &bytes)| (Priority::from_level(level as u8), bytes))
    }

    /// The worst level still permitted to move bytes in `dir`.
    ///
    /// Everything better than this is being served, everything worse held back.
    /// Compare with [`Ord`] rather than arithmetic.
    pub fn cutoff(&self, dir: Direction) -> Priority {
        Priority::from_level(match dir {
            Direction::Tx => self.cutoff_tx,
            Direction::Rx => self.cutoff_rx,
        })
    }

    fn counts(&self, dir: Direction) -> &[u64; Priority::LEVELS] {
        match dir {
            Direction::Tx => &self.tx,
            Direction::Rx => &self.rx,
        }
    }
}

/// See [`crate::ProvideGoalkeeper::bandwidth_usage`].
pub(crate) fn usage_of(gk: &Goalkeeper) -> Usage {
    gk.limiter.with_process(|_, inner, _| {
        let config = inner.config;
        Usage {
            tx: inner.tx,
            rx: inner.rx,
            cutoff_tx: inner.cutoff(Direction::Tx, &config),
            cutoff_rx: inner.cutoff(Direction::Rx, &config),
        }
    })
}

/// The process's byte accounting.
///
/// Not behind a lock of its own: it lives inside [`crate::ip_limiter`]'s, since
/// every question worth asking of one is asked of the other in the same breath.
pub(crate) struct Ledger {
    /// Kept here rather than behind a lock of its own. Two mutexes meant two
    /// acquisitions per read and write, and an ABBA deadlock between `record`
    /// and `throttled`, which took them in opposite orders.
    config: Config,
    started: Option<Instant>,
    epoch: u64,
    tx: [u64; Priority::LEVELS],
    rx: [u64; Priority::LEVELS],
    /// The socket meter's last reading, which counts for the socket's life
    /// rather than for a window. Deliberately not cleared by [`Self::roll`]:
    /// it is the baseline the next sample's delta is taken against.
    socket_tx: u64,
    socket_rx: u64,
    /// Bytes seen at the shared socket this window, accumulated from those
    /// deltas. This is the per-window figure `attributed_*` is comparable to.
    wire_tx: u64,
    wire_rx: u64,
    attributed_tx: u64,
    attributed_rx: u64,
    /// Woken when the ration refills. Bounded by the number of connections
    /// actually being throttled.
    wakers: Vec<Waker>,
}

impl Default for Ledger {
    fn default() -> Self {
        Self {
            config: Config::default(),
            started: None,
            epoch: 1,
            tx: [0; Priority::LEVELS],
            rx: [0; Priority::LEVELS],
            socket_tx: 0,
            socket_rx: 0,
            wire_tx: 0,
            wire_rx: 0,
            attributed_tx: 0,
            attributed_rx: 0,
            wakers: Vec::new(),
        }
    }
}

impl Ledger {
    fn attributed(&mut self, dir: Direction, bytes: u64) {
        match dir {
            Direction::Tx => self.attributed_tx = self.attributed_tx.saturating_add(bytes),
            Direction::Rx => self.attributed_rx = self.attributed_rx.saturating_add(bytes),
        }
    }

    /// See [`record_socket_total`], whose body this is. Split out so a test can
    /// drive it with a clock of its own: the free function reaches for the
    /// process-wide ledger and the wall clock, and the property worth asserting
    /// is about what happens *across* a window boundary.
    #[cfg_attr(not(feature = "web_transport"), allow(dead_code))]
    fn record_socket_total(&mut self, gk: &Goalkeeper, dir: Direction, total: u64, now: Instant) {
        let config = self.config;
        self.roll(gk, now, &config);
        // `total` counts the socket's whole life, while everything else here is
        // one window, so what this window carried is the growth since the last
        // sample. Comparing the lifetime figure against a per-window one
        // instead leaves a remainder that only ever grows, which reads as a
        // link permanently many times over its budget.
        //
        // Sampling runs at the window's own cadence, so a delta is about one
        // window's traffic and is credited to whichever window observes it.
        // That is a phase lag of at most one window, not an error in how much:
        // the bytes are counted once, against a budget of the same length.
        let (wire, attributed) = match dir {
            Direction::Tx => {
                let since = total.saturating_sub(self.socket_tx);
                self.socket_tx = total;
                self.wire_tx = self.wire_tx.saturating_add(since);
                (self.wire_tx, self.attributed_tx)
            }
            Direction::Rx => {
                let since = total.saturating_sub(self.socket_rx);
                self.socket_rx = total;
                self.wire_rx = self.wire_rx.saturating_add(since);
                (self.wire_rx, self.attributed_rx)
            }
        };
        // Clamped, since the two are sampled a moment apart and the
        // connections' total can briefly run ahead of the socket's.
        let unattributed = wire.saturating_sub(attributed);
        // Charged at `New`, which is what unattributed traffic is. Attribution
        // is per connection rather than per address, so it can never be
        // laundered into a better level.
        let level = Priority::New.level() as usize;
        match dir {
            Direction::Tx => self.tx[level] = unattributed,
            Direction::Rx => self.rx[level] = unattributed,
        }
    }

    /// `gk` is the instance this ledger belongs to, threaded in only so the
    /// window's network sample lands on that instance's pressure rather than the
    /// process's. A [`Ledger`] has no back-reference to its [`Goalkeeper`], and
    /// on an [`ArcGoalkeeper`][crate::ArcGoalkeeper] the two are not the same.
    fn roll(&mut self, gk: &Goalkeeper, now: Instant, config: &Config) {
        let started = *self.started.get_or_insert(now);
        if now.saturating_duration_since(started) < config.window {
            return;
        }

        // Reported before the counters are cleared, since this describes the
        // window that just ended. Whichever direction came closer to the budget
        // is the one that says how strained the link is.
        crate::resource::record_network_sample_of(gk, self.spent(config));

        // Advanced by whole windows rather than set to `now`, so the schedule
        // stays on a fixed grid. Rolling to `now` would make every window
        // `window + δ` long while still carrying one window's budget, so the
        // configured limit would never be reached.
        let window = config.window.max(Duration::from_nanos(1));
        let periods = now.saturating_duration_since(started).as_nanos() / window.as_nanos();
        self.started = Some(if periods > 64 {
            // Idle long enough that replaying the missed windows is pointless.
            now
        } else {
            started + window * periods as u32
        });
        self.epoch = self.epoch.wrapping_add(1).max(1);
        self.tx = [0; Priority::LEVELS];
        self.rx = [0; Priority::LEVELS];
        self.attributed_tx = 0;
        self.attributed_rx = 0;
        // `socket_tx`/`socket_rx` are the meter's own running totals and stay:
        // clearing them would make the next sample's delta the socket's whole
        // life over again, every window.
        self.wire_tx = 0;
        self.wire_rx = 0;
        for waker in self.wakers.drain(..) {
            waker.wake();
        }
    }

    /// The bytes this window is allowed to carry in `dir`.
    fn budget(dir: Direction, config: &Config) -> u64 {
        let per_second = match dir {
            Direction::Tx => config.max_tx_bytes_per_second,
            Direction::Rx => config.max_rx_bytes_per_second,
        };
        (per_second as u128 * config.window.as_nanos() / 1_000_000_000u128) as u64
    }

    /// How much of this window's budget the direction closest to its own limit
    /// has spent, where one means exactly at it.
    ///
    /// Compared per direction rather than by raw bytes, since the two budgets
    /// differ: half of a small uplink is more strained than half of a large
    /// downlink, however many bytes each is.
    fn spent(&self, config: &Config) -> f32 {
        let fraction = |dir: Direction, counts: &[u64; Priority::LEVELS]| {
            let budget = Self::budget(dir, config);
            if budget == 0 {
                0.0
            } else {
                counts.iter().sum::<u64>() as f32 / budget as f32
            }
        };
        fraction(Direction::Tx, &self.tx).max(fraction(Direction::Rx, &self.rx))
    }

    /// How many bytes `level` may move this window in `dir`.
    ///
    /// Two pools. The first is `1 - floor` of the budget, served strictly
    /// best-first, so a level gets whatever better levels have not taken. The
    /// second is [`Config::floor`], divided evenly among the levels the first
    /// did not reach, so being outranked costs a level almost everything but
    /// never quite everything.
    ///
    /// A level short of the whole budget gets the floor as well, since nobody
    /// worse is there to share it with. That keeps a lightly used link from
    /// being capped at `1 - floor`.
    ///
    /// Who shares is decided by who has sent this window, which is circular at
    /// the start of one: everybody is permitted until somebody exceeds the
    /// premium pool. Self-correcting, since the next window starts over.
    fn allowance(&self, level: u8, dir: Direction, config: &Config) -> u64 {
        let budget = Self::budget(dir, config);
        let floor = (budget as f64 * config.floor.clamp(0.0, 1.0) as f64) as u64;
        let premium = budget.saturating_sub(floor);
        let counts = match dir {
            Direction::Tx => &self.tx,
            Direction::Rx => &self.rx,
        };
        let level = (level as usize).min(Priority::LEVELS - 1);

        // Whatever better levels left in the premium pool.
        let better: u64 = counts[..level].iter().sum();
        let from_premium = premium.saturating_sub(better);

        // Which level exhausted the premium pool.
        let mut cumulative = 0u64;
        let mut boundary = Priority::LEVELS;
        for (at, bytes) in counts.iter().enumerate() {
            cumulative = cumulative.saturating_add(*bytes);
            // `>=`, not `>`. The level that fills the premium pool is held at
            // exactly the pool's size, so a strict test would never fire and
            // the floor would never activate.
            if cumulative >= premium {
                boundary = at;
                break;
            }
        }

        // The floor belongs to the levels strictly worse than the one that
        // exhausted the premium pool. If there are none it would go unspent, so
        // the level that exhausted the pool may have it after all.
        let worse = counts[(boundary + 1).min(Priority::LEVELS)..]
            .iter()
            .filter(|bytes| **bytes > 0)
            .count();
        let from_floor = if level > boundary {
            floor / worse.max(1) as u64
        } else if level == boundary && worse == 0 {
            floor
        } else {
            0
        };

        from_premium.saturating_add(from_floor)
    }

    /// What is left of `level`'s allowance in `dir` this window.
    fn remaining(&self, level: u8, dir: Direction, config: &Config) -> u64 {
        let counts = match dir {
            Direction::Tx => &self.tx,
            Direction::Rx => &self.rx,
        };
        let spent = counts[(level as usize).min(Priority::LEVELS - 1)];
        self.allowance(level, dir, config).saturating_sub(spent)
    }

    /// Whether `level` may still move bytes in `dir` this window. Used by tests.
    #[cfg(test)]
    fn permitted(&self, level: u8, dir: Direction, config: &Config) -> bool {
        self.remaining(level, dir, config) > 0
    }

    /// The worst level still within the budget.
    ///
    /// Walked best-first, so better levels take their bytes before worse ones
    /// are considered. Everything at or beyond the returned level is over.
    fn cutoff(&self, dir: Direction, config: &Config) -> u8 {
        let budget = Self::budget(dir, config);
        let counts = match dir {
            Direction::Tx => &self.tx,
            Direction::Rx => &self.rx,
        };
        let mut used = 0u64;
        for (level, bytes) in counts.iter().enumerate() {
            used = used.saturating_add(*bytes);
            if used > budget {
                return level as u8;
            }
        }
        Priority::LEVELS as u8
    }
}

/// Per-connection escalation state, kept here so [`Conn`] does not have to know
/// what a window is.
#[derive(Debug)]
pub(crate) struct Strikes {
    window: AtomicU64,
    consecutive: AtomicU64,
}

impl Strikes {
    pub(crate) fn new() -> Self {
        Self {
            window: AtomicU64::new(0),
            consecutive: AtomicU64::new(0),
        }
    }

    /// Records that this connection was throttled in `window`, returning how
    /// many consecutive windows that makes.
    pub(crate) fn strike(&self, window: u64) -> u32 {
        let last = self.window.swap(window, Ordering::Relaxed);
        if last == window {
            // Already counted; twice in one window says no more than once.
            return self.consecutive.load(Ordering::Relaxed) as u32;
        }
        let consecutive = if last + 1 == window {
            self.consecutive.fetch_add(1, Ordering::Relaxed) + 1
        } else {
            // A gap means it responded to backpressure at some point.
            self.consecutive.store(1, Ordering::Relaxed);
            1
        };
        consecutive as u32
    }

    pub(crate) fn clear(&self) {
        self.consecutive.store(0, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ArcGoalkeeper;
    use crate::executor::priority::UserPriority::*;

    /// A throwaway instance for the socket-total cases, which drive a standalone
    /// [`Ledger`] and assert on it directly. [`Ledger::record_socket_total`]
    /// wants a [`Goalkeeper`] only to route a window's network sample; these do
    /// not read that, so a fresh instance keeps the sample off any shared state.
    fn gk() -> ArcGoalkeeper {
        ArcGoalkeeper::new()
    }

    fn config() -> Config {
        Config {
            max_tx_bytes_per_second: 10_000,
            max_rx_bytes_per_second: 10_000,
            // Off, so these cases exercise strict priority alone. The floor has
            // its own tests.
            floor: 0.0,
            window: Duration::from_millis(100),
            kill_after: Some(Duration::from_millis(300)),
        }
    }

    /// A ledger of its own, so the assertions do not depend on what other tests
    /// have sent.
    fn ledger(spend: &[(Priority, u64)]) -> Ledger {
        let mut inner = Ledger {
            started: Some(Instant::now()),
            ..Default::default()
        };
        for (priority, bytes) in spend {
            inner.tx[priority.level() as usize] += bytes;
        }
        inner
    }

    /// `config()` with a floor, so the two pools are both in play. The budget
    /// is a window's worth of 10_000/s, so 1_000 bytes; a tenth of that is 100.
    fn floored() -> Config {
        Config {
            floor: 0.1,
            ..config()
        }
    }

    #[test]
    fn a_lone_talker_is_not_held_to_the_premium_pool() {
        // Past the premium pool with nobody worse to reserve the floor for, so
        // it may have the floor too. Otherwise a quiet link would sit
        // permanently a tenth under its limit.
        let level = Priority::User(L0).level();
        let inner = ledger(&[(Priority::User(L0), 950)]);
        assert_eq!(inner.allowance(level, Direction::Tx, &floored()), 1_000);
        assert!(inner.permitted(level, Direction::Tx, &floored()));

        // But the budget is still the budget.
        let inner = ledger(&[(Priority::User(L0), 1_001)]);
        assert!(!inner.permitted(level, Direction::Tx, &floored()));
    }

    #[test]
    fn a_worse_level_is_cut_to_its_share_of_the_floor() {
        // L0 has taken the premium pool. Three levels are past it, so the 100
        // reserved bytes are split three ways.
        let inner = ledger(&[
            (Priority::User(L0), 950),
            (Priority::User(L1), 10),
            (Priority::User(L2), 10),
            (Priority::User(L3), 10),
        ]);
        let floor_share = inner.allowance(Priority::User(L2).level(), Direction::Tx, &floored());
        assert_eq!(
            floor_share, 33,
            "a third of the floor, and none of the premium"
        );
        assert!(inner.permitted(Priority::User(L2).level(), Direction::Tx, &floored()));
    }

    #[test]
    fn the_best_level_keeps_the_premium_pool() {
        let inner = ledger(&[
            (Priority::User(L0), 950),
            (Priority::User(L1), 10),
            (Priority::User(L2), 10),
            (Priority::User(L3), 10),
        ]);
        let best = inner.allowance(Priority::User(L0).level(), Direction::Tx, &floored());
        assert!(
            best >= 900,
            "the best level got {best}, not the premium pool it is owed"
        );
    }

    #[test]
    fn a_worse_level_that_has_had_its_share_is_stopped() {
        let inner = ledger(&[
            (Priority::User(L0), 950),
            (Priority::User(L1), 500),
            (Priority::User(L2), 10),
        ]);
        assert!(
            !inner.permitted(Priority::User(L1).level(), Direction::Tx, &floored()),
            "a level well past the floor was still permitted"
        );
    }

    #[test]
    fn the_floor_is_only_paid_for_when_it_is_needed() {
        // With the floor off, the best level may have everything.
        let inner = ledger(&[(Priority::User(L0), 1)]);
        assert_eq!(
            inner.allowance(Priority::User(L0).level(), Direction::Tx, &config()),
            1_000
        );
    }

    #[test]
    fn under_the_budget_nothing_is_cut_off() {
        let inner = ledger(&[(Priority::User(L0), 100), (Priority::New, 200)]);
        assert_eq!(
            inner.cutoff(Direction::Tx, &config()),
            Priority::LEVELS as u8
        );
    }

    #[test]
    fn the_worst_levels_are_cut_off_first() {
        // 1000 bytes per 100ms window. Players take 600, strangers want 900.
        let inner = ledger(&[(Priority::User(L0), 600), (Priority::New, 900)]);
        let cutoff = inner.cutoff(Direction::Tx, &config());
        assert_eq!(cutoff, Priority::New.level(), "strangers are cut off");
        assert!(
            Priority::User(L0).level() < cutoff,
            "players are not: their bytes were taken first"
        );
    }

    #[test]
    fn a_flood_of_strangers_cannot_squeeze_a_player() {
        // However much the strangers send, the player's level stays under the
        // cutoff, which is the defining property of the ledger.
        let inner = ledger(&[(Priority::User(L0), 500), (Priority::Accept, 10_000_000)]);
        let cutoff = inner.cutoff(Direction::Tx, &config());
        assert!(Priority::User(L0).level() < cutoff);
        assert!(Priority::Accept.level() >= cutoff);
    }

    #[test]
    fn better_levels_are_cut_off_only_when_they_alone_exceed_it() {
        let inner = ledger(&[(Priority::User(L0), 5_000)]);
        assert_eq!(
            inner.cutoff(Direction::Tx, &config()),
            Priority::User(L0).level(),
            "even a player is throttled if it is the one saturating the link"
        );
    }

    #[test]
    fn tx_and_rx_are_rationed_separately() {
        let mut inner = ledger(&[(Priority::New, 5_000)]);
        inner.rx[Priority::New.level() as usize] = 0;
        assert_eq!(
            inner.cutoff(Direction::Tx, &config()),
            Priority::New.level()
        );
        assert_eq!(
            inner.cutoff(Direction::Rx, &config()),
            Priority::LEVELS as u8
        );
    }

    #[test]
    fn unattributed_traffic_is_the_remainder_and_is_not_double_counted() {
        // Connections reported 700 of the 1000 the socket actually moved.
        let gk = gk();
        let mut inner = socket_ledger();
        inner.tx[Priority::User(L0).level() as usize] = 700;
        inner.attributed_tx = 700;
        inner.record_socket_total(&gk, Direction::Tx, 1000, start());
        assert_eq!(inner.tx[Priority::New.level() as usize], 300);
        let sum: u64 = inner.tx.iter().sum();
        assert_eq!(sum, 1000, "the parts add up to the whole exactly once");
    }

    /// One origin for every window a case names.
    ///
    /// Fixed for the life of the process rather than read afresh, so
    /// `start() + window * n` is the same instant however many times it is
    /// written and however slowly the case runs. Taking `Instant::now()` per
    /// call would drift by microseconds against 100ms windows — never enough to
    /// fail, which is exactly what makes it worth removing.
    fn start() -> Instant {
        static ORIGIN: std::sync::LazyLock<Instant> = std::sync::LazyLock::new(Instant::now);
        *ORIGIN
    }

    /// A ledger fed by the socket meter, carrying the test [`config`] since
    /// [`Ledger::record_socket_total`] reads its own rather than taking one,
    /// and started at [`start`] so a case can name its windows from there.
    fn socket_ledger() -> Ledger {
        Ledger {
            config: config(),
            started: Some(start()),
            ..Default::default()
        }
    }

    /// [`Metered`][crate::web_transport] counts with `fetch_add` and is never
    /// reset, so the total handed to [`Ledger::record_socket_total`] is the
    /// socket's whole life. A window's ledger holds one window's bytes, so what
    /// is charged has to be the part that arrived since the last sample.
    ///
    /// The bug this guards is charging the lifetime figure to the window, which
    /// makes the process look more strained the longer it has been up, with no
    /// regard for the rate. It survived the case above because that one never
    /// crossed a window boundary: within a single window the lifetime total and
    /// the window's own bytes are the same number.
    #[test]
    fn only_the_bytes_since_the_last_sample_are_charged() {
        let gk = gk();
        let window = config().window;
        let mut inner = socket_ledger();

        // First window: the socket has moved 400 bytes in its life, all of them
        // during this window.
        inner.record_socket_total(&gk, Direction::Tx, 400, start());
        assert_eq!(inner.tx[Priority::New.level() as usize], 400);

        // Second window: another 400, for 800 over the two. The window is
        // still owed 400 — the earlier 400 was charged to the window it
        // happened in, and that window is over.
        inner.record_socket_total(&gk, Direction::Tx, 800, start() + window);
        assert_eq!(
            inner.tx[Priority::New.level() as usize],
            400,
            "the window was charged the socket's lifetime total, not its own bytes"
        );

        // And a window in which the socket moved nothing owes nothing, however
        // much it has carried before.
        inner.record_socket_total(&gk, Direction::Tx, 800, start() + window * 2);
        assert_eq!(
            inner.tx[Priority::New.level() as usize],
            0,
            "an idle window was charged for traffic that predates it"
        );
    }

    /// The consequence, and the reason this is worth a test of its own: the
    /// network figure feeds [`crate::resource::strained`], which
    /// [`crate::resource::ip_limiter`] consults before admitting a connection.
    /// A reading that climbs on its own puts a server into strict mode with
    /// nothing wrong with the link, and every fresh address is then held to one
    /// connection until the strain ages out — which it cannot, because the
    /// reading is still climbing.
    #[test]
    fn a_steady_link_does_not_look_more_strained_as_it_runs() {
        let config = config();
        // 400 bytes a window against a budget of 1_000 is two fifths of the
        // link, and stays two fifths however long it goes on for.
        let per_window = 400u64;
        let gk = gk();
        let mut inner = socket_ledger();
        let mut lifetime = 0u64;

        for window in 0..64u32 {
            lifetime += per_window;
            inner.record_socket_total(
                &gk,
                Direction::Tx,
                lifetime,
                start() + config.window * window,
            );
            let spent = inner.spent(&config);
            assert!(
                (spent - 0.4).abs() < 0.001,
                "window {window}: a link at two fifths of its budget read as {spent} of it"
            );
        }
    }

    #[test]
    fn strikes_need_consecutive_windows() {
        let strikes = Strikes::new();
        assert_eq!(strikes.strike(5), 1);
        // Twice in one window is still one window.
        assert_eq!(strikes.strike(5), 1);
        assert_eq!(strikes.strike(6), 2);
        assert_eq!(strikes.strike(7), 3);
        // A gap means it responded to backpressure; start over.
        assert_eq!(strikes.strike(20), 1);
    }

    /// A ration is per window and a flow-control limit is bytes outstanding, so
    /// the round trip is what converts one into the other.
    ///
    /// The bug this guards is handing the ration over unconverted, which for
    /// any peer closer than a window authorises more than the ration rather
    /// than less: at a tenth of the window, ten times.
    #[test]
    fn a_ration_becomes_a_window_through_the_round_trip() {
        // A megabyte per 100ms window is 10MB/s.
        let ration = 1024 * 1024;
        let window = Duration::from_millis(100);
        assert_eq!(
            flight(ration, window, window),
            ration,
            "a round trip of one window is the ration itself"
        );
        assert_eq!(
            flight(ration, window, Duration::from_millis(10)),
            ration / 10,
            "a tenth of the round trip is a tenth of the window"
        );
        assert_eq!(
            flight(ration, window, Duration::from_secs(1)),
            ration * 10,
            "a long link needs proportionally more outstanding to sustain the rate"
        );
        assert_eq!(
            flight(ration, window, Duration::ZERO),
            0,
            "no round trip sustains nothing, which the caller's floor rescues"
        );
    }

    #[test]
    fn clearing_forgives() {
        let strikes = Strikes::new();
        strikes.strike(1);
        strikes.strike(2);
        strikes.clear();
        assert_eq!(strikes.strike(3), 1);
    }
}
