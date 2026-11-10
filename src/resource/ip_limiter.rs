//! Per-source connection and bandwidth limiting.
//!
//! One limiter per [`Goalkeeper`][crate::Goalkeeper], which for a deployment
//! means one, since the host's sockets and its uplink are one thing. Tests take
//! an instance of their own and get a limiter of their own with it.
//!
//! A source is an address masked to a prefix, by default the whole address
//! (see [`crate::Goalkeeper::set_source_prefixes`]). A deployment whose
//! attackers hop between the addresses of a network limits by that network
//! instead, a `/24` say, and its limits are no longer multiplied by the
//! addresses an attacker holds. The prefix is held once, in the settings: each
//! source is keyed by its masked address.
//!
//! A source is not a client: a carrier-grade NAT presents hundreds of players
//! as one, so a source holding many [`ActiveSession`]s is allowed
//! proportionally more. Sessions become active only once something upstream has
//! decided they are real, so headroom cannot be minted by opening sockets.
//!
//! A source over its connection allowance may borrow from a pool shared by all
//! (see [`crate::Goalkeeper::set_borrow`]), so a household or school
//! bursting still gets in, provided it was not limited recently.
//! What each bank, a wider network of sources (see
//! [`crate::Goalkeeper::set_borrow_prefixes`]), may hold of the pool is capped
//! (see [`crate::Goalkeeper::set_borrow_per_bank`]), so no one network takes it
//! all.
//!
//! Loans are counted per source rather than per connection. Whichever of a
//! source's connections closes, it is one nearer its allowance, so a loan is
//! returned before an own slot is freed: a source does not keep borrowing once
//! its own connections would cover it.
//!
//! Besides its source, an address may belong to [`Pool`]s, as the caller says
//! (see [`crate::Goalkeeper::set_pools`]): each a cap on the connections all of
//! its addresses hold at once, which no session widens. A connection counts
//! against each of its pools for its life, whatever the pools say later.

use crate::ip_map::{Entry, IpMap};
use crate::rate_limiter::{RateLimiterProps, RateLimiterState, Units};
use crate::resource::bandwidth::{Direction, MIN_PACED_RATE};
use crate::{ProvideGoalkeeper, SystemGoalkeeper};
use log::warn;
use std::net::IpAddr;
use std::num::NonZeroU16;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// How the limiter rations.
///
/// Set through [`crate::Goalkeeper`]'s per-field setters rather than as a
/// struct, so changing one number cannot silently revert another.
#[derive(Copy, Clone, Debug)]
pub(crate) struct Config {
    /// The prefixes an IPv4 and an IPv6 address are masked to, to make their
    /// source.
    pub source_prefixes: (u8, u8),
    /// Bytes per second one source may move before being throttled, before
    /// any scaling for active sessions.
    pub bytes_per_second: Units,
    /// Bytes one source may move in a burst, before scaling.
    pub bytes_burst: Units,
    /// How much of the base allowance each active session adds.
    ///
    /// One means a source with three sessions gets four times the base, its
    /// own plus one per session. Zero disables scaling entirely.
    pub per_active_session: u32,
    /// Connections per active session a source may hold while strained: under
    /// a recent global soft limit, for a source new or recently limited.
    ///
    /// For an HTTP/1-only server, 4–6; for HTTP/2 with HTTP/1 WebSockets, 2;
    /// for HTTP/2 throughout, 1.
    pub connections_per_active_p90: u32,
    /// As [`Self::connections_per_active_p90`], ordinarily.
    pub connections_per_active_p99: u32,
    /// Connections across all sources before each source is afforded fewer.
    pub total_connections_soft_limit: u32,
    /// Connections across all sources before new ones are refused outright.
    pub total_connections_hard_limit: u32,
    /// Connections sources over their allowance may have borrowed at once, in
    /// all. Zero turns borrowing off.
    pub borrow: u32,
    /// The prefixes an IPv4 and an IPv6 address are masked to, to make the
    /// bank it borrows against. Zero makes one bank of everything, the pool
    /// alone bounding what is borrowed.
    ///
    /// Clamped to [`Self::source_prefixes`] where used (see
    /// [`Self::bank_prefix`]), so a source falls in one bank.
    pub borrow_prefixes: (u8, u8),
    /// Connections one bank's sources may have borrowed at once. Zero turns
    /// borrowing off, whatever the banks' size.
    pub borrow_per_bank: u32,
    /// How long an incident is remembered.
    pub ddos_memory: Duration,
    /// The rate limit applied by
    /// [`Goalkeeper::should_limit_custom`][crate::Goalkeeper::should_limit_custom],
    /// for whatever the caller finds expensive.
    pub custom: RateLimiterProps,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            source_prefixes: (32, 128),
            bytes_per_second: 500_000,
            bytes_burst: 1_000_000,
            per_active_session: 1,
            connections_per_active_p90: 1,
            connections_per_active_p99: 6,
            total_connections_soft_limit: 1000,
            total_connections_hard_limit: 2000,
            borrow: 200,
            borrow_prefixes: (8, 16),
            borrow_per_bank: 20,
            ddos_memory: Duration::from_secs(5 * 60),
            custom: RateLimiterProps::no_limit(),
        }
    }
}

impl Config {
    /// [`Self::borrow_prefixes`] for `ip`'s family, no longer than
    /// [`Self::source_prefixes`]. Were a bank narrower than a source, one
    /// source would span many banks, borrowing each one's share.
    fn bank_prefix(&self, ip: IpAddr) -> u8 {
        let ((source_v4, source_v6), (v4, v6)) = (self.source_prefixes, self.borrow_prefixes);
        if ip.is_ipv4() {
            v4.min(source_v4)
        } else {
            v6.min(source_v6)
        }
    }
}

/// Everything one instance rations, behind one lock.
///
/// The bandwidth ledger lives here rather than behind a lock of its own,
/// because the two are almost always wanted together: recording bytes updates
/// both, and asking whether a connection is over its ration consults both. Two
/// mutexes meant two acquisitions for one question and a deadlock waiting to
/// happen.
///
/// The cost is that connection admission and the custom rate limiter contend
/// with byte accounting, which is affordable because [`crate::conn`] settles in
/// batches.
#[derive(Default)]
struct Process {
    limiter: Addresses,
    ledger: crate::resource::bandwidth::Ledger,
    memory: crate::resource::memory::Ledger,
}

/// What every source is rationed against.
///
/// Owned by [`crate::Goalkeeper`]. The API that reaches it lives on
/// [`crate::ProvideGoalkeeper`], since the guards it hands out have to remember
/// which instance issued them.
#[derive(Default)]
pub(crate) struct IpLimiter(Mutex<Process>);

impl IpLimiter {
    pub(crate) fn with<R>(&self, f: impl FnOnce(&mut Addresses) -> R) -> R {
        f(&mut self.0.lock().unwrap().limiter)
    }

    /// Both halves at once, under one acquisition.
    ///
    /// The bandwidth ledger lives inside this lock rather than one of its own,
    /// so this is how [`crate::bandwidth`] reaches it. See [`Process`].
    pub(crate) fn with_process<R>(
        &self,
        f: impl FnOnce(
            &mut Addresses,
            &mut crate::resource::bandwidth::Ledger,
            &mut crate::resource::memory::Ledger,
        ) -> R,
    ) -> R {
        let mut process = self.0.lock().unwrap();
        let Process {
            limiter,
            ledger,
            memory,
        } = &mut *process;
        f(limiter, ledger, memory)
    }
}

/// `ip` with all but its first `v4` bits (if IPv4) or `v6` bits (if IPv6)
/// cleared: the network of that prefix holding it.
pub(crate) fn mask(ip: IpAddr, (v4, v6): (u8, u8)) -> IpAddr {
    match ip {
        IpAddr::V4(address) => {
            let keep = u32::MAX
                .checked_shl(32 - u32::from(v4.min(32)))
                .unwrap_or(0);
            IpAddr::V4((address.to_bits() & keep).into())
        }
        IpAddr::V6(address) => {
            let keep = u128::MAX
                .checked_shl(128 - u32::from(v6.min(128)))
                .unwrap_or(0);
            IpAddr::V6((address.to_bits() & keep).into())
        }
    }
}

/// The bit `ip` sets in its source's sketch of the addresses seen.
///
/// The top bits of the hash, since a multiplicative hash mixes upward.
fn sketch_bit(ip: IpAddr) -> u64 {
    1 << (fxhash::hash64(&ip) >> 58)
}

/// How many distinct addresses set the bits of `sketch`, by linear counting:
/// exact for a few, within a few of the truth for dozens, and saturating at
/// about 266 once every bit is set. The same for any source prefix, since it
/// counts addresses rather than assuming their layout.
fn estimate(sketch: u64) -> u32 {
    const BITS: f64 = 64.0;
    let zeros = sketch.count_zeros();
    if zeros == 0 {
        return (BITS * BITS.ln()).round() as u32;
    }
    (-BITS * (f64::from(zeros) / BITS).ln()).round() as u32
}

/// The bytes a second at which a source's allowance is no limit; see
/// [`scaled`].
const NO_LIMIT: Units = 1_000_000_000;

/// The steady rate of [`scaled`]'s allowance in bytes a second, or `None`
/// for no limit.
fn steady_rate(config: &Config, actives: u32) -> Option<u64> {
    let factor = 1 + actives.saturating_mul(config.per_active_session);
    let per_second = config.bytes_per_second.saturating_mul(factor);
    (per_second < NO_LIMIT).then_some(u64::from(per_second))
}

/// How many windows a source's paced connections are given to spend what is
/// left of its burst in, at the least. More than one, so that the burst is
/// never aimed at exactly: what is left halves each window, and a window that
/// runs long, or bytes counted as they enter the socket's buffer rather than
/// as they leave it, eat into the half that is not spent rather than putting
/// the source over.
const BURST_WINDOWS: f64 = 2.0;

/// What a source's allowance holds each of its paced connections to; see
/// [`Addresses::bandwidth_rate`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) struct PacedShare {
    /// The rate to pace at, which spends a [`BURST_WINDOWS`]th of what is left
    /// of the burst a window. Zero while the source is over.
    pub(crate) rate: u64,
    /// The fastest a connection already paced may be left at, which spends all
    /// of what is left in one window. A caller that leaves a rate alone until
    /// it has moved enough to be worth a syscall must not leave it past this,
    /// but may anywhere short of it.
    pub(crate) ceiling: u64,
}

/// How many of a source's connections asked for their rate (see
/// [`Addresses::bandwidth_rate`]) in the bandwidth window it was last asked in,
/// and in the one before. A connection asks once a window, on its first write
/// (or read) in it, so these are the connections moving bytes, not every one
/// the source holds open: an idle keep-alive or a quiet game socket leaves
/// more for the one that is busy.
///
/// And how much of the source's allowance this window has been handed out,
/// so that however the count is off, the shares never add up to more.
#[derive(Copy, Clone, Debug, Default)]
struct Pacers {
    /// The window, by its low bits: two that far apart are never compared.
    epoch: u32,
    this: u16,
    last: u16,
    /// The fraction of this window's allowance handed out so far.
    claimed: f32,
}

impl Pacers {
    /// Counts one more connection asking in `epoch`, of `open` the source
    /// holds, returning the fraction of the source's allowance it may have.
    ///
    /// An equal share among as many as asked last window, since those that
    /// will ask this window have not all asked yet when the first does. One
    /// asking past that many is new to it, and the others like it may be
    /// about to ask too, with nothing to say how many: an equal share among
    /// all `open`, as cautious as can be, for a window. An equal share by
    /// how many have asked would hand the k-th asker a k-th, and a browser
    /// opening six at once over half again the whole between them.
    ///
    /// Whatever the share, no more than is left unclaimed this window, so
    /// that between them they never overspend it.
    fn ask(&mut self, epoch: u64, open: u32) -> f32 {
        let epoch = epoch as u32;
        if epoch != self.epoch {
            self.last = if epoch == self.epoch.wrapping_add(1) {
                self.this
            } else {
                0
            };
            self.this = 0;
            self.claimed = 0.0;
            self.epoch = epoch;
        }
        self.this = self.this.saturating_add(1);
        let (this, last) = (u32::from(self.this), u32::from(self.last));
        let ways = if this > last { this.max(open) } else { last };
        let share = (1.0 / ways as f32).min(1.0 - self.claimed).max(0.0);
        self.claimed += share;
        share
    }
}

/// The rate to pace one of a source's connections at, for one that has
/// `headroom` of its burst left and whose rate is revisited every `window`:
/// its `share` of the source's steady rate plus enough to spend a `windows`th
/// of the headroom this window.
///
/// Pacing at the steady rate alone would never spend the burst, so a new
/// visitor's first download (what the burst is for) would crawl at it however
/// idle the host. With plenty of burst left this is far past anything a
/// connection can do, so the download goes as fast as the link and the
/// level's ration allow; only as the burst runs out does it bind, settling
/// on the steady rate, which [`RateLimiterState::should_limit_spend`] lets a
/// source keep up indefinitely. A transfer that outlasts the burst slows
/// rather than stops.
///
/// Shared among the connections moving bytes (see [`Pacers`]), since each is
/// paced on its own and all of them together must not spend past what is
/// left. One that slows among them leaves its share unspent, which is paid
/// back and so is in the headroom next window.
///
/// Never below [`MIN_PACED_RATE`], the floor the level's ration is held to
/// as well, so a share is crawling but never stopped. Enough busy connections
/// at it together overrun the steady rate (past forty at the defaults), and
/// put the source over, which leases them instead.
fn burst_rate(steady: u64, headroom: u64, share: f32, window: Duration, windows: f64) -> u64 {
    // A window of nothing revisits the rate on every write; a millisecond is
    // as good as nothing and does not divide by zero.
    let window = window.max(Duration::from_millis(1)).as_secs_f64();
    let rate = steady as f64 + headroom as f64 / (windows * window);
    ((rate * f64::from(share)) as u64).max(MIN_PACED_RATE)
}

/// A source's allowance, widened by how many sessions it has proved it
/// carries.
fn scaled(config: &Config, actives: u32) -> RateLimiterProps {
    let factor = 1 + actives.saturating_mul(config.per_active_session);
    let per_second = config.bytes_per_second.saturating_mul(factor);
    // A rate limiter spaces units `1s / throughput` apart, which rounds to
    // nothing past a billion a second. Scaling a generous configured limit by a
    // source's active sessions reaches that easily, and no limit is what it
    // means, so it is said rather than derived.
    if per_second >= NO_LIMIT {
        return RateLimiterProps::no_limit();
    }
    RateLimiterProps::new_throughput(
        per_second,
        // Saturating at `Units::MAX` would make the burst ineffectual, which is
        // the one thing a burst may not be.
        config
            .bytes_burst
            .saturating_mul(factor)
            .min(Units::MAX - 1),
    )
}

/// Summary statistics for one source. Forgotten after a long enough quiet
/// period.
#[derive(Copy, Clone, Debug)]
#[non_exhaustive]
pub struct IpStats {
    /// When this source was first seen.
    pub first: Instant,
    /// Outstanding [`ConnectionPermit`]s.
    pub connections: u32,
    /// Of [`Self::connections`], those borrowed beyond the source's own
    /// allowance.
    pub borrowed: u32,
    /// Outstanding [`ActiveSession`]s.
    pub active_sessions: u32,
    /// Roughly how many distinct addresses the source has asked to connect
    /// or held sessions from: exact for a few, saturating at about 266.
    pub addresses: u32,
    /// When this source last hit a hard limit on connecting. Not its
    /// bandwidth allowance, whose sources can be spoofed; see
    /// [`crate::Goalkeeper::address_over_bandwidth`] for that.
    pub last_limit: Option<Instant>,
}

/// The most [`Pool`]s one address belongs to.
pub const MAX_POOLS: usize = 4;

/// A cap on the connections held at once by every address in it, together,
/// whatever their sources' own allowances. Which addresses are in which pools
/// is the caller's to say (see [`crate::Goalkeeper::set_pools`]).
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Pool {
    /// Names the pool: addresses given the same id share its count. Nonzero,
    /// so that a connection's record of its pools stays small.
    pub id: NonZeroU16,
    /// Connections its addresses may hold at once, together.
    pub cap: u32,
    /// Whether a connection past the cap is refused, rather than let in and
    /// counted as [`PoolStats::over`].
    pub enforce: bool,
}

/// The pools one address belongs to, at most [`MAX_POOLS`].
#[derive(Copy, Clone, Debug, Default)]
pub struct Pools([Option<Pool>; MAX_POOLS]);

impl Pools {
    /// In no pool.
    pub fn new() -> Self {
        Self::default()
    }

    /// In `pool` as well. Past [`MAX_POOLS`], ignored (a debug build panics).
    pub fn with(mut self, pool: Pool) -> Self {
        let free = self.0.iter_mut().find(|slot| slot.is_none());
        debug_assert!(free.is_some(), "more than {MAX_POOLS} pools");
        if let Some(slot) = free {
            *slot = Some(pool);
        }
        self
    }

    fn iter(&self) -> impl Iterator<Item = &Pool> {
        self.0.iter().flatten()
    }
}

/// What one pool held and turned away since its statistics were last taken
/// (see [`crate::Goalkeeper::take_pool_stats`]).
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub struct PoolStats {
    /// Connections it holds now.
    pub connections: u32,
    /// The most it held at once.
    pub peak: u32,
    /// Connections past its cap: refused if it is enforced, else let in.
    pub over: u32,
}

/// What the limiter granted a connection: the address, the source it was
/// counted against, and the pools it counts against.
///
/// Not whether it was borrowed, since loans belong to the source rather than
/// to any one connection (see the module docs).
#[derive(Copy, Clone, Debug)]
pub(crate) struct Grant {
    ip: IpAddr,
    source: IpAddr,
    pools: [Option<NonZeroU16>; MAX_POOLS],
}

/// A permissible, long-lived connection. Hold it for the connection's life.
///
/// Carries the handle it was issued against, so it gives its slot back to the
/// instance that granted it. Against [`SystemGoalkeeper`] that handle is
/// zero-sized. It gives the slot back to the source it was counted against,
/// even if the source prefixes changed meanwhile.
///
/// [`SystemGoalkeeper`]: crate::SystemGoalkeeper
#[derive(Debug)]
pub struct ConnectionPermit<P: ProvideGoalkeeper = SystemGoalkeeper> {
    grant: Grant,
    provider: P,
}

impl<P: ProvideGoalkeeper> ConnectionPermit<P> {
    pub(crate) fn new(grant: Grant, provider: P) -> Self {
        Self { grant, provider }
    }

    /// The instance that issued this, for whatever the connection does next.
    pub fn provider(&self) -> &P {
        &self.provider
    }

    /// The address this permits.
    pub fn ip(&self) -> IpAddr {
        self.grant.ip
    }
}

impl<P: ProvideGoalkeeper> Drop for ConnectionPermit<P> {
    fn drop(&mut self) {
        let grant = self.grant;
        self.provider.limiter.with(|limiter| limiter.release(grant))
    }
}

/// A connection with meaningful activity on it: an authenticated socket rather
/// than merely an open one. See the module docs for why this earns headroom.
#[derive(Debug)]
pub struct ActiveSession<P: ProvideGoalkeeper = SystemGoalkeeper> {
    /// The source it was counted against.
    source: IpAddr,
    provider: P,
}

impl<P: ProvideGoalkeeper> ActiveSession<P> {
    pub(crate) fn new(source: IpAddr, provider: P) -> Self {
        Self { source, provider }
    }
}

impl<P: ProvideGoalkeeper> Drop for ActiveSession<P> {
    fn drop(&mut self) {
        let source = self.source;
        self.provider
            .limiter
            .with(|limiter| limiter.leave_session(source))
    }
}

/// Rate at which the limiter is willing to talk about being limited.
const WARNING_LIMIT: RateLimiterProps = RateLimiterProps::const_new(Duration::from_secs(1), 0);

/// The per-source state.
#[derive(Debug)]
pub(crate) struct Addresses {
    config: Config,
    /// Keyed by source: each address masked to the source prefixes.
    ///
    /// Changing the prefixes leaves the sources already here keyed as they
    /// were: their permits and sessions give back to them, and they are
    /// forgotten once idle. No source is merged or split, which could not be
    /// done exactly for the guards outstanding.
    usage: IpMap<Usage>,
    /// Connections borrowed, by bank, while any are.
    banks: IpMap<u32>,
    /// Connections borrowed in all.
    borrowed: u32,
    /// Each [`Pool`] by id, while it holds a connection or has statistics
    /// not yet taken.
    pools: fxhash::FxHashMap<NonZeroU16, PoolStats>,
    next_prune: Instant,
    warning_limiter: RateLimiterState,
    total_connections: u32,
    /// See [`permit_counts`].
    permits: u32,
    permits_withheld: u32,
    last_soft_limit: Option<Instant>,
}

impl Default for Addresses {
    fn default() -> Self {
        Self {
            config: Config::default(),
            usage: IpMap::default(),
            banks: IpMap::default(),
            borrowed: 0,
            pools: Default::default(),
            next_prune: Instant::now(),
            warning_limiter: RateLimiterState::default(),
            total_connections: 0,
            permits: 0,
            permits_withheld: 0,
            last_soft_limit: None,
        }
    }
}

/// One source's record.
///
/// [`IpStats`]'s fields, but held flat rather than as one, so that its padding
/// is shared with the rest's, and without [`IpStats::addresses`], which is
/// estimated when read: a source takes 8 bytes fewer.
#[derive(Debug)]
pub(crate) struct Usage {
    /// Indexed by [`Direction`]; see its docs for why they are separate.
    bandwidth: [RateLimiterState; 2],
    custom: RateLimiterState,
    /// See [`IpStats::first`].
    first: Instant,
    /// See [`IpStats::connections`].
    connections: u32,
    /// See [`IpStats::borrowed`].
    borrowed: u32,
    /// See [`IpStats::active_sessions`].
    active_sessions: u32,
    /// See [`IpStats::last_limit`].
    last_limit: Option<Instant>,
    over_bandwidth: [bool; 2],
    /// Indexed by [`Direction`]: which of its connections are moving bytes,
    /// to share its allowance among.
    pacers: [Pacers; 2],
    /// The addresses seen, one bit each by hash; see [`estimate`].
    addresses: u64,
    /// The prefix its source was masked to for the bank its loans are
    /// against, while it holds any (see [`Self::bank`]). Kept rather than
    /// read from the settings on return, so that their changing meanwhile
    /// cannot return a loan to a bank it was not borrowed from. The length
    /// rather than the bank, which would cost a source 16 bytes where this
    /// fits in padding.
    bank_prefix: u8,
}

impl Usage {
    /// The bank the loans of `source`, this record's key, are against.
    fn bank(&self, source: IpAddr) -> IpAddr {
        // `mask` reads only the prefix of `source`'s family.
        mask(source, (self.bank_prefix, self.bank_prefix))
    }

    fn new(now: Instant) -> Self {
        Self {
            bandwidth: std::array::from_fn(|_| RateLimiterState {
                until: now,
                burst_used: 0,
            }),
            custom: RateLimiterState {
                until: now,
                burst_used: 0,
            },
            first: now,
            connections: 0,
            borrowed: 0,
            active_sessions: 0,
            last_limit: None,
            over_bandwidth: [false; 2],
            pacers: Default::default(),
            addresses: 0,
            bank_prefix: 0,
        }
    }
}

/// The setters and readers [`ProvideGoalkeeper`] is written in terms of.
///
/// One per configured field rather than a `Config` struct, since a struct means
/// a caller changing one number either restates the rest or leans on
/// `..Default::default()`, which silently reverts anything set earlier.
impl Addresses {
    pub(crate) fn stats(&self) -> impl Iterator<Item = (IpAddr, IpStats)> + '_ {
        self.usage.iter().map(|(source, usage)| {
            (
                source,
                IpStats {
                    first: usage.first,
                    connections: usage.connections,
                    borrowed: usage.borrowed,
                    active_sessions: usage.active_sessions,
                    addresses: estimate(usage.addresses),
                    last_limit: usage.last_limit,
                },
            )
        })
    }

    pub(crate) fn total_connections(&self) -> u32 {
        self.total_connections
    }

    /// Connections borrowed, in all.
    pub(crate) fn borrowed(&self) -> u32 {
        self.borrowed
    }

    pub(crate) fn take_permit_counts(&mut self) -> (u32, u32) {
        (
            std::mem::take(&mut self.permits),
            std::mem::take(&mut self.permits_withheld),
        )
    }

    /// Each pool's statistics since they were last taken, starting them
    /// afresh, and forgetting a pool that holds nothing.
    pub(crate) fn take_pool_stats(&mut self) -> Vec<(NonZeroU16, PoolStats)> {
        let taken = self.pools.iter().map(|(id, stats)| (*id, *stats)).collect();
        self.pools.retain(|_, stats| {
            stats.peak = stats.connections;
            stats.over = 0;
            stats.connections > 0
        });
        taken
    }

    #[allow(dead_code, reason = "read back for symmetry with the setter")]
    pub(crate) fn custom_limit(&self) -> RateLimiterProps {
        self.config.custom
    }

    pub(crate) fn set_source_prefixes(&mut self, v4: u8, v6: u8) {
        self.config.source_prefixes = (v4.min(32), v6.min(128));
    }

    pub(crate) fn set_bandwidth_limits(&mut self, bytes_per_second: Units, bytes_burst: Units) {
        self.config.bytes_per_second = bytes_per_second;
        self.config.bytes_burst = bytes_burst;
    }

    pub(crate) fn set_per_active_session(&mut self, factor: u32) {
        self.config.per_active_session = factor;
    }

    pub(crate) fn set_connections_per_active(&mut self, p90: u32, p99: u32) {
        self.config.connections_per_active_p90 = p90;
        self.config.connections_per_active_p99 = p99;
    }

    pub(crate) fn set_total_connection_limits(&mut self, soft: u32, hard: u32) {
        self.config.total_connections_soft_limit = soft;
        self.config.total_connections_hard_limit = hard;
    }

    pub(crate) fn set_borrow(&mut self, connections: u32) {
        self.config.borrow = connections;
    }

    pub(crate) fn set_borrow_prefixes(&mut self, v4: u8, v6: u8) {
        self.config.borrow_prefixes = (v4.min(32), v6.min(128));
    }

    pub(crate) fn set_borrow_per_bank(&mut self, connections: u32) {
        self.config.borrow_per_bank = connections;
    }

    pub(crate) fn set_ddos_memory(&mut self, memory: Duration) {
        self.config.ddos_memory = memory;
    }

    pub(crate) fn set_custom_limit(&mut self, props: RateLimiterProps) {
        self.config.custom = props;
    }

    /// Counts a session from `ip`, returning the source it was counted
    /// against, for [`Self::leave_session`].
    pub(crate) fn enter_session(&mut self, ip: IpAddr) -> IpAddr {
        let source = self.source(ip);
        let entry = self.entry(source);
        entry.active_sessions += 1;
        entry.addresses |= sketch_bit(ip);
        source
    }

    pub(crate) fn leave_session(&mut self, source: IpAddr) {
        if let Some(usage) = self.usage.get_mut(&source) {
            debug_assert!(usage.active_sessions > 0);
            usage.active_sessions = usage.active_sessions.saturating_sub(1);
        } else {
            debug_assert!(false, "session outlived its source's record");
        }
    }

    pub(crate) fn should_limit_custom(&mut self, ip: IpAddr, usage: Units, now: Instant) -> bool {
        let props = self.config.custom;
        let source = self.source(ip);
        self.entry(source)
            .custom
            .should_limit_rate_with_now_and_usage(&props, now, usage)
    }
}

impl Addresses {
    /// The source `ip` belongs to.
    fn source(&self, ip: IpAddr) -> IpAddr {
        mask(ip, self.config.source_prefixes)
    }

    /// See [`IpLimiter::record_bandwidth`].
    pub(crate) fn record_bandwidth(
        &mut self,
        ip: IpAddr,
        dir: Direction,
        bytes: Units,
        now: Instant,
    ) {
        let config = self.config;
        let source = self.source(ip);
        let entry = self.entry(source);
        let actives = entry.active_sessions;
        // Both directions are measured against the same allowance, which keeps
        // the configuration to one pair.
        let props = scaled(&config, actives);
        let limit = &mut entry.bandwidth[dir as usize];
        let over = limit.should_limit_spend(&props, now, bytes);
        if over {
            // Moved regardless, so owed regardless. Otherwise a source that
            // keeps sending while over has its mark lift as if it had
            // stopped. Owed up to a burst past where refusing starts, and no
            // more: this is public, and for UDP its sources can be spoofed.
            limit.owe(&props, now, bytes);
            // Not a limit hit, for `last_limit`'s purposes, which would hold
            // the source to stricter terms of admission and bar it from
            // borrowing for the DDoS memory. For the same reason: a flood in
            // a spoofed source's name would hold its owner to them. And the
            // sources most likely to overrun this together, a household or a
            // school on one network loading a game's assets at once, are the
            // ones borrowing is for. Held back, by being over, is enough.
        }
        entry.over_bandwidth[dir as usize] = over;
        self.maybe_prune(now);
    }

    /// Whether `ip` is over its allowance in `dir` at `now`.
    ///
    /// [`Self::record_bandwidth`] marks a source over as its bytes move, but a
    /// source over its allowance is refused leases (see `bandwidth::lease`),
    /// so it moves none and nothing records it again. The mark lifts here
    /// instead, once enough has been paid back that its next spend would be
    /// accepted. Otherwise one overdraft would refuse the source for as long
    /// as it kept trying: every connection stalled, new ones before their
    /// handshake.
    ///
    /// Then, not once all of it has been paid back. That would hold every
    /// connection of a source that overshot by a little for as long as its
    /// whole burst takes to repay, which a burst sized for a game's assets
    /// makes tens of seconds. Back within its burst, it may move bytes again,
    /// and its paced connections pick up at its steady rate.
    pub(crate) fn over_bandwidth(&mut self, ip: IpAddr, dir: Direction, now: Instant) -> bool {
        let config = self.config;
        let source = self.source(ip);
        let Some(entry) = self.usage.get_mut(&source) else {
            return false;
        };
        let props = scaled(&config, entry.active_sessions);
        let over = &mut entry.over_bandwidth[dir as usize];
        if *over && !entry.bandwidth[dir as usize].would_limit_spend(&props, now) {
            *over = false;
        }
        *over
    }

    /// How fast `ip` may move bytes in `dir` at `now`, for a caller that hands
    /// the rate to something that paces itself and so never asks for a lease.
    ///
    /// A rate of zero while it is over its allowance (see
    /// [`Self::over_bandwidth`]), `None` for no limit, and otherwise rates in
    /// bytes a second for each of its connections, by how much of its burst is
    /// left (see [`burst_rate`]). `window` is how often the caller revisits
    /// them, and `epoch` which window it is in.
    ///
    /// To be asked once a window per connection, and only by one moving bytes
    /// in `dir`: each asking counts it among those the source's allowance is
    /// shared by (see [`Pacers`]).
    pub(crate) fn bandwidth_rate(
        &mut self,
        ip: IpAddr,
        dir: Direction,
        window: Duration,
        epoch: u64,
        now: Instant,
    ) -> Option<PacedShare> {
        let source = self.source(ip);
        // Counted even while over, so that the count is right once it is not.
        // Never seen, so nothing else of it to share with: all of it.
        let share = self.usage.get_mut(&source).map_or(1.0, |entry| {
            let open = entry.connections;
            entry.pacers[dir as usize].ask(epoch, open)
        });
        if self.over_bandwidth(ip, dir, now) {
            return Some(PacedShare {
                rate: 0,
                ceiling: 0,
            });
        }
        let config = self.config;
        let entry = self.usage.get(&source);
        let actives = entry.map_or(0, |entry| entry.active_sessions);
        let steady = steady_rate(&config, actives)?;
        let props = scaled(&config, actives);
        // Never recorded, so nothing spent: the whole burst.
        let headroom = entry.map_or(props.burst(), |entry| {
            entry.bandwidth[dir as usize].headroom(&props, now)
        });
        let rate = |windows| burst_rate(steady, u64::from(headroom), share, window, windows);
        Some(PacedShare {
            rate: rate(BURST_WINDOWS),
            ceiling: rate(1.0),
        })
    }

    /// The record of `source`, an address already masked to its source.
    pub(crate) fn entry(&mut self, source: IpAddr) -> &mut Usage {
        self.usage
            .entry(source)
            .or_insert_with(|| Usage::new(Instant::now()))
    }

    /// Whether `ip`, in `pools`, may open another connection, and the
    /// accounting either way.
    ///
    /// Returns what was granted rather than a guard, since a guard must carry
    /// the handle that issued it and this runs inside the lock. The caller
    /// wraps it.
    pub(crate) fn connection_permit(
        &mut self,
        ip: IpAddr,
        label: &'static str,
        strained: bool,
        pools: &Pools,
    ) -> Option<Grant> {
        self.permits = self.permits.saturating_add(1);
        let now = Instant::now();
        let config = self.config;
        let source = self.source(ip);

        if self.total_connections >= config.total_connections_hard_limit {
            self.permits_withheld = self.permits_withheld.saturating_add(1);
            self.warn(ip, label, "host is at its connection ceiling", now);
            return None;
        }

        // A pool at its cap refuses, if enforced, before the source is charged
        // anything: the source did nothing wrong.
        if let Some(full) = pools.iter().find(|pool| {
            pool.enforce
                && self
                    .pools
                    .get(&pool.id)
                    .map_or(0, |stats| stats.connections)
                    >= pool.cap
        }) {
            let stats = self.pools.entry(full.id).or_default();
            stats.over = stats.over.saturating_add(1);
            self.permits_withheld = self.permits_withheld.saturating_add(1);
            self.warn(ip, label, "its pool is full", now);
            return None;
        }

        // Held for the rest, rather than looked up again: the other fields
        // touched are disjoint from it.
        let usage = self.usage.entry(source).or_insert_with(|| Usage::new(now));

        // Opening a connection is not free, so it is charged against the
        // source's bandwidth. `Rx`, since connecting is the peer's decision.
        const CONNECT_COST: Units = 10_000;
        usage.addresses |= sketch_bit(ip);
        let props = scaled(&config, usage.active_sessions);
        if usage.bandwidth[Direction::Rx as usize].should_limit_spend(&props, now, CONNECT_COST) {
            usage.last_limit = Some(now);
            self.permits_withheld = self.permits_withheld.saturating_add(1);
            self.warn(ip, label, "connecting too fast", now);
            return None;
        }

        // `strained` is this instance's verdict, read by the caller before it
        // took this lock; see [`crate::ProvideGoalkeeper::connection_permit`].
        let soft_limit_reached =
            strained || self.total_connections >= config.total_connections_soft_limit;
        if soft_limit_reached {
            self.last_soft_limit = Some(now);
        }
        let recent_global = self
            .last_soft_limit
            .is_some_and(|last| now.duration_since(last) < config.ddos_memory);

        let old = now.duration_since(usage.first) > Duration::from_secs(60);
        let recent_local = usage
            .last_limit
            .is_some_and(|last| now.duration_since(last) < config.ddos_memory);
        let strict = (!old || recent_local) && recent_global;

        let per_active = if strict {
            config.connections_per_active_p90
        } else {
            config.connections_per_active_p99
        };
        let limit = (usage.active_sessions + 1 + (!strict) as u32).saturating_mul(per_active);

        // Past its allowance, a source borrows, if it was not limited recently,
        // the pool has a connection left and its bank has not borrowed its
        // share; or it is refused. Newness alone does not bar it, since a
        // household's burst is often its first minute.
        if usage.connections >= limit {
            // A source holding loans keeps borrowing against the bank it holds
            // them in, so that all of them are returned to one.
            if usage.borrowed == 0 {
                usage.bank_prefix = config.bank_prefix(source);
            }
            let bank = usage.bank(source);
            let lent = !recent_local
                && self.borrowed < config.borrow
                && match self.banks.entry(bank) {
                    Entry::Occupied(mut held) if *held.get() < config.borrow_per_bank => {
                        *held.get_mut() += 1;
                        true
                    }
                    Entry::Vacant(vacant) if config.borrow_per_bank > 0 => {
                        vacant.insert(1);
                        true
                    }
                    _ => false,
                };
            if !lent {
                usage.last_limit = Some(now);
                self.permits_withheld = self.permits_withheld.saturating_add(1);
                self.warn(
                    ip,
                    label,
                    if recent_local && strict {
                        "too many connections (strict)"
                    } else if recent_local {
                        "too many connections, recently limited so may not borrow"
                    } else {
                        "too many connections, none to borrow"
                    },
                    now,
                );
                return None;
            }
            usage.borrowed += 1;
            self.borrowed += 1;
        }

        usage.connections += 1;
        self.total_connections += 1;
        let mut counted = [None; MAX_POOLS];
        for (slot, pool) in counted.iter_mut().zip(pools.iter()) {
            let stats = self.pools.entry(pool.id).or_default();
            stats.connections += 1;
            stats.peak = stats.peak.max(stats.connections);
            if stats.connections > pool.cap {
                stats.over = stats.over.saturating_add(1);
            }
            *slot = Some(pool.id);
        }
        Some(Grant {
            ip,
            source,
            pools: counted,
        })
    }

    /// Gives back what `grant` was granted: its slot, to the source it was
    /// counted against, and, if that source holds any loans, one of them, to
    /// the pool and its bank. See the module docs for why a loan goes first.
    pub(crate) fn release(&mut self, grant: Grant) {
        if let Some(usage) = self.usage.get_mut(&grant.source) {
            debug_assert!(usage.connections > 0);
            usage.connections = usage.connections.saturating_sub(1);
            if usage.borrowed > 0 {
                usage.borrowed -= 1;
                debug_assert!(self.borrowed > 0);
                self.borrowed = self.borrowed.saturating_sub(1);
                match self.banks.entry(usage.bank(grant.source)) {
                    Entry::Occupied(mut held) => {
                        *held.get_mut() = held.get().saturating_sub(1);
                        if *held.get() == 0 {
                            held.remove();
                        }
                    }
                    Entry::Vacant(_) => debug_assert!(false, "loan outlived its bank's count"),
                }
            }
        } else {
            debug_assert!(false, "permit outlived its source's record");
        }
        // Subtracted even if the record went missing, so the total cannot
        // drift upwards and lock everyone out.
        debug_assert!(self.total_connections > 0);
        self.total_connections = self.total_connections.saturating_sub(1);
        for id in grant.pools.iter().flatten() {
            if let Some(stats) = self.pools.get_mut(id) {
                debug_assert!(stats.connections > 0);
                stats.connections = stats.connections.saturating_sub(1);
            } else {
                debug_assert!(false, "permit outlived its pool's record");
            }
        }
    }

    /// Says something about a limited address, at most once a second across the
    /// whole process. Under a distributed flood, logging each refusal would be
    /// the louder denial of service.
    ///
    /// `why` is a literal rather than something formatted, since it is built on
    /// every refusal and used on almost none of them. A caller wanting to say
    /// which of several regimes refused an address picks between literals; one
    /// wanting to interpolate a number would be doing that work per refused
    /// connection, which is exactly the traffic this is rate limited against.
    fn warn(&mut self, ip: IpAddr, label: &'static str, why: &'static str, now: Instant) {
        if self
            .warning_limiter
            .should_limit_rate_with_now(&WARNING_LIMIT, now)
        {
            return;
        }
        warn!("refused {label} from {ip}: {why}");
    }

    fn maybe_prune(&mut self, now: Instant) {
        if now < self.next_prune {
            return;
        }
        self.next_prune = now + Duration::from_secs(5).max(self.config.ddos_memory / 2);
        self.prune(now);
    }

    /// Forgets the sources there is nothing to remember about: none of their
    /// connections or sessions open, nothing still owed, and no limit hit
    /// within the [`Config::ddos_memory`].
    ///
    /// Not what was owed until some time ago, which every source that moved a
    /// byte lately would satisfy, and which a spoofed flood could fill the
    /// table with. What is still owed, since forgetting it would hand the
    /// source a fresh allowance; and the limits it hit, since
    /// [`Self::connection_permit`] holds a source that hit one within the
    /// memory to stricter terms, which forgetting it would let it out of.
    fn prune(&mut self, now: Instant) {
        let memory = self.config.ddos_memory;
        self.usage.retain(|_, usage| {
            usage.bandwidth.iter().any(|state| state.in_debt(now))
                || usage.custom.in_debt(now)
                || usage
                    .last_limit
                    .is_some_and(|last| now.saturating_duration_since(last) < memory)
                || usage.active_sessions > 0
                || usage.connections > 0
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ArcGoalkeeper, OwnedGoalkeeper};
    use std::sync::Arc;

    /// An address, for a case that needs one.
    fn ip(n: u16) -> IpAddr {
        IpAddr::from([10, 0, (n >> 8) as u8, n as u8])
    }

    /// The statistics of the source keyed `source`, if tracked.
    fn stats_of(gk: &OwnedGoalkeeper, source: IpAddr) -> Option<IpStats> {
        let mut found = None;
        gk.address_stats(|key, stats| {
            if key == source {
                found = Some(stats);
            }
        });
        found
    }

    #[test]
    fn an_address_may_connect_and_the_permit_frees_its_slot() {
        let gk = OwnedGoalkeeper::new();
        let permit = gk
            .connection_permit(ip(1), "test")
            .expect("first connection");
        assert_eq!(gk.total_connections(), 1);
        drop(permit);
        assert_eq!(gk.total_connections(), 0);
    }

    #[test]
    fn masking_keeps_the_prefix() {
        let v4 = IpAddr::from([198, 51, 100, 7]);
        assert_eq!(mask(v4, (32, 128)), v4);
        assert_eq!(mask(v4, (24, 128)), IpAddr::from([198, 51, 100, 0]));
        assert_eq!(mask(v4, (8, 128)), IpAddr::from([198, 0, 0, 0]));
        assert_eq!(mask(v4, (0, 128)), IpAddr::from([0, 0, 0, 0]));
        let v6: IpAddr = "2001:db8:1234:5678::1".parse().unwrap();
        assert_eq!(mask(v6, (32, 128)), v6);
        assert_eq!(
            mask(v6, (32, 48)),
            "2001:db8:1234::".parse::<IpAddr>().unwrap()
        );
        assert_eq!(mask(v6, (32, 16)), "2001::".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn sources_group_and_separate_addresses_as_configured() {
        let gk = OwnedGoalkeeper::new();
        let (a, b) = (IpAddr::from([10, 0, 0, 1]), IpAddr::from([10, 0, 0, 2]));
        // By default each address is its own source.
        let _first = [
            gk.connection_permit(a, "test").unwrap(),
            gk.connection_permit(b, "test").unwrap(),
        ];
        assert_eq!(stats_of(&gk, a).unwrap().connections, 1);
        assert_eq!(stats_of(&gk, b).unwrap().connections, 1);

        let gk = OwnedGoalkeeper::new();
        gk.set_source_prefixes(24, 48);
        let _second = [
            gk.connection_permit(a, "test").unwrap(),
            gk.connection_permit(b, "test").unwrap(),
        ];
        let network = IpAddr::from([10, 0, 0, 0]);
        let stats = stats_of(&gk, network).expect("one source for the /24");
        assert_eq!(stats.connections, 2);
        assert_eq!(stats.addresses, 2);
        assert!(stats_of(&gk, a).is_none());
    }

    #[test]
    fn permits_and_sessions_free_their_slot_after_a_settings_change() {
        let gk = OwnedGoalkeeper::new();
        let address = ip(5);
        let permit = gk.connection_permit(address, "test").unwrap();
        let session = gk.active_session(address);
        gk.set_source_prefixes(24, 48);
        // Counted against the address, so given back to it.
        drop(permit);
        drop(session);
        assert_eq!(gk.total_connections(), 0);
        let stats = stats_of(&gk, address).unwrap();
        assert_eq!((stats.connections, stats.active_sessions), (0, 0));
        // And the other way round.
        let permit = gk.connection_permit(address, "test").unwrap();
        gk.set_source_prefixes(32, 128);
        drop(permit);
        assert_eq!(
            stats_of(&gk, mask(address, (24, 48))).unwrap().connections,
            0
        );
    }

    /// A limiter whose sources may each hold two connections (one per
    /// session, none held, plus one while calm), from a pool of 10.
    fn tight() -> OwnedGoalkeeper {
        let gk = OwnedGoalkeeper::new();
        gk.set_connections_per_active(1, 1);
        gk.set_total_connection_limits(90, 100);
        gk.set_borrow(10);
        gk
    }

    /// Permits for `ip` until one is refused.
    fn until_refused(gk: &OwnedGoalkeeper, ip: IpAddr) -> Vec<ConnectionPermit<ArcGoalkeeper>> {
        let mut permits = Vec::new();
        while let Some(permit) = gk.connection_permit(ip, "test") {
            permits.push(permit);
            assert!(permits.len() <= 100, "never refused");
        }
        permits
    }

    /// Connections `ip`'s source, keyed by the default prefixes, has on loan.
    fn borrowed(gk: &OwnedGoalkeeper, ip: IpAddr) -> u32 {
        stats_of(gk, ip).map_or(0, |stats| stats.borrowed)
    }

    #[test]
    fn a_source_borrows_against_its_bank() {
        let gk = tight();
        gk.set_borrow_prefixes(8, 16);
        gk.set_borrow_per_bank(3);
        let a = IpAddr::from([10, 0, 0, 1]);
        let _a = until_refused(&gk, a);
        // Its own two, then what its /8 may borrow.
        assert_eq!(_a.len(), 5);
        assert_eq!(borrowed(&gk, a), 3);
        // Another source in the same /8 has its own allowance, but nothing to
        // borrow; one in another /8 borrows its bank's share.
        let neighbour = IpAddr::from([10, 9, 9, 9]);
        assert_eq!(until_refused(&gk, neighbour).len(), 2);
        let elsewhere = IpAddr::from([11, 0, 0, 1]);
        let _elsewhere = until_refused(&gk, elsewhere);
        assert_eq!(_elsewhere.len(), 5);
        assert_eq!(gk.borrowed_connections(), 6);
    }

    #[test]
    fn whichever_connection_closes_a_loan_is_returned_first() {
        let gk = tight();
        let a = ip(1);
        let mut permits: Vec<_> = (0..5)
            .map(|_| gk.connection_permit(a, "test").unwrap())
            .collect();
        assert_eq!(borrowed(&gk, a), 3);
        // The first, one granted within its allowance.
        drop(permits.remove(0));
        assert_eq!(borrowed(&gk, a), 2);
        assert_eq!(gk.borrowed_connections(), 2);
        // Down to its allowance, it has nothing on loan.
        permits.truncate(2);
        assert_eq!(borrowed(&gk, a), 0);
        assert_eq!(gk.borrowed_connections(), 0);
        drop(permits);
        assert_eq!(gk.total_connections(), 0);
    }

    #[test]
    fn loans_return_to_their_bank_after_a_settings_change() {
        let gk = tight();
        gk.set_borrow_prefixes(8, 16);
        let a = ip(1);
        let first: Vec<_> = (0..3)
            .map(|_| gk.connection_permit(a, "test").unwrap())
            .collect();
        // Borrowed against its /8, and still so after the banks are made /0.
        gk.set_borrow_prefixes(0, 0);
        let second = gk.connection_permit(a, "test").unwrap();
        assert_eq!(borrowed(&gk, a), 2);
        drop((first, second));
        assert_eq!(gk.borrowed_connections(), 0);
        assert!(gk.limiter.with(|l| l.banks.is_empty()));
    }

    #[test]
    fn a_recently_limited_source_may_not_borrow() {
        let gk = tight();
        gk.set_borrow_per_bank(3);
        let a = ip(1);
        // New, and borrowing nonetheless, until its bank has lent its share.
        let mut held = until_refused(&gk, a);
        assert_eq!(held.len(), 5);
        assert_eq!(borrowed(&gk, a), 3);
        // Its bank has room again, but it was refused just now.
        held.pop();
        assert_eq!(borrowed(&gk, a), 2);
        assert!(gk.connection_permit(a, "test").is_none());
        // Another source of that bank, never limited, borrows it.
        assert_eq!(until_refused(&gk, ip(2)).len(), 3);
    }

    #[test]
    fn a_bank_is_never_narrower_than_a_source() {
        let gk = tight();
        gk.set_source_prefixes(8, 16);
        gk.set_borrow_prefixes(24, 64);
        gk.set_borrow_per_bank(3);
        // One /8 source, from addresses in many /24s, borrows one bank's share.
        let _permits: Vec<_> = (0..=255)
            .map_while(|n| gk.connection_permit(IpAddr::from([10, n, 0, 1]), "test"))
            .collect();
        assert_eq!(_permits.len(), 5);
        // Clamped where used, not where set.
        assert_eq!(gk.limiter.with(|l| l.config.borrow_prefixes), (24, 64));
    }

    #[test]
    fn the_pool_bounds_borrowing_from_one_bank_of_everything() {
        let gk = tight();
        gk.set_borrow_prefixes(0, 0);
        gk.set_borrow_per_bank(100);
        let (a, other) = (IpAddr::from([10, 0, 0, 1]), IpAddr::from([11, 0, 0, 1]));
        let a = until_refused(&gk, a);
        // Its own two, then the whole pool.
        assert_eq!(a.len(), 12);
        // Nothing left to borrow for anyone else.
        let other = until_refused(&gk, other);
        assert_eq!(other.len(), 2);
        drop(a);
        assert_eq!(gk.total_connections(), 2);
        assert_eq!(gk.borrowed_connections(), 0);
    }

    #[test]
    fn borrowing_can_be_turned_off() {
        // No bank may borrow, whatever the banks' size.
        let gk = tight();
        gk.set_borrow_per_bank(0);
        gk.set_borrow_prefixes(0, 0);
        assert_eq!(until_refused(&gk, ip(9)).len(), 2);
        // Or nothing may be borrowed in all.
        let gk = tight();
        gk.set_borrow(0);
        assert_eq!(until_refused(&gk, ip(9)).len(), 2);
    }

    #[test]
    fn distinct_addresses_are_estimated() {
        let sketch = |n: u32| {
            (0..n).fold(0u64, |sketch, i| {
                sketch | sketch_bit(IpAddr::from(i.wrapping_mul(2_654_435_761).to_be_bytes()))
            })
        };
        assert_eq!(estimate(0), 0);
        assert_eq!(estimate(sketch(1)), 1);
        assert!(
            (8..=12).contains(&estimate(sketch(10))),
            "{}",
            estimate(sketch(10))
        );
        assert!(
            (50..=200).contains(&estimate(sketch(100))),
            "{}",
            estimate(sketch(100))
        );
        assert_eq!(estimate(u64::MAX), 266);
    }

    #[test]
    fn active_sessions_widen_the_allowance() {
        let config = Config {
            bytes_per_second: 1_000,
            bytes_burst: 1_000,
            per_active_session: 1,
            ..Config::default()
        };
        let bare = scaled(&config, 0);
        let busy = scaled(&config, 3);
        // Four sessions' worth: its own plus one per session.
        assert_eq!(busy.burst(), bare.burst() * 4);
    }

    #[test]
    fn scaling_can_be_turned_off() {
        let config = Config {
            per_active_session: 0,
            ..Config::default()
        };
        assert_eq!(scaled(&config, 10).burst(), scaled(&config, 0).burst());
    }

    #[test]
    fn bandwidth_is_recorded_and_read_back_per_direction() {
        let gk = OwnedGoalkeeper::new();
        let address = ip(2);

        // Sent as traffic rather than as one number, since a token bucket
        // always admits the first spend and charges it forward. Three
        // megabytes, against the shipped 500KB/s.
        let flood = |dir| {
            for _ in 0..10 {
                gk.record_address_bandwidth(address, dir, 300_000);
            }
        };

        assert!(
            !gk.address_over_bandwidth(address, Direction::Rx),
            "nothing sent yet"
        );
        flood(Direction::Rx);
        assert!(gk.address_over_bandwidth(address, Direction::Rx));
        // What the peer sent says nothing about what we sent it, so an upload
        // flood must not throttle the downstream.
        assert!(
            !gk.address_over_bandwidth(address, Direction::Tx),
            "Rx must not spend Tx's allowance"
        );

        // And the same the other way, so neither direction is privileged.
        flood(Direction::Tx);
        assert!(gk.address_over_bandwidth(address, Direction::Tx));
    }

    #[test]
    fn an_unknown_address_is_not_over_anything() {
        let gk = OwnedGoalkeeper::new();
        assert!(!gk.address_over_bandwidth(ip(3), Direction::Tx));
        assert!(!gk.address_over_bandwidth(ip(3), Direction::Rx));
    }

    /// A source over its allowance is refused leases, so it moves nothing and
    /// nothing records it again: its mark must lift with time alone, once it
    /// is back within its burst, or one overdraft stalls it for as long as it
    /// keeps trying (seen on a game server: every download from one address
    /// stopped, new connections before their TLS handshake, until a restart).
    /// Lifted then, not once all of it is paid back, so a source that
    /// overshot by a little is stalled for a little.
    #[test]
    fn an_overdraft_lifts_with_no_further_traffic() {
        let mut limiter = Addresses::default();
        limiter.set_bandwidth_limits(1_000_000, 1_000_000);
        let address = ip(6);
        let start = Instant::now();
        let after = |millis| start + std::time::Duration::from_millis(millis);
        // 3MB at once against 1MB/s and a 1MB burst: the fifth 300KB spend
        // finds 1.2MB owed, past the burst, and is refused. The bytes moved
        // anyway, so it and the other five are owed too, up to two bursts'
        // worth ahead: 2s owed, 1s of it past the burst.
        for _ in 0..10 {
            limiter.record_bandwidth(address, Direction::Tx, 300_000, start);
        }
        assert!(
            limiter.over_bandwidth(address, Direction::Tx, start),
            "over while past the burst"
        );
        assert!(
            limiter.over_bandwidth(address, Direction::Tx, after(950)),
            "the bytes moved while over were let off"
        );
        // No bytes recorded since: only time has passed.
        assert!(
            !limiter.over_bandwidth(address, Direction::Tx, after(1_050)),
            "back within the burst with nothing moving, so no longer over"
        );
        // And it stays lifted until it is overdrawn again.
        assert!(!limiter.over_bandwidth(address, Direction::Tx, after(3_000)));
    }

    /// An eighth of a second, so that dividing by it is exact.
    const WINDOW: Duration = Duration::from_millis(125);

    /// A source's connections may together spend its steady rate and half of
    /// what is left of its burst in a window, in equal shares; and be left at
    /// up to all of what is left.
    #[test]
    fn a_paced_rate_spends_half_the_burst_a_window() {
        let rate = |headroom, share| burst_rate(1_000_000, headroom, share, WINDOW, BURST_WINDOWS);
        assert_eq!(
            rate(8_000_000, 1.0),
            33_000_000,
            "4MB over a window: 32MB/s"
        );
        assert_eq!(rate(8_000_000, 0.25), 8_250_000, "a quarter of it");
        assert_eq!(rate(0, 1.0), 1_000_000, "none of it: the steady rate");
        assert_eq!(
            burst_rate(1_000_000, 8_000_000, 1.0, WINDOW, 1.0),
            65_000_000,
            "the ceiling: 8MB over a window"
        );
    }

    /// A new visitor's first download, which the burst is for, is not held
    /// back by it; the burst refills as what was spent is paid back, not all
    /// at once when all of it has been.
    #[test]
    fn a_source_is_paced_by_what_is_left_of_its_burst() {
        let mut limiter = Addresses::default();
        limiter.set_bandwidth_limits(1_000_000, 8_000_000);
        let address = ip(7);
        let start = Instant::now() + Duration::from_millis(10);
        let after = |millis| start + Duration::from_millis(millis);
        // One connection, asking in the window `now` falls in.
        let rate = |limiter: &mut Addresses, now: Instant| {
            let epoch = (now.duration_since(start).as_nanos() / WINDOW.as_nanos()) as u64;
            limiter
                .bandwidth_rate(address, Direction::Tx, WINDOW, epoch, now)
                .map(|share| share.rate)
        };
        assert_eq!(rate(&mut limiter, start), Some(33_000_000), "never seen");
        // 4MB at once owes 4s, leaving 4MB of the burst.
        for _ in 0..4 {
            limiter.record_bandwidth(address, Direction::Tx, 1_000_000, start);
        }
        assert_eq!(
            rate(&mut limiter, start),
            Some(17_000_000),
            "half the burst left"
        );
        assert_eq!(
            rate(&mut limiter, after(2_000)),
            Some(25_000_000),
            "half of what was spent paid back, so half of it is back"
        );
        assert_eq!(
            rate(&mut limiter, after(4_100)),
            Some(33_000_000),
            "all paid back, so the whole burst again"
        );
    }

    /// A transfer paced as [`Addresses::bandwidth_rate`] says, revisiting it
    /// every window, spends the burst and settles on the steady rate without
    /// ever going over, however long it outlasts the burst. The rate is
    /// applied as `Applied::configure_tx` applies it, leaving it alone until
    /// it moves an eighth unless that would overrun the ceiling, and once
    /// settled, it is left alone.
    #[test]
    fn a_paced_transfer_settles_on_the_steady_rate_without_going_over() {
        let mut limiter = Addresses::default();
        limiter.set_bandwidth_limits(1_000_000, 8_000_000);
        let address = ip(9);
        let start = Instant::now() + Duration::from_millis(10);
        // The link, which is all that holds the transfer back at first.
        const LINK: u64 = 100_000_000;
        let mut moved = 0u64;
        let mut applied: Option<u64> = None;
        let mut settled_syscalls = 0;
        // A minute, in windows.
        for window in 0..480u32 {
            let now = start + WINDOW * window;
            let share = limiter
                .bandwidth_rate(address, Direction::Tx, WINDOW, window.into(), now)
                .unwrap();
            assert_ne!(share.rate, 0, "over in window {window}");
            let apply = applied.is_none_or(|applied| {
                applied.abs_diff(share.rate) > applied / 8 || applied > share.ceiling
            });
            if apply {
                applied = Some(share.rate);
                if window >= 240 {
                    settled_syscalls += 1;
                }
            }
            let rate = applied.unwrap();
            let bytes = (rate.min(LINK) as f64 * WINDOW.as_secs_f64()) as u64;
            // In sixteen writes over the window, as the kernel releases them.
            for write in 0..16u32 {
                let at = now + WINDOW * write / 16;
                limiter.record_bandwidth(address, Direction::Tx, (bytes / 16) as u32, at);
            }
            moved += bytes;
            if window == 0 {
                assert_eq!(
                    bytes, 4_125_000,
                    "the first window: half the burst, and the steady rate"
                );
            }
        }
        // The burst and a minute at the steady rate: a little under, for what
        // was left unspent of the burst, or a write over, since what is owed
        // is weighed before a write rather than after it.
        assert!(
            (67_000_000..=68_100_000).contains(&moved),
            "{moved}: the burst was not spent, or was overspent"
        );
        assert_eq!(
            settled_syscalls, 0,
            "the rate reapplied in the last half minute, long settled"
        );
    }

    /// A source with nothing open is kept while it owes anything, so that it
    /// does not get a fresh allowance, and for the memory after it was last
    /// limited, so that it stays under stricter terms; and otherwise forgotten,
    /// so that a flood of sources that merely moved a byte does not stay.
    #[test]
    fn a_source_is_remembered_while_it_owes_or_was_limited_lately() {
        let mut limiter = Addresses::default();
        limiter.set_bandwidth_limits(1_000_000, 1_000_000);
        let limited = ip(10);
        let seen = ip(11);
        let overdrawn = ip(13);
        let start = Instant::now() + Duration::from_millis(10);
        let after = |millis| start + Duration::from_millis(millis);
        let known = |limiter: &Addresses, ip| limiter.usage.get(&limiter.source(ip)).is_some();
        // Refused a connection, which is what marks a source limited, and
        // owing nothing.
        let source = limiter.source(limited);
        limiter.entry(source).last_limit = Some(start);
        // A kilobyte, owing a millisecond.
        limiter.record_bandwidth(seen, Direction::Tx, 1_000, start);
        // Over: 3MB against a 1MB burst. The third finds 2MB owed, past the
        // burst, so is refused and owed too, for 2s in all, two bursts'
        // worth. Over its allowance, but not limited: that is for connecting.
        for _ in 0..3 {
            limiter.record_bandwidth(overdrawn, Direction::Tx, 1_000_000, start);
        }
        assert!(limiter.over_bandwidth(overdrawn, Direction::Tx, start));
        assert_eq!(
            limiter
                .usage
                .get(&limiter.source(overdrawn))
                .unwrap()
                .last_limit,
            None,
            "an overdraft marked the source limited"
        );

        limiter.prune(start);
        assert!(
            known(&limiter, limited) && known(&limiter, seen) && known(&limiter, overdrawn),
            "limited, or still owing"
        );

        limiter.prune(after(10_000));
        assert!(
            known(&limiter, limited),
            "limited within the memory, so remembered"
        );
        assert!(
            !known(&limiter, seen),
            "paid back and never limited, so forgotten"
        );
        assert!(
            !known(&limiter, overdrawn),
            "overdrawn, but paid back and never limited, so forgotten"
        );

        limiter.prune(after(5 * 60 * 1_000 + 1));
        assert!(
            !known(&limiter, limited),
            "limited before the memory, so forgotten"
        );
    }

    /// Past its burst, a source is over, and paced connections are stood down
    /// as before.
    #[test]
    fn a_source_past_its_burst_is_not_paced() {
        let mut limiter = Addresses::default();
        limiter.set_bandwidth_limits(1_000_000, 8_000_000);
        let address = ip(8);
        let start = Instant::now() + Duration::from_millis(10);
        for _ in 0..10 {
            limiter.record_bandwidth(address, Direction::Tx, 1_000_000, start);
        }
        assert_eq!(
            limiter
                .bandwidth_rate(address, Direction::Tx, WINDOW, 0, start)
                .map(|share| share.rate),
            Some(0)
        );
    }

    /// A source's allowance is shared among the connections moving bytes, not
    /// all it holds open: as many as asked for their rate last window. One
    /// left busy alone among idle ones gets all of it once the others have
    /// been quiet for a whole window. One asking past last window's count is
    /// given a share among all that are open, and only what is unclaimed.
    #[test]
    fn a_source_is_shared_among_its_busy_connections() {
        // Ten open, most of them idle throughout.
        const OPEN: u32 = 10;
        let mut pacers = Pacers::default();
        assert_eq!(pacers.ask(5, OPEN), 0.1, "nothing to go by: a tenth");
        assert_eq!(pacers.ask(5, OPEN), 0.1, "nor for the second");
        assert_eq!(pacers.ask(6, OPEN), 0.5, "two asked last window: halves");
        assert_eq!(pacers.ask(7, OPEN), 1.0, "the second quiet for a window");
        assert_eq!(
            pacers.ask(7, OPEN),
            0.0,
            "a newcomer, with all of it claimed: nothing, for a window"
        );
        assert_eq!(pacers.ask(8, OPEN), 0.5, "then halves");
        assert_eq!(pacers.ask(8, OPEN), 0.5);
        assert_eq!(
            pacers.ask(10, OPEN),
            0.1,
            "a window skipped: nothing to go by"
        );
    }

    /// However many ask in a window, and however few are thought open, the
    /// shares handed out never add up to more than the whole.
    #[test]
    fn shares_never_add_up_past_the_whole() {
        for open in [0, 1, 3, 6, 100] {
            let mut pacers = Pacers::default();
            for epoch in [1, 2, 4] {
                let total: f32 = (0..12).map(|_| pacers.ask(epoch, open)).sum();
                assert!(total <= 1.0 + 1e-6, "{total} handed out, {open} open");
            }
        }
    }

    /// A browser opening six connections at once, at the defaults: between
    /// them, the first window spends no more than is left of the burst.
    #[test]
    fn connections_starting_together_do_not_overspend_the_burst() {
        let mut limiter = Addresses::default();
        limiter.set_bandwidth_limits(500_000, 1_000_000);
        let address = ip(14);
        let start = Instant::now() + Duration::from_millis(10);
        limiter.record_bandwidth(address, Direction::Tx, 1, start);
        let source = limiter.source(address);
        limiter.entry(source).connections = 6;
        let total: u64 = (0..6)
            .map(|_| {
                limiter
                    .bandwidth_rate(address, Direction::Tx, WINDOW, 3, start)
                    .unwrap()
                    .rate
            })
            .sum();
        let spent = total as f64 * WINDOW.as_secs_f64();
        // What is left, and what the window pays back.
        let allowed = 1_000_000.0 + 500_000.0 * WINDOW.as_secs_f64();
        assert!(spent <= allowed, "{spent} spent of {allowed}");
    }

    /// Shared however many ways, a connection is not paced below the floor.
    #[test]
    fn a_share_is_not_below_the_floor() {
        assert_eq!(
            burst_rate(500_000, 0, 0.001, WINDOW, BURST_WINDOWS),
            MIN_PACED_RATE
        );
    }

    /// However much is recorded while over, the mark lifts within a burst's
    /// worth of the steady rate once it stops. Recording is public, and for
    /// UDP the source may be spoofed: a flood in a victim's name must not
    /// lock the victim out for as long as the flood was large.
    #[test]
    fn an_overdraft_is_owed_up_to_a_burst() {
        let mut limiter = Addresses::default();
        // 2s to repay a burst.
        limiter.set_bandwidth_limits(500_000, 1_000_000);
        let address = ip(7);
        let start = Instant::now();
        let after = |millis| start + std::time::Duration::from_millis(millis);
        // 1GB over 10s, which at the steady rate would take over half an hour
        // to repay. Owed two bursts ahead throughout, so never back within
        // one while it lasts, and back within one 2s after it stops.
        for i in 0..1_000 {
            limiter.record_bandwidth(address, Direction::Rx, 1_000_000, after(i * 10));
        }
        assert!(
            limiter.over_bandwidth(address, Direction::Rx, after(10_000)),
            "the flood lifted while it lasted"
        );
        assert!(
            !limiter.over_bandwidth(address, Direction::Rx, after(13_000)),
            "still over long after the flood stopped"
        );
    }

    #[test]
    fn sessions_are_counted_while_held() {
        let gk = OwnedGoalkeeper::new();
        let address = ip(4);
        let seen = |target: IpAddr| stats_of(&gk, target).map_or(0, |s| s.active_sessions);
        let a = gk.active_session(address);
        let b = gk.active_session(address);
        assert_eq!(seen(address), 2);
        drop(a);
        assert_eq!(seen(address), 1);
        drop(b);
        assert_eq!(seen(address), 0);
    }

    /// A pool, for a case that needs one.
    const POOL: NonZeroU16 = NonZeroU16::new(7).unwrap();

    /// Every address in [`POOL`] with `cap`, enforced or not.
    fn all_in(gk: &OwnedGoalkeeper, cap: u32, enforce: bool) {
        gk.set_pools(Some(Arc::new(move |_: IpAddr| {
            Pools::new().with(Pool {
                id: POOL,
                cap,
                enforce,
            })
        })));
    }

    #[test]
    fn an_enforced_pool_refuses_at_its_cap() {
        let gk = OwnedGoalkeeper::new();
        all_in(&gk, 2, true);
        // Each its own source, so only the pool is in the way.
        let a = gk.connection_permit(ip(10), "test").unwrap();
        let _b = gk.connection_permit(ip(11), "test").unwrap();
        assert!(gk.connection_permit(ip(12), "test").is_none());
        drop(a);
        assert!(gk.connection_permit(ip(13), "test").is_some());
    }

    #[test]
    fn an_unenforced_pool_counts_what_is_over() {
        let gk = OwnedGoalkeeper::new();
        all_in(&gk, 1, false);
        let _a = gk.connection_permit(ip(10), "test").unwrap();
        let _b = gk.connection_permit(ip(11), "test").unwrap();
        let stats = gk.take_pool_stats();
        assert_eq!(
            stats,
            vec![(
                POOL,
                PoolStats {
                    connections: 2,
                    peak: 2,
                    over: 1,
                }
            )]
        );
        // Taken afresh: the peak is what it holds, and nothing is over.
        assert_eq!(gk.take_pool_stats()[0].1.over, 0);
    }

    #[test]
    fn only_the_addresses_in_a_pool_count_against_it() {
        let gk = OwnedGoalkeeper::new();
        let member = ip(20);
        gk.set_pools(Some(Arc::new(move |address: IpAddr| {
            if address == member {
                Pools::new().with(Pool {
                    id: POOL,
                    cap: 1,
                    enforce: true,
                })
            } else {
                Pools::new()
            }
        })));
        let _a = gk.connection_permit(member, "test").unwrap();
        assert!(gk.connection_permit(member, "test").is_none());
        assert!(gk.connection_permit(ip(21), "test").is_some());
    }

    #[test]
    fn a_permit_gives_back_to_the_pools_it_was_counted_in() {
        let gk = OwnedGoalkeeper::new();
        all_in(&gk, 1, true);
        let a = gk.connection_permit(ip(10), "test").unwrap();
        gk.set_pools(None);
        drop(a);
        assert_eq!(gk.take_pool_stats()[0].1.connections, 0);
        // Forgotten, once reported holding nothing.
        assert!(gk.take_pool_stats().is_empty());
    }
}
