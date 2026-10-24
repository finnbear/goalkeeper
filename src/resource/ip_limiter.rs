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

use crate::ip_map::{Entry, IpMap};
use crate::rate_limiter::{RateLimiterProps, RateLimiterState, Units};
use crate::resource::bandwidth::Direction;
use crate::{ProvideGoalkeeper, SystemGoalkeeper};
use log::warn;
use std::net::IpAddr;
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

/// A source's allowance, widened by how many sessions it has proved it
/// carries.
fn scaled(config: &Config, actives: u32) -> RateLimiterProps {
    let factor = 1 + actives.saturating_mul(config.per_active_session);
    let per_second = config.bytes_per_second.saturating_mul(factor);
    // A rate limiter spaces units `1s / throughput` apart, which rounds to
    // nothing past a billion a second. Scaling a generous configured limit by a
    // source's active sessions reaches that easily, and no limit is what it
    // means, so it is said rather than derived.
    if per_second >= 1_000_000_000 {
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
    /// When this source last hit a hard limit.
    pub last_limit: Option<Instant>,
}

/// What the limiter granted a connection: the address, and the source it was
/// counted against.
///
/// Not whether it was borrowed, since loans belong to the source rather than
/// to any one connection (see the module docs).
#[derive(Copy, Clone, Debug)]
pub(crate) struct Grant {
    ip: IpAddr,
    source: IpAddr,
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
        let over =
            entry.bandwidth[dir as usize].should_limit_rate_with_now_and_usage(&props, now, bytes);
        entry.over_bandwidth[dir as usize] = over;
        if over {
            entry.last_limit = Some(now);
        }
        self.maybe_prune(now);
    }

    /// See [`IpLimiter::over_bandwidth`].
    pub(crate) fn over_bandwidth(&self, ip: IpAddr, dir: Direction) -> bool {
        self.usage
            .get(&self.source(ip))
            .map(|entry| entry.over_bandwidth[dir as usize])
            .unwrap_or(false)
    }

    /// The record of `source`, an address already masked to its source.
    pub(crate) fn entry(&mut self, source: IpAddr) -> &mut Usage {
        self.usage
            .entry(source)
            .or_insert_with(|| Usage::new(Instant::now()))
    }

    /// Whether `ip` may open another connection, and the accounting either way.
    ///
    /// Returns what was granted rather than a guard, since a guard must carry
    /// the handle that issued it and this runs inside the lock. The caller
    /// wraps it.
    pub(crate) fn connection_permit(
        &mut self,
        ip: IpAddr,
        label: &'static str,
        strained: bool,
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

        // Held for the rest, rather than looked up again: the other fields
        // touched are disjoint from it.
        let usage = self.usage.entry(source).or_insert_with(|| Usage::new(now));

        // Opening a connection is not free, so it is charged against the
        // source's bandwidth. `Rx`, since connecting is the peer's decision.
        const CONNECT_COST: Units = 10_000;
        usage.addresses |= sketch_bit(ip);
        let props = scaled(&config, usage.active_sessions);
        if usage.bandwidth[Direction::Rx as usize].should_limit_rate_with_now_and_usage(
            &props,
            now,
            CONNECT_COST,
        ) {
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
        Some(Grant { ip, source })
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

    fn prune(&mut self, now: Instant) {
        let forget = now + self.config.ddos_memory;
        self.usage.retain(|_, usage| {
            usage.bandwidth.iter().any(|state| state.until > forget)
                || usage.custom.until > forget
                || usage.active_sessions > 0
                || usage.connections > 0
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ArcGoalkeeper, OwnedGoalkeeper};

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
}
