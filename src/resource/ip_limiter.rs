//! Per-address connection and bandwidth limiting.
//!
//! One limiter per [`Goalkeeper`][crate::Goalkeeper], which for a deployment
//! means one, since the host's sockets and its uplink are one thing. Tests take
//! an instance of their own and get a limiter of their own with it.
//!
//! An address is not a client: a carrier-grade NAT presents hundreds of players
//! as one, so an address holding many [`ActiveSession`]s is allowed
//! proportionally more. Sessions become active only once something upstream has
//! decided they are real, so headroom cannot be minted by opening sockets.

use crate::rate_limiter::{RateLimiterProps, RateLimiterState, Units};
use crate::resource::bandwidth::Direction;
use crate::{ProvideGoalkeeper, SystemGoalkeeper};
use fxhash::FxHashMap;
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
    /// Bytes per second one address may move before being throttled, before
    /// any scaling for active sessions.
    pub bytes_per_second: Units,
    /// Bytes one address may move in a burst, before scaling.
    pub bytes_burst: Units,
    /// How much of the base allowance each active session adds.
    ///
    /// One means an address with three sessions gets four times the base, its
    /// own plus one per session. Zero disables scaling entirely.
    pub per_active_session: u32,
    /// Connections per active session an address may hold under ordinary
    /// conditions.
    ///
    /// For an HTTP/1-only server, 4–6; for HTTP/2 with HTTP/1 WebSockets, 2;
    /// for HTTP/2 throughout, 1.
    pub connections_per_active_p90: u32,
    /// As [`Self::connections_per_active_p90`], for the rare address that has
    /// earned the benefit of the doubt.
    pub connections_per_active_p99: u32,
    /// Connections across all addresses before each address is afforded fewer.
    pub total_connections_soft_limit: u32,
    /// Connections across all addresses before new ones are refused outright.
    pub total_connections_hard_limit: u32,
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
            bytes_per_second: 500_000,
            bytes_burst: 1_000_000,
            per_active_session: 1,
            connections_per_active_p90: 1,
            connections_per_active_p99: 6,
            total_connections_soft_limit: 400,
            total_connections_hard_limit: 1000,
            ddos_memory: Duration::from_secs(5 * 60),
            custom: RateLimiterProps::no_limit(),
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

/// What every address is rationed against.
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

/// An address's allowance, widened by how many sessions it has proved it
/// carries.
fn scaled(config: &Config, actives: u32) -> RateLimiterProps {
    let factor = 1 + actives.saturating_mul(config.per_active_session);
    let per_second = config.bytes_per_second.saturating_mul(factor);
    // A rate limiter spaces units `1s / throughput` apart, which rounds to
    // nothing past a billion a second. Scaling a generous configured limit by an
    // address's active sessions reaches that easily, and no limit is what it
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

/// Summary statistics for one address. Forgotten after a long enough quiet
/// period.
#[derive(Copy, Clone, Debug)]
#[non_exhaustive]
pub struct IpStats {
    /// When this address was first seen.
    pub first: Instant,
    /// Outstanding [`ConnectionPermit`]s.
    pub connections: u32,
    /// Outstanding [`ActiveSession`]s.
    pub active_sessions: u32,
    /// When this address last hit a hard limit.
    pub last_limit: Option<Instant>,
}

/// A permissible, long-lived connection. Hold it for the connection's life.
///
/// Carries the handle it was issued against, so it gives its slot back to the
/// instance that granted it. Against [`SystemGoalkeeper`] that handle is
/// zero-sized.
///
/// [`SystemGoalkeeper`]: crate::SystemGoalkeeper
#[derive(Debug)]
pub struct ConnectionPermit<P: ProvideGoalkeeper = SystemGoalkeeper> {
    ip: IpAddr,
    provider: P,
}

impl<P: ProvideGoalkeeper> ConnectionPermit<P> {
    pub(crate) fn new(ip: IpAddr, provider: P) -> Self {
        Self { ip, provider }
    }

    /// The instance that issued this, for whatever the connection does next.
    pub fn provider(&self) -> &P {
        &self.provider
    }

    /// The address this permits.
    pub fn ip(&self) -> IpAddr {
        self.ip
    }
}

impl<P: ProvideGoalkeeper> Drop for ConnectionPermit<P> {
    fn drop(&mut self) {
        self.provider.limiter.with(|limiter| {
            if let Some(usage) = limiter.usage.get_mut(&self.ip) {
                debug_assert!(usage.stats.connections > 0);
                usage.stats.connections = usage.stats.connections.saturating_sub(1);
            } else {
                debug_assert!(false, "permit outlived its address's record");
            }
            // Subtracted even if the record went missing, so the total cannot
            // drift upwards and lock everyone out.
            debug_assert!(limiter.total_connections > 0);
            limiter.total_connections = limiter.total_connections.saturating_sub(1);
        })
    }
}

/// A connection with meaningful activity on it: an authenticated socket rather
/// than merely an open one. See the module docs for why this earns headroom.
#[derive(Debug)]
pub struct ActiveSession<P: ProvideGoalkeeper = SystemGoalkeeper> {
    ip: IpAddr,
    provider: P,
}

impl<P: ProvideGoalkeeper> ActiveSession<P> {
    pub(crate) fn new(ip: IpAddr, provider: P) -> Self {
        Self { ip, provider }
    }
}

impl<P: ProvideGoalkeeper> Drop for ActiveSession<P> {
    fn drop(&mut self) {
        self.provider.limiter.with(|limiter| {
            if let Some(usage) = limiter.usage.get_mut(&self.ip) {
                debug_assert!(usage.stats.active_sessions > 0);
                usage.stats.active_sessions = usage.stats.active_sessions.saturating_sub(1);
            } else {
                debug_assert!(false, "session outlived its address's record");
            }
        })
    }
}

/// Rate at which the limiter is willing to talk about being limited.
const WARNING_LIMIT: RateLimiterProps = RateLimiterProps::const_new(Duration::from_secs(1), 0);

/// The per-address state.
#[derive(Debug)]
pub(crate) struct Addresses {
    config: Config,
    usage: FxHashMap<IpAddr, Usage>,
    next_prune: Instant,
    warning_limiter: RateLimiterState,
    total_connections: u32,
    /// See [`permit_counts`].
    permits: u32,
    permits_withheld: u32,
    last_soft_limit: Option<Instant>,
    /// Addresses seen recently, used to decide whether an address is rare
    /// enough to deserve the benefit of the doubt.
    new_ip_counter: u32,
}

impl Default for Addresses {
    fn default() -> Self {
        Self {
            config: Config::default(),
            usage: FxHashMap::default(),
            next_prune: Instant::now(),
            warning_limiter: RateLimiterState::default(),
            total_connections: 0,
            permits: 0,
            permits_withheld: 0,
            last_soft_limit: None,
            new_ip_counter: 200,
        }
    }
}

#[derive(Debug)]
pub(crate) struct Usage {
    /// Indexed by [`Direction`]; see its docs for why they are separate.
    bandwidth: [RateLimiterState; 2],
    custom: RateLimiterState,
    stats: IpStats,
    over_bandwidth: [bool; 2],
    /// This address is in the rare top percentile and gets the looser limit.
    granted_rare_exemption: bool,
}

/// The setters and readers [`ProvideGoalkeeper`] is written in terms of.
///
/// One per configured field rather than a `Config` struct, since a struct means
/// a caller changing one number either restates the rest or leans on
/// `..Default::default()`, which silently reverts anything set earlier.
impl Addresses {
    pub(crate) fn stats(&self) -> impl Iterator<Item = (IpAddr, IpStats)> + '_ {
        self.usage.iter().map(|(ip, usage)| (*ip, usage.stats))
    }

    pub(crate) fn total_connections(&self) -> u32 {
        self.total_connections
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

    pub(crate) fn set_ddos_memory(&mut self, memory: Duration) {
        self.config.ddos_memory = memory;
    }

    pub(crate) fn set_custom_limit(&mut self, props: RateLimiterProps) {
        self.config.custom = props;
    }

    pub(crate) fn enter_session(&mut self, ip: IpAddr) {
        self.entry(ip).stats.active_sessions += 1;
    }

    pub(crate) fn should_limit_custom(&mut self, ip: IpAddr, usage: Units, now: Instant) -> bool {
        let props = self.config.custom;
        self.entry(ip)
            .custom
            .should_limit_rate_with_now_and_usage(&props, now, usage)
    }
}

impl Addresses {
    /// See [`IpLimiter::record_bandwidth`].
    pub(crate) fn record_bandwidth(
        &mut self,
        ip: IpAddr,
        dir: Direction,
        bytes: Units,
        now: Instant,
    ) {
        let config = self.config;
        let entry = self.entry(ip);
        let actives = entry.stats.active_sessions;
        // Both directions are measured against the same allowance, which keeps
        // the configuration to one pair.
        let props = scaled(&config, actives);
        let over =
            entry.bandwidth[dir as usize].should_limit_rate_with_now_and_usage(&props, now, bytes);
        entry.over_bandwidth[dir as usize] = over;
        if over {
            entry.stats.last_limit = Some(now);
        }
        self.maybe_prune(now);
    }

    /// See [`IpLimiter::over_bandwidth`].
    pub(crate) fn over_bandwidth(&self, ip: IpAddr, dir: Direction) -> bool {
        self.usage
            .get(&ip)
            .map(|entry| entry.over_bandwidth[dir as usize])
            .unwrap_or(false)
    }

    pub(crate) fn entry(&mut self, ip: IpAddr) -> &mut Usage {
        let now = Instant::now();
        let counter = &mut self.new_ip_counter;
        self.usage.entry(ip).or_insert_with(|| {
            *counter = counter.saturating_add(1);
            Usage {
                bandwidth: std::array::from_fn(|_| RateLimiterState {
                    until: now,
                    burst_used: 0,
                }),
                custom: RateLimiterState {
                    until: now,
                    burst_used: 0,
                },
                stats: IpStats {
                    first: now,
                    connections: 0,
                    active_sessions: 0,
                    last_limit: None,
                },
                over_bandwidth: [false; 2],
                granted_rare_exemption: false,
            }
        })
    }

    /// Whether `ip` may open another connection, and the accounting either way.
    ///
    /// Returns the address rather than a guard, since a guard must carry the
    /// handle that issued it and this runs inside the lock. The caller wraps
    /// it.
    pub(crate) fn connection_permit(&mut self, ip: IpAddr, label: &'static str) -> Option<IpAddr> {
        self.permits = self.permits.saturating_add(1);
        let now = Instant::now();
        let config = self.config;

        if self.total_connections >= config.total_connections_hard_limit {
            self.permits_withheld = self.permits_withheld.saturating_add(1);
            self.warn(ip, label, "host is at its connection ceiling", now);
            return None;
        }

        // Opening a connection is not free, so it is charged against the
        // address's bandwidth. `Rx`, since connecting is the peer's decision.
        const CONNECT_COST: Units = 10_000;
        let actives = self.entry(ip).stats.active_sessions;
        let props = scaled(&config, actives);
        let entry = self.entry(ip);
        if entry.bandwidth[Direction::Rx as usize].should_limit_rate_with_now_and_usage(
            &props,
            now,
            CONNECT_COST,
        ) {
            entry.stats.last_limit = Some(now);
            self.permits_withheld = self.permits_withheld.saturating_add(1);
            self.warn(ip, label, "connecting too fast", now);
            return None;
        }

        // Read rather than stored, so it reflects the newest window rather than
        // whenever the application last reported.
        let soft_limit_reached = crate::resource::strained()
            || self.total_connections >= config.total_connections_soft_limit;
        if soft_limit_reached {
            self.last_soft_limit = Some(now);
        }
        let recent_global = self
            .last_soft_limit
            .is_some_and(|last| now.duration_since(last) < config.ddos_memory);
        let entry = self.entry(ip);
        let old = now.duration_since(entry.stats.first) > Duration::from_secs(60);
        let recent_local = entry
            .stats
            .last_limit
            .is_some_and(|last| now.duration_since(last) < config.ddos_memory);
        let strict = (!old || recent_local) && recent_global;

        // A rare address that has never been limited gets the benefit of the
        // doubt while everyone else is held tight, which keeps a genuinely busy
        // NAT from being shed alongside an attack.
        let exempt = if entry.granted_rare_exemption {
            true
        } else if strict && !recent_local && self.new_ip_counter >= 100 {
            self.new_ip_counter = (self.new_ip_counter - 100).min(self.new_ip_counter / 2);
            self.entry(ip).granted_rare_exemption = true;
            true
        } else {
            false
        };

        let entry = self.entry(ip);
        let per_active = if strict && !exempt {
            config.connections_per_active_p90
        } else {
            config.connections_per_active_p99
        };
        let limit = (entry.stats.active_sessions + 1 + (!strict) as u32).saturating_mul(per_active);

        if entry.stats.connections >= limit {
            entry.stats.last_limit = Some(now);
            self.permits_withheld = self.permits_withheld.saturating_add(1);
            self.warn(ip, label, "too many connections", now);
            None
        } else {
            entry.stats.connections += 1;
            self.total_connections += 1;
            Some(ip)
        }
    }

    /// Says something about a limited address, at most once a second across the
    /// whole process. Under a distributed flood, logging each refusal would be
    /// the louder denial of service.
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
                || usage.stats.active_sessions > 0
                || usage.stats.connections > 0
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tests share one global limiter, so they use distinct addresses rather
    /// than distinct limiters.
    fn ip(n: u16) -> IpAddr {
        IpAddr::from([10, 0, (n >> 8) as u8, n as u8])
    }

    #[test]
    fn an_address_may_connect_and_the_permit_frees_its_slot() {
        let before = SystemGoalkeeper.total_connections();
        let permit = SystemGoalkeeper
            .connection_permit(ip(1), "test")
            .expect("first connection");
        assert_eq!(SystemGoalkeeper.total_connections(), before + 1);
        drop(permit);
        assert_eq!(SystemGoalkeeper.total_connections(), before);
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
        let address = ip(2);

        // Sent as traffic rather than as one number, since a token bucket
        // always admits the first spend and charges it forward. Three
        // megabytes, against the shipped 500KB/s.
        //
        // Not `configure`d, so this does not race the tests that are: the
        // assertions below hold under any configuration at least as tight as
        // the default.
        let flood = |dir| {
            for _ in 0..10 {
                SystemGoalkeeper.record_address_bandwidth(address, dir, 300_000);
            }
        };

        assert!(
            !SystemGoalkeeper.address_over_bandwidth(address, Direction::Rx),
            "nothing sent yet"
        );
        flood(Direction::Rx);
        assert!(SystemGoalkeeper.address_over_bandwidth(address, Direction::Rx));
        // What the peer sent says nothing about what we sent it, so an upload
        // flood must not throttle the downstream.
        assert!(
            !SystemGoalkeeper.address_over_bandwidth(address, Direction::Tx),
            "Rx must not spend Tx's allowance"
        );

        // And the same the other way, so neither direction is privileged.
        flood(Direction::Tx);
        assert!(SystemGoalkeeper.address_over_bandwidth(address, Direction::Tx));
    }

    #[test]
    fn an_unknown_address_is_not_over_anything() {
        assert!(!SystemGoalkeeper.address_over_bandwidth(ip(3), Direction::Tx));
        assert!(!SystemGoalkeeper.address_over_bandwidth(ip(3), Direction::Rx));
    }

    #[test]
    fn sessions_are_counted_while_held() {
        let address = ip(4);
        let seen = |target: IpAddr| {
            let mut actives = 0;
            SystemGoalkeeper.address_stats(|ip, s| {
                if ip == target {
                    actives = s.active_sessions;
                }
            });
            actives
        };
        let a = SystemGoalkeeper.active_session(address);
        let b = SystemGoalkeeper.active_session(address);
        assert_eq!(seen(address), 2);
        drop(a);
        assert_eq!(seen(address), 1);
        drop(b);
        assert_eq!(seen(address), 0);
    }
}
