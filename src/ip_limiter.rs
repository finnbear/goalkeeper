//! Per-IP connection and bandwidth limiter.

use crate::rate_limiter::{RateLimiterProps, RateLimiterState, Units};
use fxhash::FxHashMap;
use log::warn;
use rand::random;
use std::net::IpAddr;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

static SINGLETON: LazyLock<Mutex<IpLimiter>> =
    LazyLock::new(|| Mutex::new(IpLimiter::new(500000, 0)));

/// Limits connections and bandwidth based on client IP addresses.
#[derive(Debug)]
pub struct IpLimiter {
    usage: FxHashMap<IpAddr, Usage>,
    props: RateLimiterProps,
    next_prune: Instant,
    warning_limiter: RateLimiterState,
    connections_per_active_p90: u32,
    connections_per_active_p99: u32,
    total_connection_permits: u32,
    total_connections_soft_limit: u32,
    total_connections_hard_limit: u32,
}

/// Summary statistics for a given IP.
#[derive(Copy, Clone, Debug)]
#[non_exhaustive]
pub struct IpStats {
    /// First connection (since the last time this IP was last garbage collected).
    pub first: Instant,
    /// Number of outstanding [ConnectionPermit]s.
    pub connection_permits: u32,
    /// Number of outstanding [ActiveSession]s.
    pub active_sessions: u32,
    /// Counts the number of this times this IP hit a hard limit.
    pub hard_limited: u32,
}

impl IpStats {
    fn increment_hard_limited(&mut self) {
        self.hard_limited = self.hard_limited.saturating_add(1);
    }
}

impl IpLimiter {
    /// Visit the [IpStats] for each tracked IP.
    ///
    /// The `visitor` should never block.
    pub fn stats(mut visitor: impl FnMut(IpAddr, IpStats)) {
        let this = SINGLETON.lock().unwrap();
        for (ip, v) in &this.usage {
            visitor(*ip, v.stats);
        }
    }

    /// Total number of outstanding [ConnectionPermit]s.
    pub fn total_connections() -> u32 {
        let this = SINGLETON.lock().unwrap();
        this.total_connection_permits
    }

    /// Set the bandwidth limits for the [IpLimiter] singleton.
    ///
    /// The `bytes_per_second` should be less than 1,000,000,000.
    ///
    /// Default: 500,000 bytes per second, 0 bytes burst.
    pub fn set_bandwidth_limits(bytes_per_second: Units, bytes_burst: Units) {
        let mut this = SINGLETON.lock().unwrap();
        this.props = RateLimiterProps::new_throughput(bytes_per_second, bytes_burst);
    }

    /// Set the 90th percentile number of [ConnectionPermit]s required per
    /// [ActiveSession] of a median IP for the [IpLimiter] singleton.
    ///
    /// For example:
    /// - if you have an HTTP/1-only server, set this to 4-6.
    /// - if you have an HTTP/2 server with HTTP/1 WebSockets, set this to 2.
    /// - if you have an HTTP/2 server with HTTP/2 WebSockets, set this to 1.
    ///
    /// Default: 1 (i.e. typical HTTP/2 clients)
    pub fn set_connections_per_active_p90(connections_per_active_p90: u32) {
        let mut this = SINGLETON.lock().unwrap();
        this.connections_per_active_p90 = connections_per_active_p90;
    }

    /// Set the 99th+ percentile number of [ConnectionPermit]s required per
    /// [ActiveSession] of a median IP for the [IpLimiter] singleton.
    ///
    /// For example, if your server accepts HTTP/1 clients, set this to 6-12.
    ///
    /// Default: 6
    pub fn set_connections_per_active_p99(connections_per_active_p99: u32) {
        let mut this = SINGLETON.lock().unwrap();
        this.connections_per_active_p99 = connections_per_active_p99;
    }

    /// Set the soft maximum number of [ConnectionPermit]s, across all IP's,
    /// before fewer new [ConnectionPermit]s are afforded to each IP.
    ///
    /// Default: 300
    pub fn set_total_connections_soft_limit(total_connections_soft_limit: u32) {
        let mut this = SINGLETON.lock().unwrap();
        this.total_connections_soft_limit = total_connections_soft_limit;
    }

    /// Set the hard limit on the number of [ConnectionPermit]s, across all IP's,
    /// before all new [ConnectionPermit]s are denied.
    ///
    /// Default 1000.
    pub fn set_total_connections_hard_limit(total_connections_hard_limit: u32) {
        let mut this = SINGLETON.lock().unwrap();
        this.total_connections_hard_limit = total_connections_hard_limit;
    }

    /// Call when processing a message of `bytes` bytes from `ip` at `now`.
    ///
    /// If this returns `true`, block the `usage` of bandwidth.
    pub fn should_limit_bandwidth(ip: IpAddr, bytes: Units, label: &str, now: Instant) -> bool {
        let mut this = SINGLETON.lock().unwrap();
        this.should_limit_bandwidth_inner(ip, bytes, label, now)
    }

    pub(crate) fn should_limit_bandwidth_inner(
        &mut self,
        ip: IpAddr,
        bytes: Units,
        label: &str,
        now: Instant,
    ) -> bool {
        let should_rate_limit = self.should_limit_bandwidth_inner_inner(ip, bytes, now);
        let should_warn = should_rate_limit
            && !self
                .warning_limiter
                .should_limit_rate_with_now(&WARNING_LIMIT, now);
        if should_warn {
            warn!("Bandwidth limiting {label} for {ip}");
        }
        should_rate_limit
    }
}

#[derive(Debug)]
struct Usage {
    rate_limit: RateLimiterState,
    stats: IpStats,
}

impl Usage {
    fn new(now: Instant) -> Self {
        Self {
            rate_limit: RateLimiterState {
                until: now,
                burst_used: 0,
            },
            stats: IpStats {
                first: now,
                connection_permits: 0,
                active_sessions: 0,
                hard_limited: 0,
            },
        }
    }
}

const WARNING_LIMIT: RateLimiterProps = RateLimiterProps::const_new(Duration::from_millis(100), 3);

/// A RAII guard representing a permissible, long-lived connection (such as a TCP stream).
#[derive(Debug)]
pub struct ConnectionPermit(IpAddr);

impl ConnectionPermit {
    /// Check if a new connection is permissible. If this returns `Some`, accept the
    /// connection and keep the [ConnectionPermit] for its lifetime. If this returns
    /// `None`, reject the connection.
    ///
    /// The `label` should be something like `"TCP connection"`.
    pub fn new(ip: IpAddr, label: &str) -> Option<Self> {
        let now = Instant::now();
        let mut limiter = SINGLETON.lock().unwrap();
        let limiter = &mut *limiter;
        if limiter.total_connection_permits >= limiter.total_connections_hard_limit {
            return None;
        }
        let entry = limiter.usage.entry(ip).or_insert_with(|| Usage::new(now));
        let should_rate_limit =
            entry
                .rate_limit
                .should_limit_rate_with_now_and_usage(&limiter.props, now, 10000);

        if should_rate_limit {
            if !limiter
                .warning_limiter
                .should_limit_rate_with_now(&WARNING_LIMIT, now)
            {
                warn!("Refusing new {label} for {ip} close to bandwidth limit");
            }
            entry.stats.increment_hard_limited();
            return None;
        }
        let old = now.duration_since(entry.stats.first) > Duration::from_secs(60);
        let enforce_soft_limit = (!old || entry.stats.hard_limited > 0)
            && limiter.total_connection_permits >= limiter.total_connections_soft_limit;
        let soft_limit = (entry.stats.active_sessions + 1).saturating_mul(if enforce_soft_limit {
            limiter.connections_per_active_p90
        } else {
            limiter.connections_per_active_p99
        });
        let hard_limit = if enforce_soft_limit {
            soft_limit
        } else {
            soft_limit.saturating_add(limiter.connections_per_active_p90)
        };
        let hit_hard_limit = entry.stats.connection_permits >= hard_limit;
        if hit_hard_limit || (entry.stats.connection_permits >= soft_limit && random()) {
            if hit_hard_limit {
                entry.stats.increment_hard_limited();
            }
            if !limiter
                .warning_limiter
                .should_limit_rate_with_now(&WARNING_LIMIT, now)
            {
                warn!(
                    "Count limiting {label} for {ip} ({} conn of max {soft_limit}, {} active)",
                    entry.stats.connection_permits, entry.stats.active_sessions
                );
            }
            None
        } else {
            entry.stats.connection_permits += 1;
            limiter.total_connection_permits += 1;
            Some(Self(ip))
        }
    }
}

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        let mut limiter = SINGLETON.lock().unwrap();
        if let Some(usage) = limiter.usage.get_mut(&self.0) {
            debug_assert!(usage.stats.connection_permits > 0);
            usage.stats.connection_permits = usage.stats.connection_permits.saturating_sub(1);
        } else {
            debug_assert!(false);
        }
        // Fail open by subtracting from the total even if `get_mut` returned `None`.
        debug_assert!(limiter.total_connection_permits > 0);
        limiter.total_connection_permits = limiter.total_connection_permits.saturating_sub(1);
    }
}

/// A RAII guard representing a connection with meaningful activity taking place,
/// such as an authenticated WebSocket on top of a TCP stream.
#[derive(Debug)]
pub struct ActiveSession(IpAddr);

impl ActiveSession {
    /// Keep the [ActiveSession] as long as meaningful activity is taking place.
    pub fn new(addr: IpAddr) -> Self {
        SINGLETON
            .lock()
            .unwrap()
            .usage
            .entry(addr)
            .or_insert_with(|| Usage::new(Instant::now()))
            .stats
            .active_sessions += 1;
        Self(addr)
    }
}

impl Drop for ActiveSession {
    fn drop(&mut self) {
        if let Some(usage) = SINGLETON.lock().unwrap().usage.get_mut(&self.0) {
            debug_assert!(usage.stats.active_sessions > 0);
            usage.stats.active_sessions = usage.stats.active_sessions.saturating_sub(1);
        } else {
            debug_assert!(false);
        }
    }
}

impl IpLimiter {
    /// Uses [`Units`] to represent bytes, to limit bandwidth.
    pub(crate) fn new(bytes_per_second: Units, bytes_burst: Units) -> Self {
        Self {
            usage: FxHashMap::default(),
            props: RateLimiterProps::new_throughput(bytes_per_second, bytes_burst),
            next_prune: Instant::now(),
            warning_limiter: Default::default(),
            connections_per_active_p90: 1,
            connections_per_active_p99: 6,
            total_connection_permits: 0,
            total_connections_soft_limit: 300,
            total_connections_hard_limit: 1000,
        }
    }

    /// Marks usage as being performed by the ip address.
    /// Returns true if the action should be blocked (rate limited).
    pub(crate) fn should_limit_bandwidth_inner_inner(
        &mut self,
        ip: IpAddr,
        bytes: Units,
        now: Instant,
    ) -> bool {
        let entry = self.usage.entry(ip).or_insert_with(|| Usage::new(now));
        let should_limit_rate =
            entry
                .rate_limit
                .should_limit_rate_with_now_and_usage(&self.props, now, bytes);

        if should_limit_rate {
            entry.stats.increment_hard_limited();
        }

        self.maybe_prune(now);

        should_limit_rate
    }

    /// Clean up old items. Called automatically; it is not necessary to call manually.
    fn maybe_prune(&mut self, now: Instant) {
        if now < self.next_prune {
            return;
        }
        self.next_prune = now + Duration::from_secs(5);
        self.prune(now);
    }

    fn prune(&mut self, now: Instant) {
        self.usage.retain(|_, usage: &mut Usage| {
            usage.rate_limit.until > now
                || usage.stats.active_sessions > 0
                || usage.stats.connection_permits > 0
        })
    }

    /// Returns number of IP addresses being tracked.
    #[allow(unused)]
    pub(crate) fn len(&self) -> usize {
        self.usage.len()
    }

    /// Returns `true` if any IP addresses are being tracked.
    #[allow(unused)]
    pub(crate) fn is_empty(&self) -> bool {
        self.usage.is_empty()
    }
}

#[cfg(test)]
mod test {
    use super::IpLimiter;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::time::{Duration, Instant};

    #[test]
    pub fn ip_rate_limiter() {
        let ip_one = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        let ip_two = IpAddr::V6(Ipv6Addr::new(1, 2, 3, 4, 5, 6, 7, 8));
        let mut limiter = IpLimiter::new(10, 3);

        assert_eq!(limiter.len(), 0);
        assert!(!limiter.should_limit_bandwidth_inner_inner(ip_one, 1, Instant::now()));
        assert_eq!(limiter.len(), 1);
        assert!(!limiter.should_limit_bandwidth_inner_inner(ip_one, 1, Instant::now()));
        assert_eq!(limiter.len(), 1);

        limiter.prune(Instant::now());
        assert_eq!(limiter.len(), 1);

        assert!(!limiter.should_limit_bandwidth_inner_inner(ip_one, 1, Instant::now()));
        assert_eq!(limiter.len(), 1);

        limiter.prune(Instant::now());
        assert_eq!(limiter.len(), 1);

        assert!(limiter.should_limit_bandwidth_inner_inner(ip_one, 1, Instant::now()));
        assert_eq!(limiter.len(), 1);

        std::thread::sleep(Duration::from_millis(250));

        assert!(!limiter.should_limit_bandwidth_inner_inner(ip_two, 1, Instant::now()));
        assert_eq!(limiter.len(), 2);
        assert!(!limiter.should_limit_bandwidth_inner_inner(ip_two, 1, Instant::now()));
        assert_eq!(limiter.len(), 2);

        limiter.prune(Instant::now());
        assert_eq!(limiter.len(), 2);

        std::thread::sleep(Duration::from_millis(100));

        limiter.prune(Instant::now());
        assert_eq!(limiter.len(), 1);

        std::thread::sleep(Duration::from_millis(500));

        limiter.prune(Instant::now());
        assert_eq!(limiter.len(), 0);

        assert!(!limiter.should_limit_bandwidth_inner_inner(ip_one, 1, Instant::now()));
        assert_eq!(limiter.len(), 1);
    }
}
