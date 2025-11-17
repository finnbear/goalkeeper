//! Per-IP connection and bandwidth limiter.

use crate::rate_limiter::{RateLimiterProps, RateLimiterState, Units};
use fxhash::FxHashMap;
use log::warn;
use rand::random;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

static SINGLETON: Mutex<Option<IpLimiter>> = Mutex::new(None);

/// Limits connections and bandwidth based on client IP addresses.
#[derive(Debug)]
pub struct IpLimiter {
    usage: FxHashMap<IpAddr, Usage>,
    connection_rate_limit: RateLimiterProps,
    custom_rate_limit: RateLimiterProps,
    next_prune: Instant,
    warning_limiter: RateLimiterState,
    connections_per_active_p90: u32,
    connections_per_active_p99: u32,
    total_connections: u32,
    total_connections_soft_limit: u32,
    total_connections_hard_limit: u32,
    last_soft_limit: Option<Instant>,
    ddos_memory: Duration,
    compute_pressure: bool,
}

/// Summary statistics for a given IP.
#[derive(Copy, Clone, Debug)]
#[non_exhaustive]
pub struct IpStats {
    /// First connection (since the last time this IP was last garbage collected).
    pub first: Instant,
    /// Number of outstanding [ConnectionPermit]s.
    pub connections: u32,
    /// Number of outstanding [ActiveSession]s.
    pub active_sessions: u32,
    /// Last time this IP hit a hard limit.
    pub last_hard_limit: Option<Instant>,
}

impl IpStats {
    fn increment_hard_limited(&mut self, now: Instant) {
        self.last_hard_limit = Some(now);
    }
}

impl IpLimiter {
    fn with_singleton<R>(f: impl FnOnce(&mut Self) -> R) -> R {
        let mut opt = SINGLETON.lock().unwrap();
        let this = opt.get_or_insert_with(|| Self::new(500000, 1000000));
        // Yikes..
        f(this)
    }

    /// Visit the [IpStats] for each tracked IP.
    ///
    /// The `visitor` should never block.
    pub fn stats(mut visitor: impl FnMut(IpAddr, IpStats)) {
        Self::with_singleton(|this| {
            for (ip, v) in &this.usage {
                visitor(*ip, v.stats);
            }
        });
    }

    /// Total number of outstanding [ConnectionPermit]s.
    pub fn total_connections() -> u32 {
        Self::with_singleton(|this| this.total_connections)
    }

    /// Set the bandwidth limits for the [IpLimiter] singleton.
    ///
    /// The `bytes_per_second` should be less than 1,000,000,000.
    ///
    /// Default: 500,000 bytes per second, 1,000,000 bytes burst.
    pub fn set_bandwidth_limits(bytes_per_second: Units, bytes_burst: Units) {
        Self::with_singleton(|this| {
            this.connection_rate_limit =
                RateLimiterProps::new_throughput(bytes_per_second, bytes_burst);
        })
    }

    /// Set the properties of the custom rate limit corresponding to each IP.
    pub fn set_custom_limits(props: RateLimiterProps) {
        Self::with_singleton(|this| {
            this.custom_rate_limit = props;
        })
    }

    /// Set the 90th percentile number of [ConnectionPermit]s required per
    /// [ActiveSession] of a median IP for the [IpLimiter] singleton.
    ///
    /// For example:
    /// - if you have an HTTP/1-only server, set this to 4-6.
    /// - if you have an HTTP/2 server with HTTP/1 WebSockets, set this to 2.
    /// - if you have an HTTP/2 server (possibly with HTTP/2 WebSockets), set this to 1.
    ///
    /// Default: 1
    pub fn set_connections_per_active_p90(connections_per_active_p90: u32) {
        Self::with_singleton(|this| {
            this.connections_per_active_p90 = connections_per_active_p90;
        })
    }

    /// Set the 99th+ percentile number of [ConnectionPermit]s required per
    /// [ActiveSession] of a median IP for the [IpLimiter] singleton.
    ///
    /// For example, if your server accepts HTTP/1 clients, set this to 6-12.
    ///
    /// Default: 6
    pub fn set_connections_per_active_p99(connections_per_active_p99: u32) {
        Self::with_singleton(|this| {
            this.connections_per_active_p99 = connections_per_active_p99;
        })
    }

    /// Set the soft maximum number of [ConnectionPermit]s, across all IP's,
    /// before fewer new [ConnectionPermit]s are afforded to each IP.
    ///
    /// Default: 300
    pub fn set_total_connections_soft_limit(total_connections_soft_limit: u32) {
        Self::with_singleton(|this| {
            this.total_connections_soft_limit = total_connections_soft_limit;
        })
    }

    /// Set the hard limit on the number of [ConnectionPermit]s, across all IP's,
    /// before all new [ConnectionPermit]s are denied.
    ///
    /// Default 1000.
    pub fn set_total_connections_hard_limit(total_connections_hard_limit: u32) {
        Self::with_singleton(|this| {
            this.total_connections_hard_limit = total_connections_hard_limit;
        })
    }

    /// Call when processing a message of `bytes` bytes from `ip` at `now`.
    ///
    /// If this returns `true`, block the `usage` of bandwidth.
    pub fn should_limit_bandwidth(ip: IpAddr, bytes: Units, label: &str, now: Instant) -> bool {
        Self::with_singleton(|this| this.should_limit_bandwidth_inner(ip, bytes, label, now))
    }

    /// Call to rate limit some custom (perhaps expensive) action per IP.
    ///
    /// If this returns `true`, block the `usage`.
    pub fn should_limit_custom(ip: IpAddr, usage: Units, now: Instant) -> bool {
        Self::with_singleton(|this| {
            let entry = this.usage.entry(ip).or_insert_with(|| Usage::new(now));
            entry
                .custom_rate_limit
                .should_limit_rate_with_now_and_usage(&this.custom_rate_limit, now, usage)
        })
    }

    /// Set how long a DDoS incident will be be remembered.
    ///
    /// Default: 10m
    pub fn set_ddos_memory(ddos_memory: Duration) {
        Self::with_singleton(|this| {
            this.ddos_memory = ddos_memory;
        })
    }

    /// Call with `true` any time the host's CPU and/or RAM are nearly exausted,
    /// then call with `false` when they are back to normal.
    ///
    /// This can trigger additional connection limiting before the connection
    /// count hits the value set by [Self::set_total_connections_soft_limit].
    ///
    /// Default: `false`
    pub fn set_compute_pressure(compute_pressure: bool) {
        Self::with_singleton(|this| {
            this.compute_pressure = compute_pressure;
        })
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
            warn!("bandwidth limiting {label} of {ip}");
        }
        should_rate_limit
    }
}

#[derive(Debug)]
struct Usage {
    connection_rate_limit: RateLimiterState,
    custom_rate_limit: RateLimiterState,
    stats: IpStats,
}

impl Usage {
    fn new(now: Instant) -> Self {
        Self {
            connection_rate_limit: RateLimiterState {
                until: now,
                burst_used: 0,
            },
            custom_rate_limit: RateLimiterState {
                until: now,
                burst_used: 0,
            },
            stats: IpStats {
                first: now,
                connections: 0,
                active_sessions: 0,
                last_hard_limit: None,
            },
        }
    }
}

const WARNING_LIMIT: RateLimiterProps = RateLimiterProps::const_new(Duration::from_millis(500), 3);

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
        IpLimiter::with_singleton(|limiter| {
            if limiter.total_connections >= limiter.total_connections_hard_limit {
                return None;
            }
            let entry = limiter.usage.entry(ip).or_insert_with(|| Usage::new(now));
            let should_rate_limit = entry
                .connection_rate_limit
                .should_limit_rate_with_now_and_usage(&limiter.connection_rate_limit, now, 10000);

            if should_rate_limit {
                if !limiter
                    .warning_limiter
                    .should_limit_rate_with_now(&WARNING_LIMIT, now)
                {
                    warn!("refusing {label} of {ip} (close to bw limit)");
                }
                entry.stats.increment_hard_limited(now);
                return None;
            }
            let old = now.duration_since(entry.stats.first) > Duration::from_secs(60);
            let soft_limit_reached = limiter.compute_pressure
                || limiter.total_connections >= limiter.total_connections_soft_limit;
            if soft_limit_reached {
                limiter.last_soft_limit = Some(now);
            }
            let recent_global_soft_limit = limiter
                .last_soft_limit
                .filter(|&last| now.duration_since(last) < limiter.ddos_memory)
                .is_some();
            let recent_local_hard_limit = entry
                .stats
                .last_hard_limit
                .filter(|&last| now.duration_since(last) < limiter.ddos_memory)
                .is_some();
            let enforce_soft_limit = (!old || recent_local_hard_limit) && recent_global_soft_limit;
            let soft_limit =
                (entry.stats.active_sessions + 1).saturating_mul(if enforce_soft_limit {
                    limiter.connections_per_active_p90
                } else {
                    limiter.connections_per_active_p99
                });
            let hard_limit = if enforce_soft_limit {
                soft_limit
            } else {
                soft_limit.saturating_add(limiter.connections_per_active_p90)
            };
            let hit_hard_limit = entry.stats.connections >= hard_limit;
            if hit_hard_limit || (entry.stats.connections >= soft_limit && random()) {
                if hit_hard_limit {
                    entry.stats.increment_hard_limited(now);
                }
                if !limiter
                    .warning_limiter
                    .should_limit_rate_with_now(&WARNING_LIMIT, now)
                {
                    warn!(
                        "count limiting {label} of {ip} ({} conn of max {soft_limit}, {} active)",
                        entry.stats.connections, entry.stats.active_sessions
                    );
                }
                None
            } else {
                entry.stats.connections += 1;
                limiter.total_connections += 1;
                Some(Self(ip))
            }
        })
    }
}

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        IpLimiter::with_singleton(|limiter| {
            if let Some(usage) = limiter.usage.get_mut(&self.0) {
                debug_assert!(usage.stats.connections > 0);
                usage.stats.connections = usage.stats.connections.saturating_sub(1);
            } else {
                debug_assert!(false);
            }
            // Fail open by subtracting from the total even if `get_mut` returned `None`.
            debug_assert!(limiter.total_connections > 0);
            limiter.total_connections = limiter.total_connections.saturating_sub(1);
        })
    }
}

/// A RAII guard representing a connection with meaningful activity taking place,
/// such as an authenticated WebSocket on top of a TCP stream.
#[derive(Debug)]
pub struct ActiveSession(IpAddr);

impl ActiveSession {
    /// Keep the [ActiveSession] as long as meaningful activity is taking place.
    pub fn new(addr: IpAddr) -> Self {
        IpLimiter::with_singleton(|limiter| {
            limiter
                .usage
                .entry(addr)
                .or_insert_with(|| Usage::new(Instant::now()))
                .stats
                .active_sessions += 1;
            Self(addr)
        })
    }
}

impl Drop for ActiveSession {
    fn drop(&mut self) {
        IpLimiter::with_singleton(|limiter| {
            if let Some(usage) = limiter.usage.get_mut(&self.0) {
                debug_assert!(usage.stats.active_sessions > 0);
                usage.stats.active_sessions = usage.stats.active_sessions.saturating_sub(1);
            } else {
                debug_assert!(false);
            }
        })
    }
}

impl IpLimiter {
    /// Uses [`Units`] to represent bytes, to limit bandwidth.
    pub(crate) fn new(bytes_per_second: Units, bytes_burst: Units) -> Self {
        Self {
            usage: FxHashMap::default(),
            connection_rate_limit: RateLimiterProps::new_throughput(bytes_per_second, bytes_burst),
            custom_rate_limit: RateLimiterProps::no_limit(),
            next_prune: Instant::now(),
            warning_limiter: Default::default(),
            connections_per_active_p90: 1,
            connections_per_active_p99: 6,
            total_connections: 0,
            total_connections_soft_limit: 300,
            total_connections_hard_limit: 1000,
            last_soft_limit: None,
            ddos_memory: Duration::from_secs(5 * 60),
            compute_pressure: false,
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
        let should_limit_rate = entry
            .connection_rate_limit
            .should_limit_rate_with_now_and_usage(&self.connection_rate_limit, now, bytes);

        if should_limit_rate {
            entry.stats.increment_hard_limited(now);
        }

        self.maybe_prune(now);

        should_limit_rate
    }

    /// Clean up old items. Called automatically; it is not necessary to call manually.
    fn maybe_prune(&mut self, now: Instant) {
        if now < self.next_prune {
            return;
        }
        self.next_prune = now + Duration::from_secs(5).max(self.ddos_memory / 2);
        self.prune(now);
    }

    fn prune(&mut self, now: Instant) {
        let forget = now + self.ddos_memory;
        self.usage.retain(|_, usage: &mut Usage| {
            usage.connection_rate_limit.until > forget
                || usage.custom_rate_limit.until > forget
                || usage.stats.active_sessions > 0
                || usage.stats.connections > 0
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

        limiter.ddos_memory = Duration::ZERO;

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
