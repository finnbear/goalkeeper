//! General purpose rate limiter.

use std::fmt::{self, Debug, Formatter};
use std::ops::Div;
use std::time::{Duration, Instant};

/// A rate limiter that keeps track of its own [RateLimiterProps].
pub struct RateLimiter {
    props: RateLimiterProps,
    state: RateLimiterState,
}

/// A [`u32`] is chosen for being the widest type that doesn't increase the size of
/// [`RateLimiterState`] or [`RateLimiterProps`] on a 64-bit system, and it is natively accepted
/// by [`Duration::saturating_mul`].
pub type Units = u32;

/// The state of a rate limiter.
pub struct RateLimiterState {
    /// At this time, the limit is effectively brand new.
    pub(crate) until: Instant,
    /// How much of [RateLimiterProps::burst] has been used.
    pub(crate) burst_used: Units,
}

impl Debug for RateLimiterState {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("RateLimiterState")
            .field(
                "until",
                &self
                    .until
                    .saturating_duration_since(Instant::now())
                    .as_secs_f32(),
            )
            .field("burst_used", &self.burst_used)
            .finish()
    }
}

/// The (sharable) properties of a rate limiter.
#[derive(Copy, Clone, Debug)]
pub struct RateLimiterProps {
    rate_limit: Duration,
    pub(crate) burst: Units,
}

impl RateLimiterProps {
    /// How much may be spent in a burst once the steady rate is exhausted.
    pub fn burst(&self) -> Units {
        self.burst
    }

    /// Seconds per unit of the steady rate.
    pub fn rate_limit(&self) -> Duration {
        self.rate_limit
    }
}

impl RateLimiterState {
    /// Returns `true` if the action exceeds the rate limit defined by the props and should be prevented.
    #[inline(always)]
    pub fn should_limit_rate(&mut self, props: &RateLimiterProps) -> bool {
        self.should_limit_rate_with_now_and_usage(props, Instant::now(), 1)
    }

    /// Returns `true` if the `usage` actions exceed the rate limit defined by the props and should be prevented.
    #[inline(always)]
    pub fn should_limit_rate_with_usage(&mut self, props: &RateLimiterProps, usage: Units) -> bool {
        self.should_limit_rate_with_now_and_usage(props, Instant::now(), usage)
    }

    /// Like [`Self::should_limit_rate`] but more efficient if you already know the current time.
    #[inline(always)]
    pub fn should_limit_rate_with_now(&mut self, props: &RateLimiterProps, now: Instant) -> bool {
        self.should_limit_rate_with_now_and_usage(props, now, 1)
    }

    /// Like [`Self::should_limit_rate_with_usage`] but more efficient if you already know the current time.
    #[inline]
    pub fn should_limit_rate_with_now_and_usage(
        &mut self,
        props: &RateLimiterProps,
        now: Instant,
        usage: Units,
    ) -> bool {
        if props.rate_limit == Duration::ZERO {
            return false;
        }

        let ok = if now > self.until {
            self.burst_used = 0;
            true
        } else if self.burst_used.saturating_add(usage) <= props.burst {
            self.burst_used = self.burst_used.saturating_add(usage);
            true
        } else {
            false
        };

        if ok
            && let Some(instant) = self
                .until
                .checked_add(props.rate_limit.saturating_mul(usage))
        {
            self.until = instant.max(now);
        }

        !ok
    }

    /// Adds `usage` to what is owed at `now`, after [`Self::should_limit_spend`]
    /// refused it.
    ///
    /// For a cost that has already been incurred, such as bytes that have
    /// moved, rather than an action that could be turned away: refused or not,
    /// it is paid back at the steady rate like any other, so the limit does not
    /// lift while it keeps being incurred.
    ///
    /// Up to two bursts' worth ahead of `now` and no further: a burst past
    /// where [`Self::should_limit_spend`] starts refusing, so the limit lifts
    /// within a burst's worth once it stops. Not one burst, which is where
    /// refusing starts, and so would never add anything. Without a ceiling,
    /// how long it stayed would grow with everything ever incurred, and
    /// whoever can incur it in another's name (a spoofed source, say) could
    /// hold the limit on them for as long as they liked after stopping. Never
    /// shortens what is owed.
    #[inline]
    pub(crate) fn owe(&mut self, props: &RateLimiterProps, now: Instant, usage: Units) {
        let Some(owed) = self
            .until
            .checked_add(props.rate_limit.saturating_mul(usage))
        else {
            return;
        };
        let ceiling = now
            .checked_add(
                props
                    .rate_limit
                    .saturating_mul(props.burst.saturating_mul(2)),
            )
            .map_or(owed, |ceiling| ceiling.max(self.until));
        self.until = owed.min(ceiling);
    }

    /// Whether what has been spent is still being paid back at the steady
    /// rate at `now`; once it is not, the limit is effectively brand new (see
    /// `until`). Spends nothing, for a caller that only needs to know whether
    /// a limit it hit earlier has lifted.
    #[inline]
    pub(crate) fn in_debt(&self, now: Instant) -> bool {
        now <= self.until
    }

    /// Like [`Self::should_limit_rate_with_now_and_usage`], but the burst
    /// refills as what is owed is paid back, rather than all at once when all
    /// of it has been: refused only while more than a burst's worth is owed.
    /// Leaves `burst_used` alone; what is owed is all it reads.
    ///
    /// For bandwidth, where a source paced at its steady rate must be able to
    /// keep that up indefinitely. Under the other, every unit spent while
    /// anything is owed comes out of the burst, so a source that has spent
    /// some of it and carries on at its steady rate, which never pays any of
    /// it back, runs out and is refused regardless.
    ///
    /// Only what is owed before `usage` is weighed, so a single spend larger
    /// than the burst is not refused for its size, as the other does not
    /// refuse the first spend once nothing is owed.
    #[inline]
    pub(crate) fn should_limit_spend(
        &mut self,
        props: &RateLimiterProps,
        now: Instant,
        usage: Units,
    ) -> bool {
        if self.would_limit_spend(props, now) {
            return true;
        }
        if let Some(until) = self
            .until
            .max(now)
            .checked_add(props.rate_limit.saturating_mul(usage))
        {
            self.until = until;
        }
        false
    }

    /// Whether [`Self::should_limit_spend`] would refuse at `now`: more than a
    /// burst's worth is owed. Spends nothing.
    #[inline]
    pub(crate) fn would_limit_spend(&self, props: &RateLimiterProps, now: Instant) -> bool {
        props.rate_limit != Duration::ZERO && self.owed(props, now) > props.burst
    }

    /// How much is owed at `now`, in units: what is still to be paid back at
    /// the steady rate.
    #[inline]
    fn owed(&self, props: &RateLimiterProps, now: Instant) -> Units {
        let owed = self.until.saturating_duration_since(now).as_nanos();
        let unit = props.rate_limit.as_nanos().max(1);
        owed.div_ceil(unit).min(u128::from(Units::MAX)) as Units
    }

    /// How much more may be spent at `now` before
    /// [`Self::should_limit_spend`] refuses: the burst, less what is owed.
    /// Spends nothing.
    #[inline]
    pub(crate) fn headroom(&self, props: &RateLimiterProps, now: Instant) -> Units {
        if props.rate_limit == Duration::ZERO {
            return Units::MAX;
        }
        props.burst.saturating_sub(self.owed(props, now))
    }
}

impl Default for RateLimiterState {
    fn default() -> Self {
        Self {
            until: Instant::now(),
            burst_used: 0,
        }
    }
}

impl RateLimiterProps {
    /// Limit rate (seconds per action), allowing `burst` extra actions after the
    /// `rate_limit` is exhausted.
    ///
    /// The `rate_limit` should be greater than zero.
    ///
    /// The `burst` must be less than [`Units::MAX`], otherwise the limit is ineffectual.
    pub fn new(rate_limit: Duration, burst: Units) -> Self {
        debug_assert!(
            rate_limit != Duration::ZERO,
            "use RateLimiterProps::no_limit() to explicitly opt out of rate limiting"
        );
        debug_assert!(burst < Units::MAX);
        Self { rate_limit, burst }
    }

    /// Limit throughput (items per second) instead of rate.
    ///
    /// The `throughput` should be less than 1,000,000,000.
    pub fn new_throughput(throughput: u32, burst: u32) -> Self {
        let rate_limit = Duration::from_secs(1).div(throughput);
        debug_assert!(rate_limit > Duration::ZERO);
        Self::new(rate_limit, burst)
    }

    /// Limit rate without burst.
    ///
    /// The `rate_limit` should be greater than zero.
    pub fn new_pure(rate_limit: Duration) -> Self {
        Self::new(rate_limit, 0)
    }

    /// Like [`Self::new`] but const and no runtime checks are performed.
    pub const fn const_new(rate_limit: Duration, burst: Units) -> Self {
        Self { rate_limit, burst }
    }

    /// Make a [RateLimiter] allow an infinite rate.
    pub fn no_limit() -> Self {
        Self {
            rate_limit: Duration::ZERO,
            burst: 0,
        }
    }
}

impl RateLimiter {
    /// Creates a new rate limiter with the specified properties.
    pub fn new(rate_limit: Duration, burst: Units) -> Self {
        Self::from(RateLimiterProps::new(rate_limit, burst))
    }

    /// Constructs a rate limiter that allows infinite rate.
    pub fn no_limit() -> Self {
        Self::from(RateLimiterProps::no_limit())
    }

    /// Returns true if the action exceeds the rate limit and should be prevented.
    pub fn should_limit_rate(&mut self) -> bool {
        self.state.should_limit_rate(&self.props)
    }

    /// Like [`Self::should_limit_rate`] but more efficient if you already know the time.
    pub fn should_limit_rate_with_now(&mut self, now: Instant) -> bool {
        self.state.should_limit_rate_with_now(&self.props, now)
    }
}

impl From<RateLimiterProps> for RateLimiter {
    fn from(props: RateLimiterProps) -> Self {
        Self {
            props,
            state: RateLimiterState::default(),
        }
    }
}

#[cfg(test)]
mod test {
    use crate::rate_limiter::RateLimiter;
    use std::time::Duration;

    #[test]
    fn fuzz() {
        let rate_limit = 80;
        let burst = 8;
        let mut rate_limiter = RateLimiter::new(Duration::from_millis(rate_limit), burst);
        let mut now = rate_limiter.state.until;

        for rate in 0..rate_limit + 50 {
            now += Duration::from_millis((burst as u64 + 1) * rate_limit);

            let mut total_ok = 0;
            for n in 0..burst * 2 {
                now += Duration::from_millis(rate);
                let ok = !rate_limiter.should_limit_rate_with_now(now);
                if ok {
                    total_ok += 1;
                } else {
                    assert!(n >= burst && rate <= rate_limit, "{n} {rate} {rate_limit}");
                }
            }
            assert!(total_ok >= burst);
            if rate > rate_limit {
                assert_eq!(rate_limiter.state.burst_used, 0, "{rate} {rate_limit}");
            }
        }
    }

    #[test]
    fn normal() {
        let mut rate_limiter = RateLimiter::new(Duration::from_millis(10), 2);

        for _ in 0..10 {
            assert!(!rate_limiter.should_limit_rate());
            assert_eq!(rate_limiter.state.burst_used, 0);
            std::thread::sleep(Duration::from_millis(15));
        }
    }

    #[test]
    fn limit_exceeded() {
        let mut rate_limiter = RateLimiter::new(Duration::from_millis(10), 3);

        std::thread::sleep(Duration::from_millis(5));

        assert!(!rate_limiter.should_limit_rate());
        assert_eq!(rate_limiter.state.burst_used, 0);
        assert!(!rate_limiter.should_limit_rate());
        assert_eq!(rate_limiter.state.burst_used, 1);
        assert!(!rate_limiter.should_limit_rate());
        assert_eq!(rate_limiter.state.burst_used, 2);
        assert!(!rate_limiter.should_limit_rate());
        assert_eq!(rate_limiter.state.burst_used, 3);
        assert!(rate_limiter.should_limit_rate());
        assert_eq!(rate_limiter.state.burst_used, 3);

        std::thread::sleep(Duration::from_millis(50));

        assert!(!rate_limiter.should_limit_rate());
        assert_eq!(rate_limiter.state.burst_used, 0);
    }

    #[test]
    fn no_limit() {
        let mut rate_limiter = RateLimiter::no_limit();

        for _ in 0..1000 {
            assert!(!rate_limiter.should_limit_rate());
        }
    }
}
