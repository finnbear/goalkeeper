//! Timers the executor fires itself, part way through a turn.
//!
//! A tokio timer is fired by tokio's time driver, which only runs between the
//! executor's turns: while a turn is running tasks, nothing is looking at the
//! clock on its behalf. So a deadline that passes mid-turn is noticed only when
//! the turn ends — up to [`TASKS_PER_TICK`](super) tasks, or a cooperative
//! budget's worth, later. For [`Priority::Main`](super::priority::Priority::Main)
//! that makes "highest priority" mean "first once the turn is over", which is
//! not what a fixed-rate tick needs.
//!
//! These are registered with the executor as well, which already reads the
//! clock after every task it runs. A deadline that has passed is fired there,
//! between two tasks:
//!
//! - A timer awaited by a spawned task wakes it, which enqueues it at its
//!   level, so the existing preemption check serves it ahead of a worse batch.
//! - A timer awaited by the root future — the one given to `run_until`, which is
//!   in no queue for preemption to see — ends the batch, and the root is polled
//!   again straight away.
//!
//! While the executor is idle, one tokio timer of its own, armed for the
//! earliest of them, is what wakes it to fire them. So they must be driven by
//! [`run_until`](super::Executor::run_until): polled where nothing runs one,
//! one never completes.

use super::Shared;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

/// Waits until a deadline.
///
/// See the [module](self) documentation for how this differs from
/// `tokio::time::Sleep`.
pub struct Sleep {
    shared: Arc<Shared>,
    deadline: Instant,
    /// How this is registered with the executor, if it is.
    registration: Option<Registration>,
}

/// A copy of what a [`Sleep`] registered, so that polling it again the same
/// way, which is what nearly every poll before the deadline does, need not take
/// the executor's timer lock to change nothing.
///
/// Out of date only once the registration has fired, which it does only once
/// the deadline has passed, and a poll past the deadline completes without
/// looking here; or once the executor has closed, when nothing will poll this
/// again anyway.
struct Registration {
    key: TimerKey,
    waker: Waker,
    root: bool,
}

/// A registration's place in the executor's timer list: deadline first, so the
/// list is ordered by when things are due, then an id to tell apart timers due
/// at the same moment.
pub(super) type TimerKey = (u64, u64);

impl Sleep {
    pub(super) fn new(shared: Arc<Shared>, deadline: Instant) -> Self {
        Self {
            shared,
            deadline,
            registration: None,
        }
    }

    /// When this completes.
    pub fn deadline(&self) -> Instant {
        self.deadline
    }

    /// Waits for `deadline` instead, whether or not this has completed.
    pub fn reset(&mut self, deadline: Instant) {
        self.deregister();
        self.deadline = deadline;
    }

    fn deregister(&mut self) {
        if let Some(registration) = self.registration.take() {
            self.shared.deregister_timer(registration.key);
        }
    }
}

impl Future for Sleep {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if Instant::now() >= self.deadline {
            self.deregister();
            return Poll::Ready(());
        }
        let this = &mut *self;
        let root = this.shared.polling_root();
        if let Some(registration) = &this.registration
            && registration.root == root
            && registration.waker.will_wake(cx.waker())
        {
            return Poll::Pending;
        }
        let key = this
            .registration
            .take()
            .map(|registration| registration.key);
        this.registration = this
            .shared
            .register_timer(key, this.deadline, cx.waker(), root)
            .map(|key| Registration {
                key,
                waker: cx.waker().clone(),
                root,
            });
        Poll::Pending
    }
}

impl Drop for Sleep {
    fn drop(&mut self) {
        self.deregister();
    }
}

/// Yields at a fixed period.
///
/// A tick later than [`Self::late`] is followed by the next one a full period
/// *after it*, rather than a burst to catch up with the schedule: tokio's
/// `MissedTickBehavior::Delay`. Catch-up ticks only repeat work the late tick
/// has just done.
pub struct Interval {
    sleep: Sleep,
    period: Duration,
    late: Duration,
}

impl Interval {
    pub(super) fn new(
        shared: Arc<Shared>,
        start: Instant,
        period: Duration,
        late: Duration,
    ) -> Self {
        assert!(!period.is_zero(), "an interval needs a period");
        // Any later, and a tick late by between the two is followed by one
        // already due: the burst this exists to prevent.
        debug_assert!(
            late <= period,
            "late ({late:?}) exceeds period ({period:?})"
        );
        Self {
            sleep: Sleep::new(shared, start),
            period,
            late,
        }
    }

    /// The time between ticks.
    pub fn period(&self) -> Duration {
        self.period
    }

    /// How late a tick may be and still count as on schedule, so the next is
    /// due a period after this one was *meant* to be rather than a period after
    /// it happened.
    ///
    /// Too small, and every tick counts as late — each is at least the time
    /// between its deadline passing and the executor noticing — so the schedule
    /// drifts by that much per period. Too large, and a tick that was late by
    /// most of it is followed by the next only a little over a period, less
    /// that lateness, afterwards. At most the period.
    pub fn late(&self) -> Duration {
        self.late
    }

    /// Completes at the next tick, with when that tick was due.
    pub fn poll_tick(&mut self, cx: &mut Context<'_>) -> Poll<Instant> {
        let due = self.sleep.deadline;
        if Pin::new(&mut self.sleep).poll(cx).is_pending() {
            return Poll::Pending;
        }
        let now = Instant::now();
        let next = if now.saturating_duration_since(due) > self.late {
            now + self.period
        } else {
            due + self.period
        };
        self.sleep.reset(next);
        Poll::Ready(due)
    }

    /// Waits for the next tick, and says when it was due.
    pub async fn tick(&mut self) -> Instant {
        std::future::poll_fn(|cx| self.poll_tick(cx)).await
    }
}
