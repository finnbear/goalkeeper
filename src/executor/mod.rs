//! A priority executor, scheduling on top of a caller-supplied tokio runtime.
//!
//! Only dispatch is ours. The schedule is driven by the caller's
//! `Runtime::block_on`, so IO registration and timers remain tokio's, the shape
//! `LocalSet` uses, and anything spawned with `tokio::spawn` still works
//! unprioritised. Owning dispatch rather than vetoing from inside a wrapper is
//! what makes a wake an enqueue at the task's current level and leaves a task
//! held back by priority untouched in its queue.
//!
//! # The mechanisms
//!
//! - **Priority.** Picking a task takes the lowest set bit of an occupancy
//!   bitmap, so a task at a better level is never behind one at a worse
//!   level.
//! - **Shares.** Within a level, a task may spend `window · OVERSUBSCRIBE /
//!   participants` before being set aside until the window refills. This is
//!   what stands between one task with long polls and its peers.
//! - **Aging.** Strict priority starves the bottom, so a queue whose head has
//!   waited long enough is served out of turn.
//! - **Override budget.** Aging is capped in aggregate, so a cohort that ages
//!   together cannot take the schedule over.

pub mod priority;

use crate::executor::priority::{Priority, SharedPriority};
use async_task::{Runnable, Task};
use std::collections::VecDeque;
use std::future::{Future, poll_fn};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Poll, Waker};
use std::time::{Duration, Instant};

/// How many tasks one turn of [`Executor::run_until`] may run before yielding.
///
/// The executor is a future inside somebody's `block_on`, so while it runs the
/// reactor does not. Returning periodically is what lets IO readiness and
/// timers arrive. `LocalSet` caps at 61 for the same reason.
const TASKS_PER_TICK: usize = 61;

/// Charged on top of every poll's measured duration.
///
/// A poll costs more than its body: a wake, a reschedule, a readiness syscall
/// and the clock reads that do the measuring, none of it inside the timed
/// region. Without a flat rate, a peer dribbling a byte at a time forces many
/// polls that are expensive to the schedule and nearly free against a duration.
/// Well-behaved tasks poll rarely enough that it rounds away.
const POLL_COST: Duration = Duration::from_micros(1);

/// Jobs taken from the queues in one lock acquisition.
///
/// The lock is the executor's main cost against a bare `tokio::spawn`, and
/// amortising it over a batch is most of what closes that gap. Raising it
/// further trades against latency: a batch is committed to before the first of
/// it runs, so a newly woken peer at the same level waits that much longer.
/// Preemption by a better level is unaffected, since the loop rechecks the
/// bitmap between runs.
const BATCH: usize = 8;

/// How the executor rations.
///
/// Set through [`crate::Goalkeeper`]'s per-field setters rather than as a
/// struct, so changing one number cannot silently revert another.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Config {
    /// How long a share lasts before it is refilled.
    ///
    /// Constant, and unrelated to any caller's tick. It sets how finely
    /// cumulative hogging is punished and how long a punished task waits; it
    /// does not bound aggregate CPU or protect the root task, which preemption
    /// does.
    pub window: Duration,
    /// How many equal shares of a window one task may take.
    ///
    /// An equal split is the wrong ceiling because activity is not: a handshake
    /// mid-negotiation legitimately wants several polls where a task idling on
    /// a socket wants one.
    pub oversubscribe: u32,
    /// Consecutive windows a task must exhaust its share in before losing the
    /// headroom above.
    ///
    /// More than one, so a host stall, which charges a full second to whichever
    /// task happened to be mid-poll, costs its victim the remainder of one
    /// window and nothing else.
    pub penalty_windows: u32,
    /// How long a queue's head waits before it may be served out of turn, and
    /// the interval that doubling is measured in.
    pub aging_base: Duration,
    /// Fraction of a window that may be spent on tasks running only because
    /// they aged.
    pub override_budget: f32,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            window: Duration::from_millis(100),
            oversubscribe: 4,
            penalty_windows: 3,
            aging_base: Duration::from_millis(100),
            override_budget: 0.1,
        }
    }
}

/// Live counts, for whoever reports on the process.
///
/// The per-level breakdown is read through [`Self::queued_by_priority`], so a
/// report is written in terms of [`Priority`] rather than in terms of how the
/// schedule numbers its levels.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct Tasks {
    alive: [usize; Priority::LEVELS],
    queued: [usize; Priority::LEVELS],
    parked: usize,
}

impl Tasks {
    /// Spawned and not yet finished or cancelled, at every level together.
    pub fn alive(&self) -> usize {
        self.alive.iter().sum()
    }

    /// Spawned and not yet finished or cancelled, at `priority`.
    ///
    /// A task counts at the level it is at now, not the one it started at: a
    /// connection admitted at [`Priority::New`] and raised once it proves
    /// itself moves this count with it, and so do the other tasks sharing its
    /// [`SharedPriority`].
    pub fn alive_at(&self, priority: Priority) -> usize {
        self.alive[priority.level() as usize]
    }

    /// Spawned and not yet finished or cancelled, level by level, most urgent
    /// first.
    ///
    /// Every level is yielded, including empty ones. This is the breakdown that
    /// separates what a stranger created from what the application has vouched
    /// for: everything from [`Priority::New`] down is a peer nothing is yet
    /// known about.
    pub fn alive_by_priority(&self) -> impl Iterator<Item = (Priority, usize)> + '_ {
        self.alive
            .iter()
            .enumerate()
            .map(|(level, &count)| (Priority::from_level(level as u8), count))
    }

    /// Enqueued and waiting to run, at every level together.
    pub fn queued(&self) -> usize {
        self.queued.iter().sum()
    }

    /// Enqueued and waiting to run, at `priority`.
    pub fn queued_at(&self, priority: Priority) -> usize {
        self.queued[priority.level() as usize]
    }

    /// Enqueued and waiting to run, level by level, most urgent first.
    ///
    /// Every level is yielded, including empty ones.
    pub fn queued_by_priority(&self) -> impl Iterator<Item = (Priority, usize)> + '_ {
        self.queued
            .iter()
            .enumerate()
            .map(|(level, &count)| (Priority::from_level(level as u8), count))
    }

    /// Set aside for spending their share, awaiting the next refill.
    pub fn parked(&self) -> usize {
        self.parked
    }
}

/// Live tasks at each level.
///
/// Kept up to date as tasks are spawned, finish and change level, so reading it
/// is a snapshot rather than a walk. The maintenance is the price: a handle
/// changing level moves every task sharing it, which is why the count lives
/// beside the level rather than on each task.
///
/// One lock over the whole array rather than a counter per level, so a reader
/// sees a whole picture. Moving a handle is a subtraction and an addition, and
/// with a counter each there is a moment between them when the array describes
/// a process short of however many tasks that handle has — an undercount a
/// caller has no way to recognise. Affordable because nothing on the polling
/// path comes here: only spawning, finishing and re-levelling do, and a level
/// that changed as often as a task is polled would be a different problem.
#[derive(Debug, Default)]
pub(crate) struct Census(Mutex<[usize; Priority::LEVELS]>);

impl Census {
    /// Moves `count` tasks from `from` to `to`.
    #[inline]
    pub(crate) fn shift(&self, from: u8, to: u8, count: usize) {
        if from == to || count == 0 {
            return;
        }
        let mut levels = self.0.lock().unwrap();
        debug_assert!(levels[from as usize] >= count, "moved tasks nobody counted");
        levels[from as usize] = levels[from as usize].saturating_sub(count);
        levels[to as usize] += count;
    }

    /// Records one more task at `level`.
    #[inline]
    pub(crate) fn join(&self, level: u8) {
        self.0.lock().unwrap()[level as usize] += 1;
    }

    /// Records one fewer.
    #[inline]
    pub(crate) fn leave(&self, level: u8) {
        let mut levels = self.0.lock().unwrap();
        debug_assert!(
            levels[level as usize] > 0,
            "a task left a level it never joined"
        );
        levels[level as usize] = levels[level as usize].saturating_sub(1);
    }

    fn snapshot(&self) -> [usize; Priority::LEVELS] {
        *self.0.lock().unwrap()
    }
}

/// How often shares bit, over the windows measured.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct Throttling {
    /// Windows in which at least one task was set aside.
    pub throttled: u32,
    /// Windows measured.
    pub windows: u32,
}

impl Throttling {
    /// The share of windows that set something aside, in `0..=1`.
    pub fn fraction(&self) -> f32 {
        if self.windows == 0 {
            0.0
        } else {
            (self.throttled as f32 / self.windows as f32).clamp(0.0, 1.0)
        }
    }
}

/// A priority scheduler. Cheap to clone; clones share one schedule.
///
/// Owned by [`crate::Goalkeeper`], which is what the API hangs off.
#[derive(Clone)]
pub(crate) struct Executor(Arc<Shared>);

struct Shared {
    /// Which levels have something queued. Read without the lock, written only
    /// under it, so it never disagrees with the queues.
    ready: AtomicU32,
    /// Shared with every [`SharedPriority`] a task was spawned against, since
    /// that is what moves tasks between levels.
    census: Arc<Census>,
    inner: Mutex<Inner>,
    /// When this executor started, so instants can be stored as `u64` offsets.
    epoch_instant: Instant,
}

impl Default for Executor {
    fn default() -> Self {
        Self::new(Config::default())
    }
}

impl Executor {
    /// Creates a scheduler of its own, for tests and for callers with two
    /// independent workloads.
    pub fn new(config: Config) -> Self {
        Self(Arc::new(Shared {
            ready: AtomicU32::new(0),
            census: Arc::new(Census::default()),
            inner: Mutex::new(Inner::new(config)),
            epoch_instant: Instant::now(),
        }))
    }

    /// Adjusts one configured variable, leaving the rest alone.
    pub(crate) fn set_config_with(&self, f: impl FnOnce(&mut Config)) {
        f(&mut self.0.inner.lock().unwrap().config);
    }

    /// Spawns `future` at `priority`.
    ///
    /// The returned [`Task`] cancels the future when dropped; `detach` it to
    /// let it run unattended.
    pub fn spawn<F>(&self, priority: Priority, future: F) -> Task<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        self.spawn_with(SharedPriority::new(priority), future)
    }

    /// Like [`Self::spawn`] but joins an existing [`SharedPriority`], so the
    /// task moves when everything sharing that handle moves.
    pub fn spawn_with<F>(&self, priority: SharedPriority, future: F) -> Task<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        // Counted against the handle rather than the task, so that when the
        // handle moves it takes every task sharing it along. Joined before the
        // future exists, so a task is never live and uncounted.
        priority.census_join(&self.0.census);
        let state = Arc::new(TaskState::new(priority));
        let shared = Arc::clone(&self.0);
        let scheduled = Arc::clone(&state);
        // Left however the future ends, which `Runnable::run`'s return value
        // cannot distinguish.
        let alive = Alive(state.priority.clone());
        let (runnable, task) = async_task::spawn(
            async move {
                let _alive = alive;
                future.await
            },
            move |runnable| {
                // Reading the level here, at wake time, is what makes waker
                // interception unnecessary: waking is enqueueing at the task's
                // current level.
                Shared::push(
                    &shared,
                    Job {
                        runnable,
                        state: Arc::clone(&scheduled),
                    },
                );
            },
        );
        runnable.schedule();
        task
    }

    /// Drives this executor until `future` completes, then returns its output.
    ///
    /// `future` is polled first on every turn and answers to no share, aging or
    /// preemption. It is [`Priority::Main`], so give it the work everything else
    /// exists to protect.
    ///
    /// Not `Send`-bound, so a caller can drive a future owning non-`Send` state
    /// without spawning it.
    pub async fn run_until<F: Future>(&self, gk: &crate::Goalkeeper, future: F) -> F::Output {
        let shared = &self.0;
        let mut future = std::pin::pin!(future);

        // The lateness probe, not a spawned task: driven from here it stays out
        // of the live and queued counts, needs no cancelling, and measures how
        // long the caller's runtime takes to come back to this loop.
        let mut due = Instant::now() + shared.inner.lock().unwrap().config.window;
        // Reused across turns so a batch costs no allocation.
        let mut batch: Vec<(Job, bool)> = Vec::with_capacity(BATCH);
        let mut probe = std::pin::pin!(tokio::time::sleep_until(due.into()));

        poll_fn(|cx| {
            // Recorded every turn so a wake from the reactor or another thread
            // brings the executor back, rather than leaving the queues to fill
            // while `block_on` sleeps.
            shared.set_waker(cx.waker());

            if probe.as_mut().poll(cx).is_ready() {
                let now = Instant::now();
                let window = shared.inner.lock().unwrap().config.window;
                crate::resource::record_cpu_sample_of(
                    gk,
                    now.saturating_duration_since(due),
                    window,
                );
                // The bandwidth ledger's heartbeat. Without it, a process whose
                // connections are all parked on their ration has nothing left
                // to roll the window that would release them.
                crate::resource::bandwidth::tick_of(gk);
                // The memory controller, on its own slower cadence, reporting
                // whether it ran so the RAM axis is only re-reported when the
                // reading is new.
                {
                    // Moves the heartbeat's rotation on if a group is due.
                    // Driven from here rather than from the controller's own
                    // tick, so groups can be spaced within an interval.
                    gk.controller
                        .beat_due(now, crate::resource::memory::interval_of(gk));
                    let (ran, _) = crate::resource::memory::tick_of(gk);
                    if ran {
                        crate::resource::record_memory_of(
                            gk,
                            crate::resource::memory::fullness_of(gk),
                        );
                        crate::resource::glide(gk);
                    }
                }
                // Skips whatever was missed rather than firing repeatedly to
                // catch up, which would count one stall many times over.
                due = (due + window).max(now);
                probe.as_mut().reset(due.into());
                // Registers the waker against the new deadline.
                let _ = probe.as_mut().poll(cx);
            }

            if let Poll::Ready(output) = future.as_mut().poll(cx) {
                return Poll::Ready(output);
            }

            // One clock read per iteration rather than three, since the instant
            // ending one poll begins the next. Each task is therefore charged
            // for the `pick` that chose it as well as its own run, which
            // happens on its behalf and nobody else's.
            let mut now = Instant::now();
            let mut ran = 0usize;
            while ran < TASKS_PER_TICK {
                let room = BATCH.min(TASKS_PER_TICK - ran);
                let level = shared.pick_batch(now, &mut batch, room);
                if batch.is_empty() {
                    break;
                }

                let mut rest = batch.drain(..);
                while let Some((job, aged)) = rest.next() {
                    // Outside the lock, since running a task may spawn, wake or
                    // re-enter the executor, all of which take it.
                    job.runnable.run();
                    let ended = Instant::now();
                    shared.charge(&job.state, (ended - now) + POLL_COST, aged);
                    now = ended;
                    ran += 1;

                    // Preemption, checked without the lock: something better
                    // waking must not wait behind the rest of the batch.
                    let bits = shared.ready.load(Ordering::Acquire);
                    if bits != 0 && (bits.trailing_zeros() as u8) < level {
                        shared.give_back(rest.by_ref());
                        break;
                    }
                }
                drop(rest);
            }

            // More to do, but the reactor deserves a turn.
            if shared.ready.load(Ordering::Acquire) != 0 {
                cx.waker().wake_by_ref();
            }
            Poll::Pending
        })
        .await
    }

    /// Reads [`Tasks`].
    pub fn tasks(&self) -> Tasks {
        let inner = self.0.inner.lock().unwrap();
        let mut queued = [0usize; Priority::LEVELS];
        for (level, queue) in inner.queues.iter().enumerate() {
            queued[level] = queue.len();
        }
        Tasks {
            alive: self.0.census.snapshot(),
            queued,
            parked: inner.parked.len(),
        }
    }

    /// Reads [`Throttling`] and starts a fresh measurement window.
    pub fn throttling(&self) -> Throttling {
        let mut inner = self.0.inner.lock().unwrap();
        Throttling {
            throttled: std::mem::take(&mut inner.windows_throttled),
            windows: std::mem::take(&mut inner.windows_counted),
        }
    }
}

/// Decrements the live count however its future ends.
struct Alive(SharedPriority);

impl Drop for Alive {
    fn drop(&mut self) {
        self.0.census_leave();
    }
}

/// A runnable task and the accounting that follows it.
struct Job {
    runnable: Runnable,
    state: Arc<TaskState>,
}

/// What the executor remembers about one task.
struct TaskState {
    /// Also where this task's share accounting lives, shared with every other
    /// task serving the same connection. See `priority::Accounting`.
    priority: SharedPriority,
    /// Nanoseconds since the executor started, at the moment this task was last
    /// enqueued. Aging measures from here.
    enqueued_nanos: AtomicU64,
}

impl TaskState {
    fn new(priority: SharedPriority) -> Self {
        Self {
            priority,
            enqueued_nanos: AtomicU64::new(0),
        }
    }
}

struct Inner {
    /// Kept here rather than behind a lock of its own, so choosing a task takes
    /// one lock instead of two.
    config: Config,
    queues: [VecDeque<Job>; Priority::LEVELS],
    /// Set aside for spending a share, returned to their queues at the next
    /// refill. Not per level, since only tasks that overspent are here.
    parked: Vec<Job>,
    /// Bumped by every refill. A task whose recorded window differs has a stale
    /// `spent_nanos`.
    epoch: u64,
    window_started_nanos: u64,
    /// Distinct tasks considered at each level this window.
    ///
    /// Considered rather than alive, since most tasks sit parked on IO costing
    /// nothing. Counting those too would let an attacker holding ten thousand
    /// idle connections dilute everyone's share without spending any CPU.
    participants: [u32; Priority::LEVELS],
    /// The previous window's count, used as a floor.
    ///
    /// Without it the first task considered in a window would see one
    /// participant and take the whole window. The count only rises within a
    /// window, so a share can only narrow and nothing already parked is
    /// un-parked by a later change.
    previous_participants: [u32; Priority::LEVELS],
    /// Spent this window on tasks running only because they aged.
    override_spent: Duration,
    windows_counted: u32,
    windows_throttled: u32,
    window_throttled: bool,
    waker: Option<Waker>,
}

impl Inner {
    fn new(config: Config) -> Self {
        Self {
            config,
            queues: std::array::from_fn(|_| VecDeque::new()),
            parked: Vec::new(),
            epoch: 1,
            window_started_nanos: 0,
            participants: [0; Priority::LEVELS],
            previous_participants: [0; Priority::LEVELS],
            override_spent: Duration::ZERO,
            windows_counted: 0,
            windows_throttled: 0,
            window_throttled: false,
            waker: None,
        }
    }
}

impl Shared {
    #[inline(always)]
    fn now_nanos(&self, now: Instant) -> u64 {
        now.saturating_duration_since(self.epoch_instant).as_nanos() as u64
    }

    fn set_waker(&self, waker: &Waker) {
        let mut inner = self.inner.lock().unwrap();
        match &inner.waker {
            Some(existing) if existing.will_wake(waker) => {}
            _ => inner.waker = Some(waker.clone()),
        }
    }

    /// Enqueues a woken task at whatever level it is at *now*.
    #[inline]
    fn push(shared: &Arc<Shared>, job: Job) {
        let level = job.state.priority.level() as usize;
        debug_assert!(level < Priority::LEVELS, "level {level} is off the ladder");
        let waker = {
            let mut inner = shared.inner.lock().unwrap();
            job.state
                .enqueued_nanos
                .store(shared.now_nanos(Instant::now()), Ordering::Relaxed);
            inner.queues[level].push_back(job);
            // Under the lock, so the bitmap and the queues cannot disagree.
            shared.ready.fetch_or(1 << level, Ordering::Release);
            inner.waker.take()
        };
        // Outside the lock: waking may run arbitrary code.
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    /// Takes up to `max` jobs from the best occupied level in one acquisition,
    /// and reports which level they came from.
    ///
    /// One acquisition per batch rather than per task, so a wake landing while
    /// the loop runs contends with nothing. The caller re-checks the bitmap
    /// between runs and hands back what it has not started. A batch never spans
    /// more than one level, which would be a priority inversion.
    fn pick_batch(&self, now: Instant, out: &mut Vec<(Job, bool)>, max: usize) -> u8 {
        let mut inner = self.inner.lock().unwrap();
        let config = inner.config;
        self.roll(&mut inner, now, &config);

        let mut level = Priority::LEVELS as u8;
        while out.len() < max {
            let Some((job, aged)) = self.pick_locked(&mut inner, now, &config) else {
                break;
            };
            let at = job.state.priority.level();
            if out.is_empty() {
                level = at;
            } else if at != level {
                // A better or worse level than the rest of the batch. Put it
                // back untouched and let the next batch decide.
                Self::requeue(&self.ready, &mut inner, job);
                break;
            }
            out.push((job, aged));
        }
        level
    }

    /// Returns jobs the loop chose but never started, at whatever level they
    /// now belong to.
    fn give_back(&self, jobs: impl Iterator<Item = (Job, bool)>) {
        let mut inner = self.inner.lock().unwrap();
        for (job, _) in jobs {
            Self::requeue(&self.ready, &mut inner, job);
        }
    }

    /// Puts one job back on its queue and marks its level occupied.
    #[inline(always)]
    fn requeue(ready: &AtomicU32, inner: &mut Inner, job: Job) {
        let level = job.state.priority.level() as usize;
        inner.queues[level].push_front(job);
        ready.fetch_or(1 << level, Ordering::Release);
    }

    /// The body of [`Self::pick_batch`], with the lock and the roll done.
    fn pick_locked(&self, inner: &mut Inner, now: Instant, config: &Config) -> Option<(Job, bool)> {
        loop {
            let bits = self.ready.load(Ordering::Acquire);
            if bits == 0 {
                return None;
            }
            let best = bits.trailing_zeros() as usize;
            let level = self.aged_choice(inner, best, now, config).unwrap_or(best);
            let aged = level != best;

            let Some(job) = inner.queues[level].pop_front() else {
                // The bitmap outran the queues, which should not happen; repair
                // rather than spin.
                debug_assert!(false, "bitmap claimed level {level} was occupied");
                self.ready.fetch_and(!(1 << level), Ordering::Release);
                continue;
            };
            // Cleared from the level the job came from, never from the task's
            // current priority: a task re-levelled while queued would otherwise
            // clear some other level's bit and leave this one set forever.
            if inner.queues[level].is_empty() {
                self.ready.fetch_and(!(1 << level), Ordering::Release);
            }

            if self.admit(inner, &job, level, config) {
                return Some((job, aged));
            }
            inner.window_throttled = true;
            inner.parked.push(job);
        }
    }

    /// Charges a poll to the task that took it.
    #[inline(always)]
    fn charge(&self, state: &Arc<TaskState>, spent: Duration, aged: bool) {
        state
            .priority
            .accounting()
            .spent_nanos
            .fetch_add(spent.as_nanos() as u64, Ordering::Relaxed);
        if aged {
            let mut inner = self.inner.lock().unwrap();
            inner.override_spent += spent;
        }
    }

    /// Starts a new window if the last one is over.
    fn roll(&self, inner: &mut Inner, now: Instant, config: &Config) {
        let now_nanos = self.now_nanos(now);
        if now_nanos.saturating_sub(inner.window_started_nanos) < config.window.as_nanos() as u64 {
            return;
        }
        inner.window_started_nanos = now_nanos;
        inner.epoch = inner.epoch.wrapping_add(1).max(1);
        inner.previous_participants = inner.participants;
        inner.participants = [0; Priority::LEVELS];
        inner.override_spent = Duration::ZERO;
        inner.windows_counted = inner.windows_counted.saturating_add(1);
        if std::mem::take(&mut inner.window_throttled) {
            inner.windows_throttled = inner.windows_throttled.saturating_add(1);
        }

        // Everything set aside for overspending gets another turn. Tasks held
        // back by priority never left their queue, so these are the only ones a
        // refill has to wake.
        for job in std::mem::take(&mut inner.parked) {
            let level = job.state.priority.level() as usize;
            inner.queues[level].push_back(job);
            self.ready.fetch_or(1 << level, Ordering::Release);
        }
    }

    /// Whether `job` may run, counting it as a participant the first time it is
    /// considered in a window.
    #[inline]
    fn admit(&self, inner: &mut Inner, job: &Job, level: usize, config: &Config) -> bool {
        // Per connection, not per task: several tasks may share this and count
        // and spend as one. See `priority::Accounting`.
        let state = job.state.priority.accounting();

        if state.window.load(Ordering::Relaxed) != inner.epoch {
            state.window.store(inner.epoch, Ordering::Relaxed);
            // A connection rejoining at a different level owes nothing to the
            // pool it has just entered.
            state.spent_nanos.store(0, Ordering::Relaxed);
            // First consideration in a window always succeeds, so counting here
            // is the same as counting on first dispatch.
            inner.participants[level] = inner.participants[level].saturating_add(1);
        }

        let participants = inner.participants[level]
            .max(inner.previous_participants[level])
            .max(1) as u64;
        let mut allowance = config.window.as_nanos() as u64 * config.oversubscribe.max(1) as u64;
        if state.exhaustions.load(Ordering::Relaxed) >= config.penalty_windows {
            // Proven to be the busy one, so it gets the equal split that the
            // headroom was an exception to.
            allowance /= config.oversubscribe.max(1) as u64;
        }

        let spent = state.spent_nanos.load(Ordering::Relaxed);
        let within = spent.saturating_mul(participants) < allowance;
        if within {
            state.exhaustions.store(0, Ordering::Relaxed);
        } else {
            state.exhaustions.fetch_add(1, Ordering::Relaxed);
        }
        within
    }

    /// A level that has waited long enough to be served ahead of `best`, if the
    /// override budget allows one.
    ///
    /// Aging moves a task up one occupied level per doubling of
    /// [`Config::aging_base`]. Occupied rather than one integer, since the
    /// ladder is sparse and stepping by number would take a stranger two
    /// hundred doublings to reach the top.
    fn aged_choice(
        &self,
        inner: &Inner,
        best: usize,
        now: Instant,
        config: &Config,
    ) -> Option<usize> {
        if inner.override_spent >= config.window.mul_f32(config.override_budget) {
            return None;
        }
        let base = config.aging_base.as_nanos().max(1) as u64;
        let now_nanos = self.now_nanos(now);

        let mut choice = None;
        let mut choice_slack = 0u32;
        for level in (best + 1)..Priority::LEVELS {
            let Some(head) = inner.queues[level].front() else {
                continue;
            };
            let waited =
                now_nanos.saturating_sub(head.state.enqueued_nanos.load(Ordering::Relaxed));
            if waited < base {
                continue;
            }
            let promotions = (waited / base).ilog2() + 1;
            let occupied_above = (best..level)
                .filter(|l| !inner.queues[*l].is_empty())
                .count() as u32;
            if occupied_above > 0 && promotions >= occupied_above {
                let slack = promotions - occupied_above;
                if choice.is_none() || slack > choice_slack {
                    choice = Some(level);
                    choice_slack = slack;
                }
            }
        }
        choice
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::executor::priority::UserPriority::*;
    use std::sync::atomic::AtomicUsize;

    /// Runs `body` on a fresh runtime and a fresh scheduler, so tests cannot
    /// see each other's queues.
    fn drive<F, Fut, T>(config: Config, body: F) -> T
    where
        F: FnOnce(Executor) -> Fut,
        Fut: Future<Output = T>,
    {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let executor = Executor::new(config);
        let driven = executor.clone();
        // The process's goalkeeper; these exercise the schedule, not the
        // ledgers.
        runtime.block_on(driven.run_until(crate::system(), body(executor)))
    }

    /// Windows and aging short enough that a test finishes in milliseconds.
    fn brisk() -> Config {
        Config {
            window: Duration::from_millis(20),
            aging_base: Duration::from_millis(5),
            ..Config::default()
        }
    }

    #[test]
    fn a_spawned_task_runs_and_joins() {
        let out = drive(Config::default(), |ex| async move {
            ex.spawn(Priority::User(L0), async { 7u32 }).await
        });
        assert_eq!(out, 7);
    }

    #[test]
    fn every_level_is_reachable() {
        let out = drive(Config::default(), |ex| async move {
            let mut sum = 0;
            for p in [
                Priority::Main,
                Priority::User(L0),
                Priority::User(crate::executor::priority::UserPriority::WORST),
                Priority::New,
                Priority::Accept,
            ] {
                sum += ex.spawn(p, async { 1u32 }).await;
            }
            sum
        });
        assert_eq!(out, 5);
    }

    #[test]
    fn work_is_taken_most_urgent_first() {
        let order = Arc::new(Mutex::new(Vec::new()));
        let seen = drive(Config::default(), {
            let order = Arc::clone(&order);
            |ex| async move {
                // Spawned worst-first, so the completion order can only come
                // from the schedule and not from arrival.
                let mut tasks = Vec::new();
                for p in [
                    Priority::Accept,
                    Priority::New,
                    Priority::User(L2),
                    Priority::User(L0),
                ] {
                    let order = Arc::clone(&order);
                    tasks.push(ex.spawn(p, async move {
                        order.lock().unwrap().push(p);
                    }));
                }
                for task in tasks {
                    task.await;
                }
                order.lock().unwrap().clone()
            }
        });
        assert_eq!(
            seen,
            vec![
                Priority::User(L0),
                Priority::User(L2),
                Priority::New,
                Priority::Accept,
            ]
        );
    }

    #[test]
    fn a_flood_of_low_priority_work_is_not_even_polled() {
        // The property a gate cannot provide: tasks held back by priority are
        // never touched, so holding them back costs nothing.
        //
        // Sampled inside the urgent task rather than after awaiting it, by
        // which point the strangers have quite properly been served.
        let polled = Arc::new(AtomicUsize::new(0));
        let observed = drive(Config::default(), {
            let polled = Arc::clone(&polled);
            |ex| async move {
                for _ in 0..1000 {
                    let polled = Arc::clone(&polled);
                    ex.spawn(Priority::Accept, async move {
                        polled.fetch_add(1, Ordering::Relaxed);
                    })
                    .detach();
                }
                let seen = Arc::clone(&polled);
                ex.spawn(
                    Priority::User(L0),
                    async move { seen.load(Ordering::Relaxed) },
                )
                .await
            }
        });
        assert_eq!(
            observed, 0,
            "strangers were polled before the urgent task got its turn"
        );
        assert!(
            polled.load(Ordering::Relaxed) > 0,
            "the strangers should still run once nothing better is waiting"
        );
    }

    #[test]
    fn an_endless_low_priority_stream_does_not_delay_better_work() {
        let done = Arc::new(AtomicUsize::new(0));
        let rounds = drive(Config::default(), {
            let done = Arc::clone(&done);
            |ex| async move {
                let spin = ex.spawn(Priority::Accept, async {
                    loop {
                        tokio::task::yield_now().await;
                    }
                });
                let mut rounds = 0usize;
                for _ in 0..50 {
                    let done = Arc::clone(&done);
                    ex.spawn(Priority::User(L0), async move {
                        done.fetch_add(1, Ordering::Relaxed);
                    })
                    .await;
                    rounds += 1;
                }
                drop(spin);
                rounds
            }
        });
        assert_eq!(rounds, 50);
        assert_eq!(done.load(Ordering::Relaxed), 50);
    }

    #[test]
    fn dropping_a_task_cancels_it() {
        let ran = Arc::new(AtomicUsize::new(0));
        drive(brisk(), {
            let ran = Arc::clone(&ran);
            |ex| async move {
                let task = ex.spawn(Priority::User(L0), async move {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    ran.fetch_add(1, Ordering::Relaxed);
                });
                drop(task);
                tokio::time::sleep(Duration::from_millis(80)).await;
            }
        });
        assert_eq!(ran.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn a_detached_task_still_runs() {
        let ran = Arc::new(AtomicUsize::new(0));
        drive(brisk(), {
            let ran = Arc::clone(&ran);
            |ex| async move {
                let ran2 = Arc::clone(&ran);
                ex.spawn(Priority::User(L0), async move {
                    ran2.fetch_add(1, Ordering::Relaxed);
                })
                .detach();
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        });
        assert_eq!(ran.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn the_live_count_returns_to_zero() {
        // Whether a task completes or is cancelled, it must stop being counted;
        // `Runnable::run`'s return value cannot tell the two apart.
        let executor = Executor::new(brisk());
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let driven = executor.clone();
        let ex = executor.clone();
        runtime.block_on(driven.run_until(crate::system(), async move {
            let finished = ex.spawn(Priority::User(L0), async { 1u32 });
            let cancelled = ex.spawn(Priority::New, async {
                tokio::time::sleep(Duration::from_secs(60)).await;
            });
            let tasks = ex.tasks();
            assert_eq!(tasks.alive(), 2);
            // Counted where they are, not merely counted.
            assert_eq!(tasks.alive_at(Priority::User(L0)), 1);
            assert_eq!(tasks.alive_at(Priority::New), 1);
            let _ = finished.await;
            drop(cancelled);
            tokio::time::sleep(Duration::from_millis(10)).await;
        }));
        assert_eq!(executor.tasks().alive(), 0);
        assert!(executor.tasks().alive_by_priority().all(|(_, n)| n == 0));
    }

    /// A task counts at the level its handle is at now, and moves with it.
    #[test]
    fn re_levelling_a_handle_moves_every_task_sharing_it() {
        let executor = Executor::new(brisk());
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let driven = executor.clone();
        let ex = executor.clone();
        runtime.block_on(driven.run_until(crate::system(), async move {
            // Two tasks on one handle, as a connection and its streams are.
            let shared = SharedPriority::new(Priority::New);
            let tasks: Vec<_> = (0..2)
                .map(|_| {
                    ex.spawn_with(shared.clone(), async {
                        tokio::time::sleep(Duration::from_secs(60)).await;
                    })
                })
                .collect();
            assert_eq!(ex.tasks().alive_at(Priority::New), 2);

            shared.set_base(Priority::User(L0));
            let moved = ex.tasks();
            assert_eq!(moved.alive_at(Priority::New), 0, "left behind");
            assert_eq!(moved.alive_at(Priority::User(L0)), 2, "both moved");

            // A boost composes over the base and takes them along too.
            let boost = shared.boost(Priority::Main);
            assert_eq!(ex.tasks().alive_at(Priority::Main), 2);
            drop(boost);
            assert_eq!(ex.tasks().alive_at(Priority::User(L0)), 2, "given back");

            // Dying at the level they were moved to, not the one they started
            // at, which is what would leave a count stranded.
            drop(tasks);
            tokio::time::sleep(Duration::from_millis(10)).await;
            assert_eq!(ex.tasks().alive(), 0);
            assert!(ex.tasks().alive_by_priority().all(|(_, n)| n == 0));
        }));
    }

    /// A reader never catches the census mid-move.
    ///
    /// Re-levelling is a subtraction and an addition. With a counter per level
    /// there is a moment between them where the tasks being moved are at no
    /// level at all, and a reader landing there is told the process has fewer
    /// tasks than it does — silently, since nothing about the answer says it was
    /// taken mid-flight. The total is fixed and known here, so any reading other
    /// than that total is that gap.
    #[test]
    fn a_reader_never_sees_a_partly_moved_census() {
        const TASKS: usize = 16;

        let executor = Executor::new(brisk());
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let driven = executor.clone();
        let ex = executor.clone();
        runtime.block_on(driven.run_until(crate::system(), async move {
            // One handle, so every move is all of them at once and the window
            // is as wide as this can make it.
            let shared = SharedPriority::new(Priority::New);
            let _tasks: Vec<_> = (0..TASKS)
                .map(|_| {
                    ex.spawn_with(shared.clone(), async {
                        tokio::time::sleep(Duration::from_secs(60)).await;
                    })
                })
                .collect();

            let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let mover = {
                let shared = shared.clone();
                let stop = Arc::clone(&stop);
                std::thread::spawn(move || {
                    while !stop.load(Ordering::Relaxed) {
                        shared.set_base(Priority::User(L0));
                        shared.set_base(Priority::Accept);
                    }
                })
            };

            let mut seen = Vec::new();
            for _ in 0..200_000 {
                let alive = ex.tasks().alive();
                if alive != TASKS {
                    seen.push(alive);
                    break;
                }
            }
            stop.store(true, Ordering::Relaxed);
            let _ = mover.join();

            assert!(
                seen.is_empty(),
                "a snapshot read {seen:?} while {TASKS} tasks were alive"
            );
        }));
    }

    #[test]
    fn timers_still_fire_while_the_queues_are_busy() {
        // The executor is a future inside `block_on`; if it never yields, the
        // reactor never runs and nothing waiting on time or IO completes.
        let elapsed = drive(brisk(), |ex| async move {
            for _ in 0..500 {
                ex.spawn(Priority::Accept, async {
                    for _ in 0..1000 {
                        tokio::task::yield_now().await;
                    }
                })
                .detach();
            }
            let started = Instant::now();
            tokio::time::sleep(Duration::from_millis(30)).await;
            started.elapsed()
        });
        assert!(
            elapsed < Duration::from_secs(3),
            "the reactor was starved: {elapsed:?}"
        );
    }

    #[test]
    fn a_task_woken_from_another_thread_is_enqueued() {
        let out = drive(brisk(), |ex| async move {
            let (tx, rx) = tokio::sync::oneshot::channel::<u32>();
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(10));
                let _ = tx.send(9);
            });
            ex.spawn(Priority::User(L0), async move { rx.await.unwrap() })
                .await
        });
        assert_eq!(out, 9);
    }

    #[test]
    fn re_levelling_a_queued_task_does_not_strand_a_bit() {
        // Clearing the bitmap from the task's *current* priority rather than
        // the queue it came from would leave a bit set forever, stalling that
        // level and everything below it.
        let executor = Executor::new(brisk());
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let driven = executor.clone();
        let ex = executor.clone();
        let out = runtime.block_on(driven.run_until(crate::system(), async move {
            let priority = SharedPriority::new(Priority::Accept);
            let moved = priority.clone();
            let task = ex.spawn_with(priority, async { 5u32 });
            // Re-level it while it sits in the `Accept` queue.
            moved.set_base(Priority::User(L0));
            let first = task.await;
            // Everything must still schedule afterwards.
            let second = ex.spawn(Priority::Accept, async { 6u32 }).await;
            first + second
        }));
        assert_eq!(out, 11);
        let queued = executor.tasks().queued;
        assert!(
            queued.iter().all(|n| *n == 0),
            "a queue was left occupied: {queued:?}"
        );
    }

    #[test]
    fn nothing_is_left_queued_after_everything_finishes() {
        let executor = Executor::new(brisk());
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let driven = executor.clone();
        let ex = executor.clone();
        runtime.block_on(driven.run_until(crate::system(), async move {
            let mut tasks = Vec::new();
            for i in 0..200 {
                let p = if i % 2 == 0 {
                    Priority::User(L0)
                } else {
                    Priority::New
                };
                tasks.push(ex.spawn(p, async {
                    tokio::task::yield_now().await;
                }));
            }
            for task in tasks {
                task.await;
            }
        }));
        let snapshot = executor.tasks();
        assert!(
            snapshot.queued.iter().all(|n| *n == 0) && snapshot.parked == 0,
            "left behind: {snapshot:?}"
        );
        assert_eq!(snapshot.alive(), 0);
    }

    #[test]
    fn a_starved_level_is_eventually_served() {
        // Strict priority alone would never run the low task while the high one
        // keeps waking. Aging is what stops that being permanent.
        let low_ran = Arc::new(AtomicUsize::new(0));
        drive(brisk(), {
            let low_ran = Arc::clone(&low_ran);
            |ex| async move {
                let spin = ex.spawn(Priority::User(L0), async {
                    loop {
                        tokio::task::yield_now().await;
                    }
                });
                let low = ex.spawn(Priority::Accept, async move {
                    low_ran.fetch_add(1, Ordering::Relaxed);
                });
                let _ = tokio::time::timeout(Duration::from_millis(2000), low).await;
                drop(spin);
            }
        });
        assert_eq!(
            low_ran.load(Ordering::Relaxed),
            1,
            "the starved task never ran"
        );
    }
}
