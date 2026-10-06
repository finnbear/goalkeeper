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
pub mod timer;

use crate::executor::priority::{Priority, SharedPriority};
use crate::executor::timer::{Interval, Sleep, TimerKey};
use async_task::{FallibleTask, Runnable};
use fxhash::FxHashMap;
use std::cell::Cell;
use std::collections::{BTreeMap, VecDeque};
use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

/// How many tasks one turn of [`Executor::run_until`] may run before yielding.
///
/// The executor is a future inside somebody's `block_on`, so while it runs the
/// reactor does not. Returning periodically is what lets IO readiness and
/// timers arrive. `LocalSet` caps at 61 for the same reason.
///
/// An upper bound, not a target: a turn also ends when the cooperative budget
/// runs out, which under load happens first. See [`Executor::run_until`].
///
/// Polling the root again for a [`timer`] of its own counts as a task, so this
/// bounds those too.
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
pub(crate) struct Executor(handle::Handle);

mod handle {
    use super::Shared;
    use std::sync::Arc;
    use std::sync::atomic::Ordering;

    /// The schedule, counted: closed once the last of these is gone, if it can
    /// close at all. A [`Mode::Permanent`](super::Mode::Permanent) one keeps no
    /// count, since there is nothing for one to decide.
    ///
    /// Tasks and timers hold a bare `Arc<Shared>` rather than this. Were they
    /// to, a task left queued or waiting on a timer would keep itself alive:
    /// `Shared`, its queue or timer list, the task, and back to `Shared`.
    ///
    /// In a module of its own so that nothing else can build one, since one
    /// built without counting would close the schedule under its clones.
    pub(super) struct Handle(Arc<Shared>);

    impl Handle {
        /// The first handle to `shared`.
        pub(super) fn new(shared: Shared) -> Self {
            if let Some(handles) = shared.mode.handles() {
                handles.store(1, Ordering::Relaxed);
            }
            Self(Arc::new(shared))
        }
    }

    impl Clone for Handle {
        fn clone(&self) -> Self {
            // Relaxed like `Arc`'s own: a new handle is made from an existing
            // one, which keeps the count above zero meanwhile.
            if let Some(handles) = self.0.mode.handles() {
                handles.fetch_add(1, Ordering::Relaxed);
            }
            Self(Arc::clone(&self.0))
        }
    }

    impl std::ops::Deref for Handle {
        type Target = Arc<Shared>;

        fn deref(&self) -> &Arc<Shared> {
            &self.0
        }
    }

    impl Drop for Handle {
        fn drop(&mut self) {
            if let Some(handles) = self.0.mode.handles()
                && handles.fetch_sub(1, Ordering::AcqRel) == 1
            {
                self.0.close();
            }
        }
    }
}

thread_local! {
    /// The executor whose `run_until` is polling its root future on this
    /// thread right now, if any, so a timer registered meanwhile is known to be
    /// the root's. Per thread, since a timer polled on another thread at the
    /// same moment is not; per executor, since a root may poll another's timer.
    static POLLING_ROOT: Cell<*const Shared> = const { Cell::new(std::ptr::null()) };
}

/// Marks this thread as polling `shared`'s root for as long as it lives, and
/// restores whatever was marked before, even if the poll panics.
struct PollingRoot(*const Shared);

impl PollingRoot {
    fn enter(shared: &Shared) -> Self {
        Self(POLLING_ROOT.replace(shared))
    }
}

impl Drop for PollingRoot {
    fn drop(&mut self) {
        POLLING_ROOT.set(self.0);
    }
}

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
    /// Registered [`timer`]s, behind a lock of their own so that registering
    /// one never contends with the schedule.
    timers: Mutex<Timers>,
    /// When the earliest registered [`timer`] is due, as an offset like the
    /// rest, or `u64::MAX` for none. Read without the lock after every task,
    /// written only under `timers`.
    ///
    /// Sequentially consistent, as is [`Self::turning`], since the two are a
    /// handshake: a timer registered as a turn ends is seen either by the
    /// turn re-arming its alarm or by the registration waking the executor.
    next_timer_nanos: AtomicU64,
    /// Whether `run_until` is in a turn, and so will re-arm its alarm for any
    /// timer registered meanwhile before it sleeps. A timer registered outside
    /// one, as the earliest, wakes the executor to re-arm instead.
    turning: AtomicBool,
    /// Whatever wants to run at the end of every turn; see
    /// [`Executor::on_turn_end`].
    turn_hooks: Mutex<Vec<Weak<dyn TurnHook>>>,
    /// Whether `turn_hooks` holds anything, so a turn with none costs a load
    /// rather than a lock.
    has_turn_hooks: AtomicBool,
    /// Whether this executor can ever close, and what closing it takes.
    mode: Mode,
}

/// Something run at the end of every turn of [`Executor::run_until`]; see
/// [`Executor::on_turn_end`].
pub(crate) trait TurnHook: Send + Sync {
    /// The turn's tasks have run, and the reactor is about to have its turn.
    ///
    /// Run on the executor's thread, with a lock held that other turns ending
    /// on other threads also take, so it should be quick, and must not
    /// register a hook itself.
    fn turn_ended(&self);
}

/// Whether an executor can close. Fixed at construction.
enum Mode {
    /// The process's: it lives in a `static`, which is never dropped, and no
    /// owner wraps it to close it.
    ///
    /// So it keeps nothing for closing. [`Mode::Ephemeral`]'s record of live
    /// tasks would be a lock, a waker clone and a map entry on every spawn,
    /// and another lock on every task's end, all for a close that never comes,
    /// on the one executor where they are paid most.
    Permanent,
    /// Closes when its owner does, or its last [`handle::Handle`] goes.
    Ephemeral {
        /// A waker for every live task, by the address of its [`TaskState`].
        ///
        /// What lets [`Shared::close`] reach a task waiting on something the
        /// executor does not hold: a socket, or a ledger inside the very
        /// `Goalkeeper` whose handle the task keeps alive. Woken, it is
        /// scheduled, and a closed executor drops what is scheduled.
        live: Mutex<FxHashMap<usize, Waker>>,
        /// Live [`handle::Handle`]s, which is to say clones of the
        /// [`Executor`].
        handles: AtomicUsize,
        /// Set once the last [`handle::Handle`] is gone, or its owner closes
        /// it. Nothing will run a task again, so one woken from then on is
        /// dropped rather than queued, and a timer is not registered. Read under
        /// whichever lock guards what it would be added to, so nothing added
        /// can slip past [`Shared::close`]'s sweep.
        closed: AtomicBool,
    },
}

impl Mode {
    fn ephemeral() -> Self {
        Self::Ephemeral {
            live: Mutex::new(FxHashMap::default()),
            handles: AtomicUsize::new(0),
            closed: AtomicBool::new(false),
        }
    }

    /// The count of [`handle::Handle`]s, where closing hangs on it.
    fn handles(&self) -> Option<&AtomicUsize> {
        match self {
            Self::Permanent => None,
            Self::Ephemeral { handles, .. } => Some(handles),
        }
    }
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
        Self::build(config, Mode::ephemeral())
    }

    /// Creates the process's scheduler, which can never close and so keeps no
    /// record of its tasks for closing them. See [`Mode::Permanent`].
    ///
    /// Unused by unit tests, which are forbidden the process's instance.
    #[cfg_attr(test, allow(dead_code))]
    pub(crate) fn permanent(config: Config) -> Self {
        Self::build(config, Mode::Permanent)
    }

    fn build(config: Config, mode: Mode) -> Self {
        Self(handle::Handle::new(Shared {
            ready: AtomicU32::new(0),
            census: Arc::new(Census::default()),
            inner: Mutex::new(Inner::new(config)),
            epoch_instant: Instant::now(),
            timers: Mutex::new(Timers::default()),
            next_timer_nanos: AtomicU64::new(u64::MAX),
            turning: AtomicBool::new(false),
            turn_hooks: Mutex::new(Vec::new()),
            has_turn_hooks: AtomicBool::new(false),
            mode,
        }))
    }

    /// Runs `hook` at the end of every turn of [`Self::run_until`], until it is
    /// dropped.
    ///
    /// For work that is cheaper done once for everything a turn's tasks
    /// produced than once for each: sending the turn's packets with one system
    /// call, for one. The end of a turn is when every task that was ready has
    /// run, or as many as a turn runs, and the reactor, which would carry
    /// anything out, has not yet had its turn.
    #[allow(unused)]
    pub(crate) fn on_turn_end(&self, hook: Weak<dyn TurnHook>) {
        self.0.turn_hooks.lock().unwrap().push(hook);
        self.0.has_turn_hooks.store(true, Ordering::Release);
    }

    /// Drops every task now, and every task spawned or woken from now on,
    /// since nothing will run them again. Irreversible.
    ///
    /// For an owner whose tasks may hold clones of it, and so keep every
    /// [`Executor`] alive: waiting for the last to drop would wait forever.
    pub(crate) fn close(&self) {
        self.0.close();
    }

    /// A [`Sleep`] until `deadline`, fired by this executor as soon as it is
    /// due, between two tasks if need be.
    pub fn sleep_until(&self, deadline: Instant) -> Sleep {
        Sleep::new(Arc::clone(&self.0), deadline)
    }

    /// An [`Interval`] ticking first at `start`, then every `period`, fired
    /// like [`Self::sleep_until`]. See [`Interval::late`] for `late`.
    pub fn interval_at(&self, start: Instant, period: Duration, late: Duration) -> Interval {
        Interval::new(Arc::clone(&self.0), start, period, late)
    }

    /// Adjusts one configured variable, leaving the rest alone.
    pub(crate) fn set_config_with(&self, f: impl FnOnce(&mut Config)) {
        f(&mut self.0.inner.lock().unwrap().config);
    }

    /// Spawns `future` at `priority`.
    ///
    /// The returned [`FallibleTask`] cancels the future when dropped; `detach`
    /// it to let it run unattended. It completes with [`None`] if the executor
    /// closes first, having dropped the future unfinished.
    pub fn spawn<F>(&self, priority: Priority, future: F) -> FallibleTask<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        self.spawn_with(SharedPriority::new(priority), future)
    }

    /// Like [`Self::spawn`] but joins an existing [`SharedPriority`], so the
    /// task moves when everything sharing that handle moves.
    pub fn spawn_with<F>(&self, priority: SharedPriority, future: F) -> FallibleTask<F::Output>
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
        let alive = Alive {
            state: Arc::clone(&state),
            shared: Arc::clone(&self.0),
        };
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
        // Before it is scheduled, so a close after this reaches it wherever it
        // goes to wait.
        self.0.enlist(&state, &runnable);
        runnable.schedule();
        // Fallible, since a closed executor drops the future, and awaiting an
        // infallible `Task` for one that was dropped panics.
        task.fallible()
    }

    /// Drives this executor until `future` completes, then returns its output.
    ///
    /// `future` is polled first on every turn and answers to no share, aging or
    /// preemption. It is [`Priority::Main`], so give it the work everything else
    /// exists to protect.
    ///
    /// Give it this executor's [`timer`]s rather than tokio's, too. A tokio
    /// timer that falls due mid-turn waits for the turn to end; one of these
    /// ends the turn's batch and has `future` polled again at once. That is
    /// served best by a `future` that polls its timers whenever it is polled.
    /// One that sometimes does not, being busy awaiting something else, still
    /// gets its timer, from the wake that comes with it, one turn later.
    ///
    /// Every [`timer`] must be driven by one of these: while idle, it is this
    /// that sleeps until the earliest is due, and nothing else fires them.
    ///
    /// Being polled again that way, part way through a turn, is also a poll
    /// that nothing woke. A `future` must tolerate those — as futures should —
    /// and in particular must not treat one as the end of a yield: tokio's
    /// `yield_now` does, and completes before the reactor has had its turn.
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
        let mut alarm = Alarm::new();

        poll_fn(|cx| {
            // Before anything that might register a timer, so one registered
            // from here on is left to this turn to arm for.
            shared.turning.store(true, Ordering::SeqCst);
            // Recorded every turn so a wake from the reactor or another thread
            // brings the executor back, rather than leaving the queues to fill
            // while `block_on` sleeps.
            shared.set_waker(cx.waker());

            // Until it is pending, since that is the poll that registers the
            // waker. Another thread's driver may fire the deadline set below
            // before this polls it again, and a timer that has fired wakes
            // nothing: its waker was taken by the poll that saw it ready.
            while probe.as_mut().poll(cx).is_ready() {
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
            }

            // Timers that fell due between turns. Whatever they wake is queued
            // at its level, and the root is about to be polled regardless.
            shared.fire_due(Instant::now());
            // With a fresh budget, which polling the alarm spends a little of.
            if alarm.arm(shared, cx) {
                cx.waker().wake_by_ref();
            }

            // Tasks run this turn, and polls of the root after its first.
            let mut ran = 0usize;
            // Whether the turn ended because the cooperative budget ran out
            // rather than because there was nothing left to run.
            let mut spent = false;
            loop {
                let polled = {
                    let _root = PollingRoot::enter(shared);
                    future.as_mut().poll(cx)
                };
                if let Poll::Ready(output) = polled {
                    shared.run_turn_hooks();
                    shared.turning.store(false, Ordering::SeqCst);
                    return Poll::Ready(output);
                }
                // The root may have spent the budget, all of it or what the
                // tasks before it left, and a task must not be polled with none.
                if !tokio::task::coop::has_budget_remaining() {
                    spent = true;
                    break;
                }

                // One clock read per iteration rather than three, since the
                // instant ending one poll begins the next. Each task is
                // therefore charged for the `pick` that chose it as well as its
                // own run, which happens on its behalf and nobody else's.
                let mut now = Instant::now();
                // Whether one of the root's timers fell due part way through.
                let mut root_due = false;
                while ran < TASKS_PER_TICK {
                    let room = BATCH.min(TASKS_PER_TICK - ran);
                    let level = shared.pick_batch(now, &mut batch, room);
                    if batch.is_empty() {
                        break;
                    }

                    let mut rest = batch.drain(..);
                    while let Some((job, aged)) = rest.next() {
                        // Closed since the batch was picked, by another thread
                        // or by the task before this one: `close` could not
                        // sweep what this turn holds, so it is dropped here
                        // rather than run.
                        if shared.is_closed() {
                            shared.give_back(std::iter::once((job, aged)).chain(rest.by_ref()));
                            break;
                        }
                        // Outside the lock, since running a task may spawn, wake
                        // or re-enter the executor, all of which take it.
                        job.runnable.run();
                        let ended = Instant::now();
                        shared.charge(&job.state, (ended - now) + POLL_COST, aged);
                        now = ended;
                        ran += 1;

                        // The cooperative budget is spent, so end the turn here.
                        // See the note above the loop: a task polled past this
                        // point does no work and pays a full redispatch for it.
                        // First, since nothing below may run anything once it
                        // is spent, the root included; a timer due now is fired
                        // as the next turn starts, before the root is polled.
                        // The root spending it is caught where it is polled.
                        if !tokio::task::coop::has_budget_remaining() {
                            shared.give_back(rest.by_ref());
                            spent = true;
                            break;
                        }

                        // A timer due now, found with the clock already read.
                        // One the root awaits ends the batch outright: the root
                        // is in no queue, so nothing below would ever see it.
                        if shared.fire_due(now) {
                            shared.give_back(rest.by_ref());
                            root_due = true;
                            break;
                        }

                        // Preemption, checked without the lock: something better
                        // waking — a timer's task just now, included — must not
                        // wait behind the rest of the batch.
                        let bits = shared.ready.load(Ordering::Acquire);
                        if bits != 0 && (bits.trailing_zeros() as u8) < level {
                            shared.give_back(rest.by_ref());
                            break;
                        }
                    }
                    drop(rest);
                    if spent || root_due {
                        break;
                    }
                }

                // Never alongside `spent`, which is checked first.
                if root_due && ran < TASKS_PER_TICK {
                    // Straight back to the root, rather than waiting out the
                    // round trip through the reactor that its wake will also
                    // bring. Counted as a task, so a root timer falling due
                    // again and again cannot keep the reactor from its turn.
                    ran += 1;
                    continue;
                }
                // Out of room, so a root timer due above is served by the turn
                // its wake brings, which comes soon.
                break;
            }

            shared.run_turn_hooks();

            // Whatever this turn registered, armed for now: this turn is the
            // last chance to before sleeping. Cleared first, so a timer
            // registered from here on wakes the executor rather than being
            // missed by the arming below. Not when the budget is spent, since
            // polling the alarm would find none to spend, and the turn that
            // follows at once arms it.
            shared.turning.store(false, Ordering::SeqCst);
            if !spent && alarm.arm(shared, cx) {
                cx.waker().wake_by_ref();
            }

            // Ending on a spent budget is not the same as having nothing to do,
            // and the check below only wakes when a queue is occupied. A task
            // given back above leaves its level set, so that check does see it —
            // but a turn that spent the budget on its very last task would
            // otherwise sleep with a fresh budget and nothing to spend it on.
            if spent {
                cx.waker().wake_by_ref();
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

/// Decrements the live count and leaves [`Shared::live`] however its future
/// ends.
struct Alive {
    state: Arc<TaskState>,
    shared: Arc<Shared>,
}

impl Drop for Alive {
    fn drop(&mut self) {
        self.state.priority.census_leave();
        self.shared.discharge(&self.state);
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

/// Registered [`timer`]s.
#[derive(Default)]
struct Timers {
    /// Soonest first.
    entries: BTreeMap<TimerKey, TimerEntry>,
    /// Tells apart timers due at the same moment.
    next_id: u64,
}

/// The one tokio timer an executor keeps, armed for its earliest [`timer`].
///
/// What wakes an idle executor to fire them. A busy one fires them between
/// tasks without it; this is for when there are no tasks to be between. One
/// for them all rather than one each, so a timer costs the tokio driver nothing
/// and its polls spend none of tokio's cooperative budget.
struct Alarm {
    sleep: Pin<Box<tokio::time::Sleep>>,
    /// The offset `sleep` is armed for, or `u64::MAX` for none, including once
    /// it has fired, so the next arming resets it.
    armed: u64,
}

impl Alarm {
    fn new() -> Self {
        Self {
            // Never polled until armed, so never registered with the driver
            // at this deadline.
            sleep: Box::pin(tokio::time::sleep(Duration::from_secs(3600))),
            armed: u64::MAX,
        }
    }

    /// Arms for the earliest registered timer, and says whether it is due
    /// already, in which case the caller owes itself another turn.
    ///
    /// Left armed for a deadline no timer has any more, rather than disarmed,
    /// when the timers all go: firing then costs a turn, which is cheaper than
    /// a reset every time the list empties.
    fn arm(&mut self, shared: &Shared, cx: &mut Context<'_>) -> bool {
        let next = shared.next_timer_nanos.load(Ordering::SeqCst);
        if next == u64::MAX {
            self.armed = u64::MAX;
            return false;
        }
        if next != self.armed {
            let Some(at) = shared.instant_at(next) else {
                self.armed = u64::MAX;
                return false;
            };
            self.armed = next;
            self.sleep.as_mut().reset(at.into());
        }
        if self.sleep.as_mut().poll(cx).is_ready() {
            // A fired sleep wakes nothing more until it is reset.
            self.armed = u64::MAX;
            return true;
        }
        false
    }
}

/// Who a registered timer wakes.
struct TimerEntry {
    waker: Waker,
    /// Registered while the root future was being polled. The root is in no
    /// queue, so waking it does nothing preemption can see; the executor has to
    /// end the batch and poll it itself.
    root: bool,
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
    /// Saturating, so a timer due centuries from now stays in the future rather
    /// than wrapping round to one due already.
    #[inline(always)]
    fn now_nanos(&self, now: Instant) -> u64 {
        let nanos = now.saturating_duration_since(self.epoch_instant).as_nanos();
        u64::try_from(nanos).unwrap_or(u64::MAX)
    }

    /// Whether this thread is polling this executor's root future right now.
    pub(super) fn polling_root(&self) -> bool {
        std::ptr::eq(POLLING_ROOT.get(), self)
    }

    /// Registers a timer due at `deadline`, or updates the registration `key`
    /// names, and says where it now is: nowhere if the executor has closed.
    pub(super) fn register_timer(
        &self,
        key: Option<TimerKey>,
        deadline: Instant,
        waker: &Waker,
        root: bool,
    ) -> Option<TimerKey> {
        let nanos = self.now_nanos(deadline);
        // A waker this replaces, never read. Declared before the guard so it is
        // dropped after it, outside the lock: see `close`.
        let mut _replaced = None;
        let mut timers = self.timers.lock().unwrap();
        if let Some(key) = key {
            // A timer polled again before it is due, by a waker or from a place
            // it was not registered with: the same deadline, so the same key.
            if key.0 == nanos
                && let Some(entry) = timers.entries.get_mut(&key)
            {
                if !entry.waker.will_wake(waker) {
                    _replaced = Some(std::mem::replace(&mut entry.waker, waker.clone()));
                }
                entry.root = root;
                return Some(key);
            }
            // Fired already, or due at another time now.
            _replaced = timers.entries.remove(&key).map(|entry| entry.waker);
        }
        if self.is_closed() {
            self.store_next_timer(&timers);
            return None;
        }
        let key = (nanos, timers.next_id);
        timers.next_id = timers.next_id.wrapping_add(1);
        timers.entries.insert(
            key,
            TimerEntry {
                waker: waker.clone(),
                root,
            },
        );
        let earliest = self.store_next_timer(&timers) == nanos;
        drop(timers);
        // Registered as the earliest while no turn is running, so the alarm is
        // armed for something later, if anything: have a turn re-arm it. Within
        // a turn, the turn re-arms on its own before it ends. See
        // `next_timer_nanos` for why these two are sequentially consistent.
        if earliest && !self.turning.load(Ordering::SeqCst) {
            self.wake_executor();
        }
        Some(key)
    }

    /// Runs every live [`TurnHook`], forgetting the dropped ones.
    fn run_turn_hooks(&self) {
        if !self.has_turn_hooks.load(Ordering::Acquire) {
            return;
        }
        let mut hooks = self.turn_hooks.lock().unwrap();
        hooks.retain(|hook| match hook.upgrade() {
            Some(hook) => {
                hook.turn_ended();
                true
            }
            None => false,
        });
        if hooks.is_empty() {
            self.has_turn_hooks.store(false, Ordering::Release);
        }
    }

    /// Brings `run_until` round for another turn, if it is waiting for one.
    fn wake_executor(&self) {
        let waker = self.inner.lock().unwrap().waker.take();
        // Outside the lock: waking may run arbitrary code.
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    /// When the timer offset `nanos` falls due, or [`None`] if that is past
    /// what an [`Instant`] can say, which is as good as never.
    fn instant_at(&self, nanos: u64) -> Option<Instant> {
        self.epoch_instant.checked_add(Duration::from_nanos(nanos))
    }

    /// Forgets a registration, which may already have fired.
    pub(super) fn deregister_timer(&self, key: TimerKey) {
        let removed = {
            let mut timers = self.timers.lock().unwrap();
            let removed = timers.entries.remove(&key);
            if removed.is_some() {
                self.store_next_timer(&timers);
            }
            removed
        };
        // Outside the lock: see `close`.
        drop(removed);
    }

    /// Publishes when the earliest timer is due, and says.
    fn store_next_timer(&self, timers: &Timers) -> u64 {
        let next = timers
            .entries
            .first_key_value()
            .map_or(u64::MAX, |(&(nanos, _), _)| nanos);
        self.next_timer_nanos.store(next, Ordering::SeqCst);
        next
    }

    /// Whether this has closed, which a [`Mode::Permanent`] one never does.
    fn is_closed(&self) -> bool {
        match &self.mode {
            Mode::Permanent => false,
            Mode::Ephemeral { closed, .. } => closed.load(Ordering::Acquire),
        }
    }

    /// Records a new task among the live, unless the executor has closed, in
    /// which case scheduling it is what drops it, or never can.
    fn enlist(&self, state: &Arc<TaskState>, runnable: &Runnable) {
        let Mode::Ephemeral { live, closed, .. } = &self.mode else {
            return;
        };
        let mut live = live.lock().unwrap();
        if !closed.load(Ordering::Acquire) {
            live.insert(Arc::as_ptr(state) as usize, runnable.waker());
        }
    }

    /// Forgets a task whose future has ended.
    fn discharge(&self, state: &Arc<TaskState>) {
        let Mode::Ephemeral { live, .. } = &self.mode else {
            return;
        };
        let waker = live.lock().unwrap().remove(&(Arc::as_ptr(state) as usize));
        // Outside the lock: see `close`.
        drop(waker);
    }

    /// Drops every task, and has every task spawned or woken from now on
    /// dropped too, since nothing will run them.
    ///
    /// Dropping a task drops its future, which is what frees whatever it held.
    /// One queued or parked is dropped here; one in a running turn's batch is
    /// dropped by that turn instead of run, or when it is given back; any other
    /// is woken so it is scheduled, which drops it, and a wake landing on it
    /// later finds it gone rather than dropping it inside whoever woke it.
    fn close(&self) {
        let Mode::Ephemeral { live, closed, .. } = &self.mode else {
            // It keeps no record of the tasks this would have to reach.
            debug_assert!(false, "closed an executor that cannot close");
            return;
        };
        closed.store(true, Ordering::Release);
        let (queues, parked) = {
            let mut inner = self.inner.lock().unwrap();
            self.ready.store(0, Ordering::Release);
            (
                std::mem::replace(&mut inner.queues, std::array::from_fn(|_| VecDeque::new())),
                std::mem::take(&mut inner.parked),
            )
        };
        let timers = {
            let mut timers = self.timers.lock().unwrap();
            self.next_timer_nanos.store(u64::MAX, Ordering::Release);
            std::mem::take(&mut timers.entries)
        };
        let live = std::mem::take(&mut *live.lock().unwrap());
        // Outside the locks: a future dropped here may deregister a timer or
        // wake a task, both of which take one. Dropping a timer's waker may
        // too, since a task whose last waker goes is woken to be dropped.
        drop(queues);
        drop(parked);
        drop(timers);
        for waker in live.into_values() {
            waker.wake();
        }
    }

    /// Wakes every timer due by `now`, and says whether one was the root's.
    ///
    /// The root's are woken too, although the caller polls the root again
    /// anyway when one is due. That poll reaches the timer only if the root
    /// polls it whenever it is polled; one busy awaiting something else first
    /// does not, and a timer fired is gone from the list, so nothing else would
    /// ever wake the root for it. The wake costs at most a turn more once this
    /// one ends.
    ///
    /// One atomic load when nothing is due, which is almost always, so it is
    /// cheap enough to ask after every task.
    ///
    /// One timer per acquisition of the lock, rather than gathering them all
    /// under one: gathering needs somewhere to put them, and this runs between
    /// every two tasks, where allocating is not wanted. Rarely more than one is
    /// due at a time, so the extra acquisitions are rarely taken.
    fn fire_due(&self, now: Instant) -> bool {
        let now_nanos = self.now_nanos(now);
        let mut root = false;
        while now_nanos >= self.next_timer_nanos.load(Ordering::SeqCst) {
            let due = {
                let mut timers = self.timers.lock().unwrap();
                let due = match timers.entries.first_entry() {
                    Some(first) if first.key().0 <= now_nanos => Some(first.remove()),
                    // Changed since the load above: deregistered, or replaced by
                    // one due later.
                    _ => None,
                };
                self.store_next_timer(&timers);
                due
            };
            let Some(entry) = due else {
                break;
            };
            // Outside the lock: waking may run arbitrary code, a timer of its
            // own included.
            root |= entry.root;
            entry.waker.wake();
        }
        root
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
            if shared.is_closed() {
                drop(inner);
                // Nothing will run it. Dropped outside the lock, since that
                // drops its future, which may wake another task.
                drop(job);
                return;
            }
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
    /// now belong to, or drops them if the executor has closed since.
    fn give_back(&self, jobs: impl Iterator<Item = (Job, bool)>) {
        let mut inner = self.inner.lock().unwrap();
        // Under the lock `close` sweeps under, so a job given back is either
        // swept or dropped here, never left queued on a closed executor.
        if self.is_closed() {
            drop(inner);
            // Nothing will run them. Dropped outside the lock, since that drops
            // their futures, which may wake another task.
            jobs.for_each(drop);
            return;
        }
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
            let level = self
                .aged_choice(inner, bits, best, now, config)
                .unwrap_or(best);
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
    /// Whether a worse level has waited long enough to be served before `best`.
    ///
    /// `bits` is the occupancy bitmap the caller already read, and doing the
    /// whole search against it rather than against the queues is what keeps
    /// this off the dispatch path's critical cost. Empty levels are never
    /// looked at, and "how many occupied levels sit between these two" is a
    /// mask and a popcount rather than a scan.
    fn aged_choice(
        &self,
        inner: &Inner,
        bits: u32,
        best: usize,
        now: Instant,
        config: &Config,
    ) -> Option<usize> {
        // Everything worse than `best`. Nothing there means nothing to promote,
        // which is the common case: one level occupied, or the best one is the
        // only one with work.
        let mut worse = bits & !((1u32 << (best + 1)) - 1);
        if worse == 0 {
            return None;
        }
        if inner.override_spent >= config.window.mul_f32(config.override_budget) {
            return None;
        }
        let base = config.aging_base.as_nanos().max(1) as u64;
        let now_nanos = self.now_nanos(now);

        let mut choice = None;
        let mut choice_slack = 0u32;
        while worse != 0 {
            let level = worse.trailing_zeros() as usize;
            worse &= worse - 1;
            let Some(head) = inner.queues[level].front() else {
                debug_assert!(false, "bitmap claimed level {level} was occupied");
                continue;
            };
            let waited =
                now_nanos.saturating_sub(head.state.enqueued_nanos.load(Ordering::Relaxed));
            if waited < base {
                continue;
            }
            let promotions = (waited / base).ilog2() + 1;
            // The occupied levels in `best..level`, straight off the bitmap.
            let between = ((1u32 << level) - 1) & !((1u32 << best) - 1);
            let occupied_above = (bits & between).count_ones();
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
        // An instance of its own, for the probe to sample; these exercise the
        // schedule, not the ledgers, and must not touch the shared one.
        let gk = crate::OwnedGoalkeeper::new();
        runtime.block_on(driven.run_until(&gk, body(executor)))
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
        assert_eq!(out, Some(7));
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
                sum += ex.spawn(p, async { 1u32 }).await.unwrap();
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
            observed,
            Some(0),
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
        let gk = crate::OwnedGoalkeeper::new();
        runtime.block_on(driven.run_until(&gk, async move {
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
        let gk = crate::OwnedGoalkeeper::new();
        runtime.block_on(driven.run_until(&gk, async move {
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
        let gk = crate::OwnedGoalkeeper::new();
        runtime.block_on(driven.run_until(&gk, async move {
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
        assert_eq!(out, Some(9));
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
        let gk = crate::OwnedGoalkeeper::new();
        let out = runtime.block_on(driven.run_until(&gk, async move {
            let priority = SharedPriority::new(Priority::Accept);
            let moved = priority.clone();
            let task = ex.spawn_with(priority, async { 5u32 });
            // Re-level it while it sits in the `Accept` queue.
            moved.set_base(Priority::User(L0));
            let first = task.await.unwrap();
            // Everything must still schedule afterwards.
            let second = ex.spawn(Priority::Accept, async { 6u32 }).await.unwrap();
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
        let gk = crate::OwnedGoalkeeper::new();
        runtime.block_on(driven.run_until(&gk, async move {
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

    /// A task is never polled with nothing left to spend.
    ///
    /// The turn's tasks share one cooperative budget — it is installed by the
    /// caller's `block_on`, once per poll of `run_until` — so a turn long enough
    /// to spend it used to go on polling anyway, and everything after that point
    /// returned `Pending` without doing a thing. Each such poll costs a full
    /// redispatch, so the waste rises with load and vanishes when idle, which is
    /// exactly the shape that is hard to see in a profile.
    ///
    /// Asserted from inside the tasks: each records whether it *had* budget when
    /// it was polled. Each then spends several units, as a real task does — a
    /// `select!` over a socket, a timer and two channels is four on its own — so
    /// a turn's worth of them is several budgets over, which is the condition
    /// being tested. One consuming a single unit would not reach it: sixty-one
    /// of those fit inside the hundred and twenty-eight tokio grants.
    #[test]
    fn a_task_is_not_polled_without_budget_to_spend() {
        /// Budget-consuming operations per poll.
        const OPS: usize = 8;
        const TASKS: usize = 300;
        let broke = Arc::new(AtomicUsize::new(0));
        let ran = Arc::new(AtomicUsize::new(0));
        drive(Config::default(), {
            let broke = Arc::clone(&broke);
            let ran = Arc::clone(&ran);
            |ex| async move {
                let mut tasks = Vec::new();
                for _ in 0..TASKS {
                    let broke = Arc::clone(&broke);
                    let ran = Arc::clone(&ran);
                    // A channel with everything already in it: a receive is a
                    // budget-consuming operation that completes at once, so each
                    // poll spends `OPS` of the turn's budget without this task
                    // ever waiting on anything.
                    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
                    for _ in 0..OPS {
                        tx.send(()).unwrap();
                    }
                    tasks.push(ex.spawn(Priority::User(L0), async move {
                        // Read at the top of every poll, and this future is
                        // polled more than once — the budget may run out
                        // part-way through, which re-queues it right here.
                        if !tokio::task::coop::has_budget_remaining() {
                            broke.fetch_add(1, Ordering::Relaxed);
                        }
                        for _ in 0..OPS {
                            let _ = rx.recv().await;
                        }
                        ran.fetch_add(1, Ordering::Relaxed);
                    }));
                }
                for task in tasks {
                    task.await;
                }
            }
        });
        assert_eq!(
            ran.load(Ordering::Relaxed),
            TASKS,
            "every task should have finished"
        );
        assert_eq!(
            broke.load(Ordering::Relaxed),
            0,
            "a task was polled with the cooperative budget already spent"
        );
    }

    /// Pending once, then ready again within the same turn. Unlike tokio's
    /// `yield_now`, which holds the wake until the reactor has had its turn, so
    /// a task yielding this way keeps the turn it is in busy.
    async fn yield_within_turn() {
        let mut yielded = false;
        poll_fn(|cx| {
            if yielded {
                Poll::Ready(())
            } else {
                yielded = true;
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        })
        .await
    }

    /// Spawns `count` tasks at `priority`, each spending a millisecond of CPU
    /// per poll and ready again straight after, until `stop` is set. Enough of
    /// them make a single turn tens of milliseconds long.
    fn spawn_busy(ex: &Executor, priority: Priority, count: usize, stop: &Arc<AtomicBool>) {
        for _ in 0..count {
            let stop = Arc::clone(stop);
            ex.spawn(priority, async move {
                while !stop.load(Ordering::Relaxed) {
                    let until = Instant::now() + Duration::from_millis(1);
                    while Instant::now() < until {}
                    yield_within_turn().await;
                }
            })
            .detach();
        }
    }

    #[test]
    fn a_root_timer_fires_part_way_through_a_turn() {
        // A tokio timer here would wait for the turn to end: up to
        // `TASKS_PER_TICK` milliseconds of busy tasks.
        let late = drive(Config::default(), |ex| async move {
            let stop = Arc::new(AtomicBool::new(false));
            spawn_busy(&ex, Priority::User(L0), 8, &stop);
            let deadline = Instant::now() + Duration::from_millis(20);
            ex.sleep_until(deadline).await;
            let late = Instant::now().saturating_duration_since(deadline);
            stop.store(true, Ordering::Relaxed);
            late
        });
        assert!(
            late < Duration::from_millis(5),
            "the root waited out the turn: {late:?} late"
        );
    }

    #[test]
    fn a_root_timer_is_served_again_and_again_within_one_turn() {
        let (first, last) = drive(Config::default(), |ex| async move {
            let stop = Arc::new(AtomicBool::new(false));
            spawn_busy(&ex, Priority::User(L0), 8, &stop);
            // Counts the caller's runtime getting control back, which it only
            // does between turns.
            let turns = Arc::new(AtomicU64::new(0));
            let counter = tokio::spawn({
                let turns = Arc::clone(&turns);
                async move {
                    loop {
                        turns.fetch_add(1, Ordering::Relaxed);
                        tokio::task::yield_now().await;
                    }
                }
            });
            // Three ticks well inside one turn of busy tasks.
            let period = Duration::from_millis(5);
            let mut interval = ex.interval_at(Instant::now() + period, period, period);
            interval.tick().await;
            let first = turns.load(Ordering::Relaxed);
            interval.tick().await;
            interval.tick().await;
            let last = turns.load(Ordering::Relaxed);
            stop.store(true, Ordering::Relaxed);
            counter.abort();
            (first, last)
        });
        assert_eq!(first, last, "the turn ended to serve the root");
    }

    #[test]
    fn a_task_timer_preempts_a_worse_batch() {
        let late = drive(Config::default(), |ex| async move {
            let stop = Arc::new(AtomicBool::new(false));
            spawn_busy(&ex, Priority::Accept, 8, &stop);
            let timer = ex.clone();
            let late = ex
                .spawn(Priority::User(L0), async move {
                    let deadline = Instant::now() + Duration::from_millis(20);
                    timer.sleep_until(deadline).await;
                    Instant::now().saturating_duration_since(deadline)
                })
                .await
                .unwrap();
            stop.store(true, Ordering::Relaxed);
            late
        });
        assert!(
            late < Duration::from_millis(5),
            "the task waited out the batch: {late:?} late"
        );
    }

    #[test]
    fn a_late_interval_delays_rather_than_bursting() {
        let gap = drive(brisk(), |ex| async move {
            let mut interval = ex.interval_at(
                Instant::now(),
                Duration::from_millis(10),
                Duration::from_millis(1),
            );
            interval.tick().await;
            // Three and a half periods late for the next tick.
            std::thread::sleep(Duration::from_millis(35));
            interval.tick().await;
            let after_late = Instant::now();
            interval.tick().await;
            after_late.elapsed()
        });
        assert!(
            gap >= Duration::from_millis(9),
            "caught up in a burst: the tick after a late one came {gap:?} later"
        );
    }

    #[test]
    fn a_timer_polled_on_another_thread_is_not_the_roots() {
        use std::pin::Pin;
        use std::task::Context;

        let roots = drive(Config::default(), |ex| async move {
            let far = Instant::now() + Duration::from_secs(3600);
            let mut here = ex.sleep_until(far);
            let mut there = ex.sleep_until(far);
            let _ = Pin::new(&mut here).poll(&mut Context::from_waker(Waker::noop()));
            // While this thread is polling the root, but on another.
            std::thread::scope(|scope| {
                scope.spawn(|| {
                    let _ = Pin::new(&mut there).poll(&mut Context::from_waker(Waker::noop()));
                });
            });
            let timers = ex.0.timers.lock().unwrap();
            timers
                .entries
                .values()
                .map(|entry| entry.root)
                .collect::<Vec<_>>()
        });
        assert_eq!(roots, [true, false], "registered in that order");
    }

    #[test]
    fn a_timer_centuries_away_is_not_due_now() {
        use std::pin::Pin;
        use std::task::Context;

        let registered = drive(Config::default(), |ex| async move {
            // One nanosecond past what fits in a `u64`, which wrapped would be
            // the epoch itself, and long due.
            let far = ex.0.epoch_instant + Duration::from_nanos(u64::MAX) + Duration::from_nanos(1);
            let mut sleep = ex.sleep_until(far);
            let _ = Pin::new(&mut sleep).poll(&mut Context::from_waker(Waker::noop()));
            ex.0.fire_due(Instant::now());
            ex.0.timers.lock().unwrap().entries.len()
        });
        assert_eq!(registered, 1, "fired centuries early");
    }

    /// Sets its flag when dropped.
    struct SetOnDrop(Arc<AtomicBool>);

    impl Drop for SetOnDrop {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Relaxed);
        }
    }

    /// Leaves a task waiting an hour on what `wait` makes when the root
    /// completes, and says whether it was dropped with the executor.
    ///
    /// Read while the runtime is still up, since its shutting down wakes
    /// whatever waits on it, which would drop the task regardless.
    fn dropped_with_the_executor<W>(wait: impl FnOnce(&Executor, Instant) -> W) -> bool
    where
        W: Future<Output = ()> + Send + 'static,
    {
        let dropped = Arc::new(AtomicBool::new(false));
        let guard = SetOnDrop(Arc::clone(&dropped));
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let executor = Executor::new(Config::default());
        let gk = crate::OwnedGoalkeeper::new();
        runtime.block_on(executor.run_until(&gk, async {
            let wait = wait(&executor, Instant::now() + Duration::from_secs(3600));
            executor
                .spawn(Priority::User(L0), async move {
                    let _guard = guard;
                    wait.await;
                })
                .detach();
            // Long enough for the task to start waiting.
            for _ in 0..4 {
                tokio::task::yield_now().await;
            }
        }));
        drop(executor);
        let dropped = dropped.load(Ordering::Relaxed);
        drop(runtime);
        dropped
    }

    #[test]
    fn a_task_left_waiting_on_a_timer_is_dropped_with_the_executor() {
        assert!(
            dropped_with_the_executor(|ex, deadline| ex.sleep_until(deadline)),
            "the timer kept the task waiting"
        );
    }

    #[test]
    fn a_task_left_waiting_on_tokio_is_dropped_with_the_executor() {
        assert!(
            dropped_with_the_executor(|_, deadline| tokio::time::sleep_until(deadline.into())),
            "closing never reached a task only tokio could wake"
        );
    }

    /// A task holding a handle to its own instance, as a connection's task
    /// holds its permit, is dropped with the owner rather than keeping the
    /// instance, and so itself, alive.
    #[test]
    fn a_task_holding_a_handle_is_dropped_with_the_owner() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let owner = crate::OwnedGoalkeeper::new();
        let instance = Arc::downgrade(&owner.handle().0);
        let waiting = Arc::new(AtomicBool::new(false));
        let queued = Arc::new(AtomicBool::new(false));
        runtime.block_on(owner.run_until(async {
            // Waits where no queue of the executor's can see it, as one parked
            // on the instance's own ledger or heartbeat does.
            let gk = owner.handle();
            let guard = SetOnDrop(Arc::clone(&waiting));
            owner
                .spawn(Priority::User(L0), async move {
                    let _held = (gk, guard);
                    tokio::time::sleep(Duration::from_secs(3600)).await;
                })
                .detach();
            for _ in 0..4 {
                tokio::task::yield_now().await;
            }
            // Never run, since the root completes first.
            let gk = owner.handle();
            let guard = SetOnDrop(Arc::clone(&queued));
            owner
                .spawn(Priority::User(L0), async move {
                    let _held = (gk, guard);
                })
                .detach();
        }));
        drop(owner);
        // Before the runtime goes, since its shutting down would wake them.
        assert!(
            waiting.load(Ordering::Relaxed),
            "a task waiting on its instance kept it"
        );
        assert!(
            queued.load(Ordering::Relaxed),
            "a queued task kept its instance"
        );
        assert!(
            instance.upgrade().is_none(),
            "the instance outlived its owner"
        );
        drop(runtime);
    }

    /// A task spawned once the owner is gone is dropped unrun, and awaiting it
    /// says so rather than panicking.
    #[test]
    fn a_task_on_a_closed_executor_completes_with_none() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let owner = crate::OwnedGoalkeeper::new();
        let gk = owner.handle();
        drop(owner);
        let out = runtime.block_on(gk.run_until(gk.spawn(Priority::User(L0), async { 1u32 })));
        assert_eq!(out, None);
    }

    /// The root, polled again for a timer of its own part way through a turn,
    /// spending what the turn had left, is not followed by a task polled with
    /// none. See [`a_task_is_not_polled_without_budget_to_spend`].
    #[test]
    fn a_task_is_not_polled_after_the_root_spends_the_budget() {
        let broke = Arc::new(AtomicUsize::new(0));
        let polled = Arc::new(AtomicUsize::new(0));
        drive(Config::default(), {
            let broke = Arc::clone(&broke);
            let polled = Arc::clone(&polled);
            |ex| async move {
                let stop = Arc::new(AtomicBool::new(false));
                for _ in 0..8 {
                    let stop = Arc::clone(&stop);
                    let broke = Arc::clone(&broke);
                    let polled = Arc::clone(&polled);
                    ex.spawn(Priority::User(L0), async move {
                        while !stop.load(Ordering::Relaxed) {
                            if !tokio::task::coop::has_budget_remaining() {
                                broke.fetch_add(1, Ordering::Relaxed);
                            }
                            polled.fetch_add(1, Ordering::Relaxed);
                            let until = Instant::now() + Duration::from_millis(1);
                            while Instant::now() < until {}
                            yield_within_turn().await;
                        }
                    })
                    .detach();
                }
                for _ in 0..5 {
                    ex.sleep_until(Instant::now() + Duration::from_millis(3))
                        .await;
                    while tokio::task::coop::has_budget_remaining() {
                        tokio::task::coop::consume_budget().await;
                    }
                }
                stop.store(true, Ordering::Relaxed);
            }
        });
        assert!(
            polled.load(Ordering::Relaxed) > 0,
            "the tasks never ran, so this proves nothing"
        );
        assert_eq!(
            broke.load(Ordering::Relaxed),
            0,
            "a task was polled with the cooperative budget already spent"
        );
    }
}
