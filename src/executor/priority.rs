//! Where a task sits in the schedule.
//!
//! [`Priority`] is the level; [`SharedPriority`] is a handle carrying one that
//! can be moved while the task lives.
//!
//! The ends of the ladder belong to goalkeeper, which assigns
//! [`Priority::New`] to a freshly accepted connection and [`Priority::Accept`]
//! to an accept loop. A caller names [`Priority::Main`] once, for the root task
//! everything else exists to protect, and [`Priority::User`] in between.
//!
//! A task that serves other tasks, such as a QUIC endpoint driver, has no
//! variant of its own and should inherit with [`SharedPriority::depend_on`]:
//! its correct priority is the best of whatever depends on it.

use crate::executor::Census;
use std::sync::atomic::{AtomicU8, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// Where a task sits in the schedule. Lower is more urgent.
///
/// Ordered by declaration, so `Main < User(_) < New < Accept` and `User(L0) <
/// User(L1)`, which is exactly the schedule order.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Priority {
    /// The caller's root task, typically a game's tick, that every other
    /// priority exists to keep out of the way of.
    Main,
    /// The caller's own ladder.
    User(UserPriority),
    /// A connection that has been accepted and nothing more is known about.
    ///
    /// Assigned by goalkeeper; raise it with [`SharedPriority::set_base`] as
    /// the connection establishes itself.
    New,
    /// An accept loop.
    ///
    /// Assigned by goalkeeper, and always last: a connection not yet accepted
    /// has cost nothing.
    Accept,
}

/// The caller's own levels. Bounded so the ends of [`Priority`] stay reserved
/// without a runtime check.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
#[allow(missing_docs, reason = "ten ordinals; the names carry no meaning")]
pub enum UserPriority {
    L0 = 0,
    L1,
    L2,
    L3,
    L4,
    L5,
    L6,
    L7,
    L8,
    L9,
}

/// The dense index a [`Priority`] occupies is crate-internal bookkeeping: the
/// width of the executor's occupancy bitmap, the length of its array of queues,
/// the offsets a bandwidth ledger is kept in.
///
/// It stays internal because an index admits arithmetic, comparison against the
/// wrong ladder, and values naming no level at all. Reports that need a
/// breakdown per level are handed `(Priority, _)` pairs instead; see
/// [`crate::executor::Tasks::queued_by_priority`].
impl Priority {
    /// How many distinct levels exist: [`Self::Main`], the user's own, then
    /// [`Self::New`] and [`Self::Accept`].
    ///
    /// Derived, so adding a [`UserPriority`] needs no edit here.
    pub(crate) const LEVELS: usize = 1 + UserPriority::COUNT + 2;

    /// The level [`Self::New`] occupies: one past the last user level.
    const NEW: u8 = 1 + UserPriority::COUNT as u8;

    /// The dense index used by the executor's queues and bitmap.
    ///
    /// A jump table over a handful of variants, on the path taken for every
    /// enqueue and every dispatch.
    #[inline(always)]
    pub(crate) const fn level(self) -> u8 {
        match self {
            Self::Main => 0,
            Self::User(u) => 1 + u as u8,
            Self::New => Self::NEW,
            Self::Accept => Self::NEW + 1,
        }
    }

    /// Inverse of [`Self::level`]. Saturates rather than panicking, since it is
    /// only reached from diagnostics.
    #[inline(always)]
    pub(crate) const fn from_level(level: u8) -> Self {
        // Not a `match`: a pattern cannot be written in terms of a constant
        // range, and the user range's end moves with `UserPriority::COUNT`.
        if level == 0 {
            Self::Main
        } else if level < Self::NEW {
            Self::User(UserPriority::from_index(level - 1))
        } else if level == Self::NEW {
            Self::New
        } else {
            Self::Accept
        }
    }
}

const _: () = assert!(
    Priority::LEVELS <= u32::BITS as usize,
    "the executor's occupancy bitmap is a u32"
);

impl UserPriority {
    /// The worst of them.
    ///
    /// Indexing saturates, so one past the end names the last variant without
    /// naming it.
    pub const WORST: Self = Self::from_index(u8::MAX);

    /// How many there are.
    ///
    /// The enum is `#[repr(u8)]` and contiguous from zero, so the last
    /// discriminant plus one is the count. `std::mem::variant_count` would say
    /// it directly, but is nightly-only.
    pub(crate) const COUNT: usize = Self::WORST as usize + 1;

    const fn from_index(index: u8) -> Self {
        // A table rather than `transmute`, since this crate forbids unsafe.
        match index {
            0 => Self::L0,
            1 => Self::L1,
            2 => Self::L2,
            3 => Self::L3,
            4 => Self::L4,
            5 => Self::L5,
            6 => Self::L6,
            7 => Self::L7,
            8 => Self::L8,
            _ => Self::L9,
        }
    }
}

/// A priority that can be read cheaply and changed while its task lives.
///
/// Cloning shares the level: a connection's task, the tasks hyper spawns for
/// it, and the socket task it turns into all hold the same handle, so
/// re-levelling any of them re-levels the connection.
///
/// Reads are one relaxed load. [`Self::set_base`], [`Self::boost`] and
/// [`Self::depend_on`] happen on state transitions, never on the path a poll
/// takes.
#[derive(Clone, Debug)]
pub struct SharedPriority(Arc<Inner>);

/// What the executor's shares are reckoned against.
///
/// Held per handle rather than per task, because a connection is what deserves
/// a share and a connection is not one task: hyper spawns a task per HTTP/2
/// stream, all sharing this handle. Pooling here makes the allowance a property
/// of the peer rather than of its choice of protocol, and means opening more
/// tasks cannot buy more share.
#[derive(Debug, Default)]
pub(crate) struct Accounting {
    /// Which window [`Self::spent_nanos`] belongs to. Rolled lazily, so a
    /// connection idle for a hundred windows costs nothing to keep current.
    pub(crate) window: AtomicU64,
    pub(crate) spent_nanos: AtomicU64,
    /// Consecutive windows whose share this connection exhausted.
    pub(crate) exhaustions: AtomicU32,
}

#[derive(Debug)]
struct Inner {
    /// What this task is, absent anything depending on it.
    base: AtomicU8,
    /// Shared by every task holding this handle. See [`Accounting`].
    accounting: Accounting,
    /// `base` reconciled with every outstanding boost. The only field read on
    /// the hot path.
    effective: AtomicU8,
    /// Outstanding [`Boost`]s as `(level, count)`, kept small and unsorted
    /// because a connection has a handful at most.
    boosts: Mutex<Vec<(u8, u32)>>,
    /// Priorities this one boosts, so a change here propagates to them. See
    /// [`SharedPriority::depend_on`].
    links: Mutex<Vec<Link>>,
    /// This handle's live tasks and where the executor has them counted.
    ///
    /// Behind the same lock as the level move it accompanies, so the count and
    /// [`Self::effective`] cannot disagree about where these tasks are.
    census: Mutex<CensusState>,
}

/// One handle's contribution to [`Census`].
#[derive(Debug, Default)]
struct CensusState {
    /// The executor's counters, learned when the first task is spawned against
    /// this handle. [`None`] for a handle nothing has been spawned against,
    /// which is every handle a caller builds and never uses.
    census: Option<Arc<Census>>,
    /// Live tasks holding this handle.
    tasks: usize,
    /// The level those tasks are counted at, which trails
    /// [`Inner::effective`] only within a critical section.
    level: u8,
}

/// A live edge from a dependent to what it depends on.
#[derive(Debug)]
struct Link {
    /// What is being boosted.
    target: SharedPriority,
    /// The level currently contributed to it, so it can be withdrawn when this
    /// side changes.
    contributed: u8,
}

impl SharedPriority {
    /// A handle starting at `base`.
    pub fn new(base: Priority) -> Self {
        let level = base.level();
        Self(Arc::new(Inner {
            base: AtomicU8::new(level),
            accounting: Accounting::default(),
            effective: AtomicU8::new(level),
            boosts: Mutex::new(Vec::new()),
            links: Mutex::new(Vec::new()),
            census: Mutex::new(CensusState {
                census: None,
                tasks: 0,
                level,
            }),
        }))
    }

    /// Counts one more task against this handle, in `census`.
    ///
    /// Idempotent about which census: the first spawn adopts one and later
    /// spawns join it, so a handle shared across two executors counts in the
    /// one that saw it first rather than in both.
    pub(crate) fn census_join(&self, census: &Arc<Census>) {
        let mut state = self.0.census.lock().unwrap();
        // Read under the lock, so a level moving concurrently either counts
        // this task at the old level and then moves it, or at the new one.
        let level = self.0.effective.load(Ordering::Relaxed);
        let (counted_at, tasks) = (state.level, state.tasks);
        let census = state.census.get_or_insert_with(|| Arc::clone(census));
        // A no-op while every level change goes through `reconcile`, which
        // keeps the two in step. Here so that this is right on its own terms
        // rather than by appeal to that.
        census.shift(counted_at, level, tasks);
        census.join(level);
        state.level = level;
        state.tasks += 1;
    }

    /// Counts one fewer, at wherever this handle currently has them.
    pub(crate) fn census_leave(&self) {
        let mut state = self.0.census.lock().unwrap();
        if let Some(census) = &state.census {
            census.leave(state.level);
        }
        state.tasks -= 1;
    }

    /// The level right now, accounting for boosts. One relaxed load.
    #[inline]
    pub fn effective(&self) -> Priority {
        Priority::from_level(self.level())
    }

    /// The share accounting shared by every task holding this handle.
    #[inline(always)]
    pub(crate) fn accounting(&self) -> &Accounting {
        &self.0.accounting
    }

    /// The level right now, as the executor's dense index.
    ///
    /// Crate-internal; callers want [`Self::effective`]. One load, read for
    /// every enqueue and every dispatch.
    #[inline(always)]
    pub(crate) fn level(&self) -> u8 {
        self.0.effective.load(Ordering::Relaxed)
    }

    /// Changes what this task is, absent anything depending on it.
    ///
    /// An application's own ladder is driven from here, as a socket moves
    /// between "alive", "dead" and "inactive" with its player, which is what
    /// [`Priority::User`] is for.
    ///
    /// Takes effect at the task's next enqueue; a task already queued keeps the
    /// level it was queued at for one dispatch.
    pub fn set_base(&self, base: Priority) {
        let changed = {
            let boosts = self.0.boosts.lock().unwrap();
            // Stored under the boosts lock, which is what makes this and the
            // reconcile that reads it one step. Written nowhere else.
            self.0.base.store(base.level(), Ordering::Relaxed);
            self.reconcile(&boosts)
        };
        self.propagate_if_changed(changed);
    }

    /// Holds this task at at least `level` until the returned guard is dropped.
    ///
    /// Boosts compose: a connection carrying several sockets stays at the best
    /// of them until the last is gone.
    #[must_use = "dropping the guard immediately gives the level back"]
    pub fn boost(&self, level: Priority) -> Boost {
        self.add_boost(level.level());
        Boost {
            priority: self.clone(),
            level: level.level(),
        }
    }

    /// Makes `dependency` inherit this task's level for as long as the returned
    /// guard lives.
    ///
    /// A task that serves others, such as a QUIC endpoint driver, has no
    /// correct fixed level: it must rank with the best of whatever it serves,
    /// or everything behind it stalls.
    ///
    /// The edge is live. When this side's effective level changes, the
    /// contribution to `dependency` is withdrawn and re-made at the new level.
    ///
    /// One level deep in practice; a cycle would recurse.
    #[must_use = "dropping the guard removes the inheritance"]
    pub fn depend_on(&self, dependency: &SharedPriority) -> Dependency {
        let level = self.level();
        dependency.add_boost(level);
        self.0.links.lock().unwrap().push(Link {
            target: dependency.clone(),
            contributed: level,
        });
        Dependency {
            dependent: self.clone(),
            dependency: dependency.clone(),
        }
    }

    fn add_boost(&self, level: u8) {
        let changed = {
            let mut boosts = self.0.boosts.lock().unwrap();
            match boosts.iter_mut().find(|(l, _)| *l == level) {
                Some((_, count)) => *count += 1,
                None => boosts.push((level, 1)),
            }
            self.reconcile(&boosts)
        };
        self.propagate_if_changed(changed);
    }

    fn remove_boost(&self, level: u8) {
        let changed = {
            let mut boosts = self.0.boosts.lock().unwrap();
            if let Some(index) = boosts.iter().position(|(l, _)| *l == level) {
                boosts[index].1 -= 1;
                if boosts[index].1 == 0 {
                    boosts.swap_remove(index);
                }
            } else {
                debug_assert!(false, "removed a boost that was never added");
            }
            self.reconcile(&boosts)
        };
        self.propagate_if_changed(changed);
    }

    /// Reconciles `effective` with `base` and `boosts`, returning the new level
    /// if it moved.
    ///
    /// Takes the boosts as proof they are held: what this reads and what it
    /// writes have to be one step. Computing the level from a released snapshot
    /// lets a second writer land between the two, and whichever wrote last
    /// leaves `effective` describing neither — a connection stuck at its base
    /// with a live [`Boost`], or holding one it has given back, until something
    /// else happens to re-level it.
    ///
    /// Lock order is boosts, then census, and nothing takes them the other way
    /// round: [`Self::census_join`] and [`Self::census_leave`] take only the
    /// census, and [`Self::propagate`], which reaches other handles' locks, runs
    /// with both released.
    fn reconcile(&self, boosts: &[(u8, u32)]) -> Option<u8> {
        let level = boosts
            .iter()
            .map(|(l, _)| *l)
            .min()
            .unwrap_or(u8::MAX)
            .min(self.0.base.load(Ordering::Relaxed));
        // Under the census lock as well, so the level and the count of tasks at
        // it move together.
        let mut state = self.0.census.lock().unwrap();
        let previous = self.0.effective.swap(level, Ordering::Relaxed);
        if let Some(census) = &state.census {
            census.shift(state.level, level, state.tasks);
        }
        state.level = level;
        (previous != level).then_some(level)
    }

    /// Pushes the result of a [`Self::reconcile`] to anything depending on this.
    ///
    /// Separate so it is plain that every caller does this with the locks
    /// released: it reaches other handles.
    fn propagate_if_changed(&self, changed: Option<u8>) {
        if let Some(level) = changed {
            self.propagate(level);
        }
    }

    /// Re-make this task's contribution to everything it depends on.
    fn propagate(&self, level: u8) {
        // Collected first so the lock is not held across `add_boost`, which
        // takes the target's locks and may propagate further.
        let mut links = self.0.links.lock().unwrap();
        for link in links.iter_mut() {
            if link.contributed == level {
                continue;
            }
            let target = link.target.clone();
            let old = std::mem::replace(&mut link.contributed, level);
            target.add_boost(level);
            target.remove_boost(old);
        }
    }
}

/// Keeps a task at a level while it is held. See [`SharedPriority::boost`].
#[derive(Debug)]
pub struct Boost {
    priority: SharedPriority,
    level: u8,
}

impl Drop for Boost {
    fn drop(&mut self) {
        self.priority.remove_boost(self.level);
    }
}

/// Keeps an inheritance edge alive. See [`SharedPriority::depend_on`].
#[derive(Debug)]
pub struct Dependency {
    dependent: SharedPriority,
    dependency: SharedPriority,
}

impl Drop for Dependency {
    fn drop(&mut self) {
        let mut links = self.dependent.0.links.lock().unwrap();
        if let Some(index) = links
            .iter()
            .position(|link| Arc::ptr_eq(&link.target.0, &self.dependency.0))
        {
            let link = links.swap_remove(index);
            drop(links);
            self.dependency.remove_boost(link.contributed);
        } else {
            debug_assert!(false, "dropped a dependency that was never added");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use UserPriority::*;

    #[test]
    fn the_ladder_is_ordered_by_urgency() {
        assert!(Priority::Main < Priority::User(L0));
        assert!(Priority::User(L0) < Priority::User(L1));
        assert!(Priority::User(UserPriority::WORST) < Priority::New);
        assert!(Priority::New < Priority::Accept);
    }

    #[test]
    fn levels_round_trip_and_stay_dense() {
        for level in 0..Priority::LEVELS as u8 {
            assert_eq!(Priority::from_level(level).level(), level);
        }
        assert_eq!(Priority::Accept.level() as usize, Priority::LEVELS - 1);
    }

    #[test]
    fn a_boost_holds_a_level_and_gives_it_back() {
        let p = SharedPriority::new(Priority::New);
        assert_eq!(p.effective(), Priority::New);
        {
            let _held = p.boost(Priority::User(L0));
            assert_eq!(p.effective(), Priority::User(L0));
        }
        assert_eq!(p.effective(), Priority::New);
    }

    #[test]
    fn boosts_compose_and_the_best_wins() {
        let p = SharedPriority::new(Priority::New);
        let a = p.boost(Priority::User(L2));
        let b = p.boost(Priority::User(L0));
        assert_eq!(p.effective(), Priority::User(L0));
        // The better one going away falls back to the other, not to base.
        drop(b);
        assert_eq!(p.effective(), Priority::User(L2));
        drop(a);
        assert_eq!(p.effective(), Priority::New);
    }

    #[test]
    fn set_base_does_not_override_a_better_boost() {
        let p = SharedPriority::new(Priority::New);
        let _held = p.boost(Priority::User(L5));
        p.set_base(Priority::User(L9));
        assert_eq!(p.effective(), Priority::User(L5), "boost still wins");
        p.set_base(Priority::User(L0));
        assert_eq!(p.effective(), Priority::User(L0), "base can be better");
    }

    #[test]
    fn a_dependency_inherits_the_best_of_its_dependents() {
        let driver = SharedPriority::new(Priority::New);
        let stranger = SharedPriority::new(Priority::New);
        let player = SharedPriority::new(Priority::User(L0));

        let _a = stranger.depend_on(&driver);
        assert_eq!(driver.effective(), Priority::New);

        let b = player.depend_on(&driver);
        assert_eq!(
            driver.effective(),
            Priority::User(L0),
            "one live player lifts the driver"
        );

        drop(b);
        assert_eq!(
            driver.effective(),
            Priority::New,
            "and it falls back when they leave"
        );
    }

    #[test]
    fn a_dependency_follows_a_dependent_that_is_re_levelled() {
        let driver = SharedPriority::new(Priority::New);
        let conn = SharedPriority::new(Priority::New);
        let _link = conn.depend_on(&driver);
        assert_eq!(driver.effective(), Priority::New);

        // The connection authenticates: the driver must follow, or it would be
        // scheduled behind the very connection it is demultiplexing for.
        conn.set_base(Priority::User(L0));
        assert_eq!(driver.effective(), Priority::User(L0));

        // And follows it back down.
        conn.set_base(Priority::User(L2));
        assert_eq!(driver.effective(), Priority::User(L2));
    }

    #[test]
    fn dropping_a_dependency_withdraws_the_current_contribution() {
        let driver = SharedPriority::new(Priority::New);
        let conn = SharedPriority::new(Priority::User(L3));
        let link = conn.depend_on(&driver);
        conn.set_base(Priority::User(L0));
        assert_eq!(driver.effective(), Priority::User(L0));
        // Withdrawing must remove what was *currently* contributed, not what
        // was contributed when the link was made.
        drop(link);
        assert_eq!(driver.effective(), Priority::New);
    }

    #[test]
    fn clones_share_one_level() {
        let a = SharedPriority::new(Priority::New);
        let b = a.clone();
        a.set_base(Priority::User(L1));
        assert_eq!(b.effective(), Priority::User(L1));
    }

    /// A held boost is honoured however hard the base is moved underneath it.
    ///
    /// [`Priority::Main`] is the best level there is, so while a boost to it is
    /// outstanding no reconcile can conclude anything else: whatever the base
    /// says, the minimum is `Main`. That makes it an invariant a second thread
    /// can check continuously, which is what this needs, because the failure it
    /// is for does not survive to the end of a run.
    ///
    /// That failure: a writer reads the boosts, is overtaken by the boost being
    /// taken, and then stores a level computed from before it existed. The
    /// handle is left below its own boost, and stays there until something else
    /// happens to re-level it. Under churn the next write repairs it in
    /// microseconds, so a test that only inspects the settled level sees
    /// nothing wrong; the breach has to be caught while it is open.
    ///
    /// Single-threaded callers cannot reach any of this, which is why this test
    /// insists on threads.
    #[test]
    fn a_held_boost_is_never_undercut_by_a_concurrent_writer() {
        const MOVERS: usize = 3;
        const ROUNDS: usize = 20_000;

        let shared = SharedPriority::new(Priority::New);
        let stop = std::sync::atomic::AtomicBool::new(false);
        let breach = Mutex::new(None);

        std::thread::scope(|scope| {
            for thread in 0..MOVERS {
                let shared = shared.clone();
                let stop = &stop;
                scope.spawn(move || {
                    let mut round = 0usize;
                    while !stop.load(Ordering::Relaxed) {
                        // Two levels, both worse than `Main`, so neither can
                        // ever be the right answer while the boost below is
                        // held.
                        shared.set_base(if (thread + round).is_multiple_of(2) {
                            Priority::User(L1)
                        } else {
                            Priority::New
                        });
                        round += 1;
                    }
                });
            }

            for _ in 0..ROUNDS {
                let boost = shared.boost(Priority::Main);
                // Re-read rather than checked once: a writer that overtook the
                // boost lands its stale store at some point during the hold,
                // not necessarily before this line is first reached.
                let seen = (0..8)
                    .map(|_| shared.effective())
                    .find(|seen| *seen != Priority::Main);
                drop(boost);
                if let Some(seen) = seen {
                    *breach.lock().unwrap() = Some(seen);
                    break;
                }
            }
            // Recorded rather than asserted, and stopped on every path: an
            // assertion here would unwind past this store and leave the movers
            // spinning, which `scope` would then wait on forever.
            stop.store(true, Ordering::Relaxed);
        });

        let breach = breach.lock().unwrap();
        assert!(
            breach.is_none(),
            "a boost to {:?} was outstanding and the handle sat at {:?}",
            Priority::Main,
            breach.unwrap()
        );
    }
}
