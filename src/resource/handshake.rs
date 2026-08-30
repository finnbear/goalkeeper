//! Rationing concurrent crypto.
//!
//! A handshake is the one piece of connection work an unauthenticated peer can
//! make a server do that costs real CPU. Slots ration it.
//!
//! A slot is not a reservation, since it can be held as cheaply as it can be
//! used. A handshake taking longer than a real one plausibly takes is *slow*,
//! and a slow handshake may be evicted, either by a newcomer that finds no room
//! or by its own address holding too many. Fast handshakes are never evictable,
//! so a flood of arrivals cannot cancel the work it displaces.
//!
//! There is no timer: a handshake past its deadline keeps its slot until
//! somebody comes for it.

use crate::{Goalkeeper, ProvideGoalkeeper, SystemGoalkeeper};

use std::future::Future;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tokio::sync::oneshot;

/// The numbers, and the pressure switch between them.
///
/// One policy for every transport and both halves of the decision, how many and
/// for how long, so a host's tolerance for crypto is described in one place.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) struct Policy {
    /// Handshakes allowed in flight at once. Not a cap on connections, which
    /// the per-address limiter bounds.
    pub capacity: usize,
    /// How long a handshake may go unfinished before the next arrival reaps it,
    /// whether or not its slot is wanted.
    ///
    /// Generous, since a client on a slow link legitimately needs a second or
    /// two.
    pub deadline: Duration,
    /// How long a handshake may take before it becomes evictable. Comfortably
    /// longer than the round trip or two a real one costs.
    pub slow: Duration,
    /// Slow handshakes one address may hold at once.
    ///
    /// Qualified on slow, since an unqualified cap would punish a browser
    /// opening several connections at once or a NAT presenting thousands of
    /// clients as one address.
    pub slow_per_ip: usize,
}

impl Policy {
    /// What an unloaded host allows.
    pub const NORMAL: Self = Self {
        capacity: 32,
        deadline: Duration::from_secs(15),
        slow: Duration::from_secs(1),
        slow_per_ip: 2,
    };

    /// What a host already short of CPU allows.
    ///
    /// Every number tightens together. A smaller pool with unchanged patience
    /// would shed more legitimate traffic per stalled handshake, not less.
    pub const PRESSURED: Self = Self {
        capacity: 16,
        deadline: Duration::from_secs(3),
        slow: Duration::from_millis(500),
        slow_per_ip: 2,
    };
}

/// Which policies to switch between.
#[derive(Copy, Clone, Debug)]
pub(crate) struct Config {
    /// Applied when the host has headroom.
    pub normal: Policy,
    /// Applied when the host is short of CPU or memory, but not of link, which
    /// says nothing about crypto. See
    /// [`crate::resource::Pressure::worst_compute`].
    pub pressured: Policy,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            normal: Policy::NORMAL,
            pressured: Policy::PRESSURED,
        }
    }
}

/// The slots every handshake competes for.
///
/// Owned by [`Goalkeeper`]; the API that reaches it lives on
/// [`crate::ProvideGoalkeeper`].
#[derive(Default)]
pub(crate) struct HandshakeSemaphore {
    config: Mutex<Config>,
    /// Not behind an `Arc`, since nothing outside this struct holds it. A
    /// [`Slot`] reaches the registry through the handle it was issued against.
    pub(crate) registry: Mutex<Registry>,
}

/// Adjusts one configured field, on each policy in turn.
///
/// The callback is handed a policy and whether it is the pressured one, so a
/// setter names one field and supplies both of its values, keeping the pair
/// from drifting apart one edit at a time.
pub(crate) fn set_policy(gk: &Goalkeeper, f: impl Fn(&mut Policy, bool)) {
    let mut config = gk.handshakes.config.lock().unwrap();
    f(&mut config.normal, false);
    f(&mut config.pressured, true);
}

/// Where the pool currently sits between its two policies, in `0..=1`.
///
/// Glided rather than switched, one step per tick in both directions. Halving
/// the pool in one step would evict a burst of handshakes that were about to
/// finish, costing exactly the CPU the tightening meant to save.
///
/// [`Policy::NORMAL`] and [`Policy::PRESSURED`] are therefore the ends of a
/// range rather than two settings, one of which applies.
fn interpolate(normal: Policy, pressured: Policy, at: f32) -> Policy {
    let at = at.clamp(0.0, 1.0) as f64;
    let between = |a: usize, b: usize| (a as f64 + (b as f64 - a as f64) * at) as usize;
    let over = |a: Duration, b: Duration| a.mul_f64(1.0 - at) + b.mul_f64(at);
    Policy {
        // All four move together on one scalar, since a smaller pool with
        // unchanged patience sheds more legitimate traffic, not less.
        capacity: between(normal.capacity, pressured.capacity),
        deadline: over(normal.deadline, pressured.deadline),
        slow: over(normal.slow, pressured.slow),
        slow_per_ip: between(normal.slow_per_ip, pressured.slow_per_ip),
    }
}

/// See [`crate::ProvideGoalkeeper::handshake_slot`].
pub(crate) fn slot<P: ProvideGoalkeeper>(
    provider: &P,
    ip: IpAddr,
    accepted: Instant,
) -> Option<Slot<P>> {
    let gk: &Goalkeeper = provider;
    let policy = {
        let config = *gk.handshakes.config.lock().unwrap();
        // Compute strain rather than strain in general, since a saturated
        // uplink is no reason to shrink this pool. A position rather than a
        // verdict; see `interpolate`.
        interpolate(
            config.normal,
            config.pressured,
            crate::resource::compute_glide_of(gk),
        )
    };
    let mut slot = gk
        .handshakes
        .registry
        .lock()
        .unwrap()
        .admit(ip, accepted, policy)?;
    slot.provider = Some(provider.clone());
    Some(slot)
}

/// See [`crate::ProvideGoalkeeper::handshake_counts`].
pub(crate) fn counts(gk: &Goalkeeper) -> Counts {
    gk.handshakes.registry.lock().unwrap().take_counts()
}

/// What has happened to handshakes over a window.
///
/// Counts rather than rates, so a report that is late or skipped widens the
/// window instead of distorting it.
#[derive(Copy, Clone, Debug, Default, PartialEq)]
pub struct Counts {
    /// Connections that reached the pool.
    pub attempts: u32,
    /// Turned away because nothing could be evicted for them.
    pub refused: u32,
    /// Given up on, whether reaped past the deadline or evicted for being slow.
    /// One number, since which rule reached it first says more about the
    /// constants than about the peer.
    pub killed: u32,
    /// Finished, whether or not the handshake itself succeeded.
    pub completed: u32,
    /// Highest fraction of capacity in use.
    ///
    /// A fraction rather than a count, since capacity moves with pressure.
    pub peak: f32,
}

/// A handshake in flight.
struct Entry {
    id: u64,
    ip: IpAddr,
    /// When the connection was accepted, not when the task got around to it.
    accepted: Instant,
    /// Dropped to evict. The handshake selects on the paired receiver, so
    /// removing an entry from the registry cancels it.
    _kill: oneshot::Sender<()>,
}

/// Every handshake in flight, and the decisions about who may join them.
///
/// Holds no IO and no upstream type, so the policy can be exercised directly.
#[derive(Default)]
pub(crate) struct Registry {
    entries: Vec<Entry>,
    next_id: u64,
    counts: Counts,
}

impl Registry {
    /// Admits a handshake from `ip`, evicting to make room if that is allowed.
    ///
    /// In order:
    ///
    /// 1. Reap everything past [`Policy::deadline`]. Unconditional; an arrival
    ///    is the only clock this keeps.
    /// 2. Enforce [`Policy::slow_per_ip`] against the arriving address, newest
    ///    first, whether or not there is room.
    /// 3. Take a free slot if there is one.
    /// 4. Otherwise evict the oldest slow handshake, whoever owns it.
    /// 5. Otherwise refuse.
    fn admit<P: ProvideGoalkeeper>(
        &mut self,
        ip: IpAddr,
        accepted: Instant,
        policy: Policy,
    ) -> Option<Slot<P>> {
        let age = |entry: &Entry| accepted.saturating_duration_since(entry.accepted);
        let slow = |entry: &Entry| age(entry) >= policy.slow;
        self.counts.attempts = self.counts.attempts.saturating_add(1);

        // 1. The expired, whoever owns them.
        let before = self.entries.len();
        self.entries.retain(|entry| age(entry) < policy.deadline);
        self.counts.killed = self
            .counts
            .killed
            .saturating_add((before - self.entries.len()) as u32);

        // 2. The arriving address's own slow handshakes, newest first. `>=`
        //    because the arrival is about to join them.
        while self
            .entries
            .iter()
            .filter(|e| e.ip == ip && slow(e))
            .count()
            >= policy.slow_per_ip
        {
            let Some(newest) = self
                .entries
                .iter()
                .enumerate()
                .filter(|(_, e)| e.ip == ip && slow(e))
                .max_by_key(|(_, e)| e.accepted)
                .map(|(index, _)| index)
            else {
                break;
            };
            self.entries.swap_remove(newest);
            self.counts.killed = self.counts.killed.saturating_add(1);
        }

        // 3, 4 and 5.
        if self.entries.len() >= policy.capacity {
            let Some(oldest) = self
                .entries
                .iter()
                .enumerate()
                .filter(|(_, e)| slow(e))
                .min_by_key(|(_, e)| e.accepted)
                .map(|(index, _)| index)
            else {
                self.counts.refused = self.counts.refused.saturating_add(1);
                return None;
            };
            self.entries.swap_remove(oldest);
            self.counts.killed = self.counts.killed.saturating_add(1);
        }

        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        let (_kill, kill) = oneshot::channel();
        self.entries.push(Entry {
            id,
            ip,
            accepted,
            _kill,
        });
        // Sampled here because this is the only place the pool grows.
        self.counts.peak = self
            .counts
            .peak
            .max(self.entries.len() as f32 / policy.capacity.max(1) as f32);
        Some(Slot {
            id,
            kill,
            provider: None,
        })
    }

    /// Frees `id`'s slot, if it still holds one.
    ///
    /// Finding one means the handshake got to the end under its own power;
    /// finding none means it was evicted, and whoever evicted it counted that.
    fn release(&mut self, id: u64) {
        if let Some(index) = self.entries.iter().position(|e| e.id == id) {
            self.entries.swap_remove(index);
            self.counts.completed = self.counts.completed.saturating_add(1);
        }
    }

    fn take_counts(&mut self) -> Counts {
        std::mem::take(&mut self.counts)
    }
}

/// A handshake's claim on a slot, and its permission to keep going.
///
/// Released by dropping, so a handshake that finishes, fails, times out or is
/// evicted returns the slot by the same path.
///
/// Carries the handle it was issued against, so it releases to the instance
/// that granted it. Against [`SystemGoalkeeper`] that handle is zero-sized.
pub struct Slot<P: ProvideGoalkeeper = SystemGoalkeeper> {
    id: u64,
    /// Resolves when this handshake is evicted, which the sender being dropped
    /// is enough to say.
    kill: oneshot::Receiver<()>,
    /// [`None`] only between [`Registry::admit`] and [`slot`] installing it,
    /// which nothing else observes.
    provider: Option<P>,
}

impl<P: ProvideGoalkeeper> Slot<P> {
    /// Runs `future` under this slot, giving it up the moment it resolves.
    ///
    /// [`None`] means the handshake was evicted or displaced. Either way the
    /// slot is given up, since holding one while serving a connection would
    /// make the cap bound connections rather than handshakes.
    pub async fn run<F: Future>(mut self, future: F) -> Option<F::Output> {
        tokio::select! {
            output = future => Some(output),
            // Evicted, which the sender being dropped is enough to say.
            _ = &mut self.kill => None,
        }
        // `self` drops here, returning the slot however this resolved.
    }
}

impl<P: ProvideGoalkeeper> Drop for Slot<P> {
    fn drop(&mut self) {
        if let Some(provider) = &self.provider {
            provider
                .handshakes
                .registry
                .lock()
                .unwrap()
                .release(self.id);
        }
    }
}

/// Runs `future` under `slot` if there is one.
///
/// [`None`] for a listener with no crypto to ration, which runs unbounded.
#[cfg(feature = "tls")]
pub(crate) async fn bounded<F: Future, P: ProvideGoalkeeper>(
    slot: Option<Slot<P>>,
    future: F,
) -> Option<F::Output> {
    match slot {
        Some(slot) => slot.run(future).await,
        None => Some(future.await),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(n: u8) -> IpAddr {
        IpAddr::from([10, 0, 0, n])
    }

    fn policy() -> Policy {
        Policy {
            capacity: 4,
            deadline: Duration::from_secs(5),
            slow: Duration::from_secs(1),
            slow_per_ip: 2,
        }
    }

    fn at(start: Instant, seconds: u64) -> Instant {
        start + Duration::from_secs(seconds)
    }

    impl Registry {
        /// [`Registry::admit`] with the provider pinned, so inference stops
        /// asking. The registry itself is instance-agnostic.
        fn admit_one(&mut self, ip: IpAddr, accepted: Instant) -> Option<Slot<SystemGoalkeeper>> {
            self.admit(ip, accepted, policy())
        }
    }

    #[test]
    fn admits_until_full() {
        let mut registry = Registry::default();
        let start = Instant::now();
        for n in 0..4 {
            assert!(registry.admit_one(ip(n), start).is_some());
        }
        assert_eq!(registry.entries.len(), 4);
    }

    #[test]
    fn refuses_when_every_handshake_is_fast() {
        let mut registry = Registry::default();
        let start = Instant::now();
        for n in 0..4 {
            registry.admit_one(ip(n), start).unwrap();
        }
        // Still within the slow threshold, so nothing may be cancelled for
        // the newcomer: the arrivals a flood consists of must not displace
        // work that is about to finish.
        assert!(registry.admit_one(ip(9), start).is_none());
        assert_eq!(registry.entries.len(), 4);
    }

    #[test]
    fn evicts_the_oldest_slow_handshake() {
        let mut registry = Registry::default();
        let start = Instant::now();
        for n in 0..4 {
            registry.admit_one(ip(n), at(start, n as u64)).unwrap();
        }
        assert!(registry.admit_one(ip(9), at(start, 4)).is_some());
        assert!(!registry.entries.iter().any(|e| e.ip == ip(0)));
        assert!(registry.entries.iter().any(|e| e.ip == ip(9)));
        assert_eq!(registry.entries.len(), 4);
    }

    #[test]
    fn caps_slow_handshakes_per_address() {
        let mut registry = Registry::default();
        let start = Instant::now();
        let accepted = |registry: &Registry| {
            let mut accepted: Vec<_> = registry.entries.iter().map(|e| e.accepted).collect();
            accepted.sort();
            accepted
        };

        for n in 0..3 {
            registry.admit_one(ip(1), at(start, n)).unwrap();
        }
        assert_eq!(accepted(&registry), vec![at(start, 0), at(start, 2)]);

        // And again, however long it keeps trying. Inside the deadline, so it
        // is the cap doing this and not the reaper.
        registry.admit_one(ip(1), at(start, 4)).unwrap();
        assert_eq!(accepted(&registry), vec![at(start, 0), at(start, 4)]);
    }

    #[test]
    fn one_address_cannot_hold_the_pool() {
        let mut registry = Registry::default();
        let start = Instant::now();
        for n in 0..20 {
            registry.admit_one(ip(1), at(start, n * 2));
        }
        assert!(registry.entries.len() <= policy().slow_per_ip);
        // So the rest of the pool is there for everyone else.
        for n in 2..6 {
            assert!(registry.admit_one(ip(n), at(start, 40)).is_some());
        }
    }

    #[test]
    fn an_arrival_reaps_everything_expired() {
        let mut registry = Registry::default();
        let start = Instant::now();
        for n in 0..4 {
            registry.admit_one(ip(n), start).unwrap();
        }
        assert!(registry.admit_one(ip(9), at(start, 6)).is_some());
        assert_eq!(registry.entries.len(), 1);
        assert!(registry.entries.iter().all(|e| e.ip == ip(9)));
    }

    #[test]
    fn nothing_reaps_an_idle_host() {
        let mut registry = Registry::default();
        let start = Instant::now();
        registry.admit_one(ip(1), start).unwrap();
        // Deliberate: nobody is being denied while nobody is asking.
        assert_eq!(registry.entries.len(), 1);
    }

    #[test]
    fn a_released_slot_frees_its_room() {
        let mut registry = Registry::default();
        let start = Instant::now();
        let ids: Vec<_> = (0..4)
            .map(|n| registry.admit_one(ip(n), start).unwrap().id)
            .collect();
        assert!(registry.admit_one(ip(9), start).is_none());
        registry.release(ids[0]);
        assert!(registry.admit_one(ip(9), start).is_some());
    }

    #[test]
    fn pressure_shrinks_the_pool_without_evicting() {
        let mut registry = Registry::default();
        let start = Instant::now();
        for n in 0..4 {
            registry.admit_one(ip(n), start).unwrap();
        }
        let pressured = Policy {
            capacity: 2,
            ..policy()
        };
        let refused: Option<Slot<SystemGoalkeeper>> = registry.admit(ip(9), start, pressured);
        assert!(refused.is_none());
        assert_eq!(registry.entries.len(), 4, "the ones running are left alone");
    }

    #[test]
    fn counts_what_a_report_would_carry() {
        let mut registry = Registry::default();
        let start = Instant::now();

        let mut slots: Vec<_> = (0..4)
            .map(|n| registry.admit_one(ip(n), start).unwrap())
            .collect();
        let finished = slots.pop().unwrap();
        registry.release(finished.id);

        assert!(registry.admit_one(ip(8), start).is_some());
        assert!(registry.admit_one(ip(9), start).is_none());
        assert!(registry.admit_one(ip(9), at(start, 6)).is_some());

        let counts = registry.take_counts();
        assert_eq!(counts.attempts, 7);
        assert_eq!(counts.refused, 1);
        assert_eq!(counts.completed, 1);
        assert_eq!(counts.killed, 4);
        assert_eq!(counts.peak, 1.0);
        assert_eq!(
            registry.take_counts().attempts,
            0,
            "the window starts empty"
        );
    }

    #[tokio::test]
    async fn an_evicted_handshake_is_abandoned() {
        let mut registry = Registry::default();
        let start = Instant::now();
        let slot = registry.admit_one(ip(1), start).unwrap();
        // Evicting drops the sender, which is all the signal there is.
        registry.entries.clear();
        let outcome = slot.run(std::future::pending::<()>()).await;
        assert!(outcome.is_none());
    }

    #[tokio::test]
    async fn a_finished_handshake_returns_its_output() {
        let mut registry = Registry::default();
        let slot = registry.admit_one(ip(1), Instant::now()).unwrap();
        assert_eq!(slot.run(async { 5u32 }).await, Some(5));
    }

    #[cfg(feature = "tls")]
    #[tokio::test]
    async fn a_listener_without_crypto_runs_unbounded() {
        assert_eq!(
            bounded(None::<Slot<SystemGoalkeeper>>, async { 7u32 }).await,
            Some(7)
        );
    }
}
