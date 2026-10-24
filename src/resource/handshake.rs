//! Rationing concurrent crypto.
//!
//! A handshake is the one piece of connection work an unauthenticated peer can
//! make a server do that costs real CPU. Slots ration it.
//!
//! A slot is not a reservation, since it can be held as cheaply as it can be
//! used. A handshake taking longer than a real one plausibly takes is *slow*,
//! and a slow handshake may be evicted by a newcomer that finds no room. Fast
//! handshakes are not evictable, so a flood of arrivals cannot cancel the work
//! it displaces — unless their network, a `/24` or `/48` by default, holds
//! more than its share of a full pool, so that one network cannot fill it with
//! handshakes too young to touch, however many of its addresses it spreads them
//! across.
//!
//! Nothing is evicted while there is room. A network with many handshakes in
//! flight is as often a VPN exit or a carrier NAT, or a browser opening several
//! connections over a slow link, as an attacker, and while the pool has room
//! none of them is in anyone's way. Only once it is full does the network
//! holding the most give way first.
//!
//! A handshake whose peer has sent its ClientHello is evicted after one whose
//! peer has not. Sending one costs an attacker nothing, so this is a tiebreak
//! rather than protection: a peer that has not managed even that by the time it
//! is slow is no browser on a slow link, whereas one that sent it and then
//! stalled may well be, such as behind a tunnel dropping the server's full-size
//! reply until the kernel shrinks it.
//!
//! There is no timer: a handshake past its deadline keeps its slot until
//! somebody comes for it.

use crate::resource::ip_limiter::mask;
use crate::{Goalkeeper, ProvideGoalkeeper, SystemGoalkeeper};

use fxhash::FxHashMap;
use log::warn;
use std::cmp::Reverse;
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
    /// two, and one whose server reply is lost on a narrow path needs a few
    /// more for the kernel to shrink it.
    pub deadline: Duration,
    /// How long a handshake may take before it becomes evictable. Comfortably
    /// longer than the round trip or two a real one costs.
    pub slow: Duration,
    /// Handshakes one source, an address masked to [`Config::share_prefixes`],
    /// may hold in a full pool before even its fast
    /// ones become evictable.
    ///
    /// Applies only when a newcomer finds no room, since while there is room an
    /// address with many handshakes is in nobody's way: it is as often a NAT,
    /// a VPN exit or a browser opening several connections as an attacker.
    pub share: usize,
}

impl Policy {
    /// What an unloaded host allows.
    pub const NORMAL: Self = Self {
        capacity: 32,
        deadline: Duration::from_secs(15),
        slow: Duration::from_secs(1),
        share: 8,
    };

    /// What a host already short of CPU allows.
    ///
    /// Every number tightens together. A smaller pool with unchanged patience
    /// would shed more legitimate traffic per stalled handshake, not less.
    ///
    /// Except the deadline, which stays long enough for a handshake whose
    /// server reply is lost on a narrow path to recover: the kernel takes a
    /// second or three to notice and shrink it (`tcp_mtu_probing`), and a
    /// deadline shorter than that reaps exactly the clients it should spare.
    /// Pressure still evicts them sooner, through the smaller pool.
    pub const PRESSURED: Self = Self {
        capacity: 16,
        deadline: Duration::from_secs(5),
        slow: Duration::from_millis(500),
        share: 4,
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
    /// The prefixes an IPv4 and an IPv6 address are masked to, to make the
    /// source whose handshakes count against one [`Policy::share`]. Not part
    /// of [`Policy`], since it does not move with pressure.
    pub share_prefixes: (u8, u8),
}

impl Default for Config {
    fn default() -> Self {
        Self {
            normal: Policy::NORMAL,
            pressured: Policy::PRESSURED,
            share_prefixes: (24, 48),
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

/// See [`crate::Goalkeeper::set_handshake_share_prefixes`].
pub(crate) fn set_share_prefixes(gk: &Goalkeeper, v4: u8, v6: u8) {
    gk.handshakes.config.lock().unwrap().share_prefixes = (v4.min(32), v6.min(128));
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
        share: between(normal.share, pressured.share),
    }
}

/// A handshake turned away: the pool was full and nothing in it was evictable.
///
/// The connection should be closed. Letting it handshake anyway, without a
/// slot, would give it no deadline and make it impossible to evict, which is
/// exactly what the pool exists to prevent.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Refused;

/// See [`crate::ProvideGoalkeeper::handshake_slot`].
pub(crate) fn slot<P: ProvideGoalkeeper>(
    provider: &P,
    ip: IpAddr,
    accepted: Instant,
    hello: bool,
) -> Result<Slot<P>, Refused> {
    let gk: &Goalkeeper = provider;
    let (policy, source) = {
        let config = *gk.handshakes.config.lock().unwrap();
        // Compute strain rather than strain in general, since a saturated
        // uplink is no reason to shrink this pool. A position rather than a
        // verdict; see `interpolate`.
        let policy = interpolate(
            config.normal,
            config.pressured,
            crate::resource::compute_glide_of(gk),
        );
        (policy, mask(ip, config.share_prefixes))
    };
    let (slot, batch) = {
        let mut registry = gk.handshakes.registry.lock().unwrap();
        let slot = registry.admit(ip, source, accepted, hello, policy);
        (slot, registry.take_due_batch(accepted))
    };
    // Outside the lock: formatting a full batch is the slowest thing here, and
    // every handshake waits on that lock.
    if let Some(batch) = batch {
        batch.log();
    }
    let mut slot = slot.ok_or(Refused)?;
    slot.provider = Some(provider.clone());
    Ok(slot)
}

/// See [`crate::ProvideGoalkeeper::handshake_counts`].
pub(crate) fn counts(gk: &Goalkeeper) -> Counts {
    gk.handshakes.registry.lock().unwrap().take_counts()
}

/// Distinct addresses a [`Batch`] names, per kind, before it only counts. A
/// real flood comes from far more, and naming them all would make the record of
/// an attack a resource it can exhaust; the first few are what tell a handful
/// holding the pool from a crowd anyway.
const MAX_ADDRESSES: usize = 32;

/// The shortest span a [`Batch`] covers before it is logged.
const BATCH_SPAN: Duration = Duration::from_secs(10);

/// The fewest kills and refusals a [`Batch`] holds before it is logged, so a
/// quiet host says nothing about a straggler or two.
const BATCH_EVENTS: u32 = 10;

/// Who [`Counts::killed`] and [`Counts::refused`] happened to, gathered to be
/// logged together: for telling a crowd of ordinary clients apart from a few
/// addresses holding the pool, which the counts alone can't.
///
/// Logged rather than reported, the way a refused connection is (see
/// `IpLimiter::warn`), and batched for the same reason that is rate limited:
/// under a flood, a line per event would be the louder denial of service.
#[derive(Debug, Default, PartialEq)]
struct Batch {
    /// When the first event in it happened.
    started: Option<Instant>,
    /// Kills and refusals, named or not.
    events: u32,
    /// Handshakes given up on, by address.
    killed: FxHashMap<IpAddr, u32>,
    /// Handshakes turned away, by address.
    refused: FxHashMap<IpAddr, u32>,
    /// Kills of addresses past [`MAX_ADDRESSES`], counted but not named.
    killed_unnamed: u32,
    /// Refusals of addresses past [`MAX_ADDRESSES`], counted but not named.
    refused_unnamed: u32,
}

impl Batch {
    /// Counts one against `ip` in `map`, or in `unnamed` once the map is full
    /// of other addresses.
    fn note(map: &mut FxHashMap<IpAddr, u32>, unnamed: &mut u32, ip: IpAddr) {
        if let Some(count) = map.get_mut(&ip) {
            *count = count.saturating_add(1);
        } else if map.len() < MAX_ADDRESSES {
            map.insert(ip, 1);
        } else {
            *unnamed = unnamed.saturating_add(1);
        }
    }

    fn event(&mut self, now: Instant) {
        self.started.get_or_insert(now);
        self.events = self.events.saturating_add(1);
    }

    fn killed(&mut self, ip: IpAddr, now: Instant) {
        self.event(now);
        Self::note(&mut self.killed, &mut self.killed_unnamed, ip);
    }

    fn refused(&mut self, ip: IpAddr, now: Instant) {
        self.event(now);
        Self::note(&mut self.refused, &mut self.refused_unnamed, ip);
    }

    /// Whether it has gathered enough, over long enough, to be logged.
    fn due(&self, now: Instant) -> bool {
        self.events >= BATCH_EVENTS
            && self
                .started
                .is_some_and(|started| now.saturating_duration_since(started) >= BATCH_SPAN)
    }

    /// A line per kind that happened: each address and its count, most first.
    fn log(&self) {
        let seconds = self
            .started
            .map_or(0, |started| started.elapsed().as_secs());
        Self::log_kind("killed", &self.killed, self.killed_unnamed, seconds);
        Self::log_kind("refused", &self.refused, self.refused_unnamed, seconds);
    }

    fn log_kind(what: &str, counts: &FxHashMap<IpAddr, u32>, unnamed: u32, seconds: u64) {
        if counts.is_empty() && unnamed == 0 {
            return;
        }
        let mut sorted: Vec<_> = counts.iter().collect();
        sorted.sort_unstable_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
        let total = sorted.iter().map(|(_, n)| **n as u64).sum::<u64>() + unnamed as u64;
        let map = sorted
            .iter()
            .map(|(ip, n)| format!("{ip}: {n}"))
            .collect::<Vec<_>>()
            .join(", ");
        let rest = if unnamed > 0 {
            format!(" and {unnamed} from addresses past the cap")
        } else {
            String::new()
        };
        warn!(
            "handshakes {what} in {seconds}s: {total} from {} addresses {{{map}}}{rest}",
            sorted.len()
        );
    }
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
    /// Given up on, whether reaped past the deadline or evicted to make room
    /// for a newcomer.
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
    /// `ip` masked to [`Config::share_prefixes`] when it arrived: what its
    /// share is counted against.
    source: IpAddr,
    /// When the connection was accepted, not when the task got around to it.
    accepted: Instant,
    /// Whether the peer's ClientHello has arrived. See [`Hello`].
    hello: bool,
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
    /// Who the kills and refusals happened to, until there are enough to log.
    batch: Batch,
    /// Handshakes per source, counted afresh by each arrival that finds the
    /// pool full. Kept between arrivals only for its allocation.
    holdings: FxHashMap<IpAddr, usize>,
}

impl Registry {
    /// Admits a handshake from `ip`, evicting to make room if that is allowed.
    ///
    /// In order:
    ///
    /// 1. Reap everything past [`Policy::deadline`]. Unconditional; an arrival
    ///    is the only clock this keeps.
    /// 2. Take a free slot if there is one, whoever is asking and however many
    ///    the address already holds.
    /// 3. Otherwise evict one, if anything is evictable: a slow handshake, or
    ///    any handshake of a source holding more than [`Policy::share`].
    ///    Of those, one still waiting for its ClientHello before one that has
    ///    heard it; then the source holding the most; then the oldest.
    /// 4. Otherwise refuse.
    ///
    /// `source` is `ip` masked to [`Config::share_prefixes`]. `hello` is
    /// whether the peer's ClientHello has already arrived.
    fn admit<P: ProvideGoalkeeper>(
        &mut self,
        ip: IpAddr,
        source: IpAddr,
        accepted: Instant,
        hello: bool,
        policy: Policy,
    ) -> Option<Slot<P>> {
        let age = |entry: &Entry| accepted.saturating_duration_since(entry.accepted);
        let slow = |entry: &Entry| age(entry) >= policy.slow;
        self.counts.attempts = self.counts.attempts.saturating_add(1);

        // 1. The expired, whoever owns them.
        let before = self.entries.len();
        let batch = &mut self.batch;
        self.entries.retain(|entry| {
            let alive = age(entry) < policy.deadline;
            if !alive {
                batch.killed(entry.ip, accepted);
            }
            alive
        });
        self.counts.killed = self
            .counts
            .killed
            .saturating_add((before - self.entries.len()) as u32);

        // 2, 3 and 4. Counted only once the pool is full, since nothing else
        //    needs the counts, and a full pool is bounded by its capacity.
        if self.entries.len() >= policy.capacity {
            let holdings = &mut self.holdings;
            holdings.clear();
            for entry in &self.entries {
                *holdings.entry(entry.source).or_default() += 1;
            }
            let Some(victim) = self
                .entries
                .iter()
                .enumerate()
                .filter(|(_, e)| slow(e) || holdings[&e.source] > policy.share)
                .min_by_key(|(_, e)| (e.hello, Reverse(holdings[&e.source]), e.accepted))
                .map(|(index, _)| index)
            else {
                self.counts.refused = self.counts.refused.saturating_add(1);
                self.batch.refused(ip, accepted);
                return None;
            };
            let evicted = self.entries.swap_remove(victim);
            self.counts.killed = self.counts.killed.saturating_add(1);
            self.batch.killed(evicted.ip, accepted);
        }

        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        let (_kill, kill) = oneshot::channel();
        self.entries.push(Entry {
            id,
            ip,
            source,
            accepted,
            hello,
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

    /// Records that `id`'s peer has sent its ClientHello, if `id` still holds a
    /// slot.
    fn heard(&mut self, id: u64) {
        if let Some(entry) = self.entries.iter_mut().find(|e| e.id == id) {
            entry.hello = true;
        }
    }

    fn take_counts(&mut self) -> Counts {
        std::mem::take(&mut self.counts)
    }

    /// The batch, and a fresh one in its place, if it is due to be logged.
    fn take_due_batch(&mut self, now: Instant) -> Option<Batch> {
        self.batch.due(now).then(|| std::mem::take(&mut self.batch))
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

    /// A handle for the handshake [`Self::run`] runs to say its peer's
    /// ClientHello has arrived, which it alone can see.
    ///
    /// Taken before running, since running consumes the slot.
    pub fn hello(&self) -> Hello<P> {
        Hello {
            id: self.id,
            provider: self.provider.clone(),
        }
    }
}

/// Says that a [`Slot`]'s peer has sent its ClientHello.
///
/// Its handshake is then evicted only after every one that has not: see the
/// module documentation.
pub struct Hello<P: ProvideGoalkeeper = SystemGoalkeeper> {
    id: u64,
    /// As on the [`Slot`] it came from.
    provider: Option<P>,
}

impl<P: ProvideGoalkeeper> Hello<P> {
    /// Records it. Nothing happens if the handshake has already been evicted
    /// or finished.
    pub fn heard(&self) {
        if let Some(provider) = &self.provider {
            provider.handshakes.registry.lock().unwrap().heard(self.id);
        }
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
            share: 2,
        }
    }

    fn at(start: Instant, seconds: u64) -> Instant {
        start + Duration::from_secs(seconds)
    }

    impl Registry {
        /// [`Registry::admit`] with the provider pinned, so inference stops
        /// asking. The registry itself is instance-agnostic.
        fn admit_one(&mut self, ip: IpAddr, accepted: Instant) -> Option<Slot<SystemGoalkeeper>> {
            self.admit(ip, ip, accepted, false, policy())
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

    /// A VPN exit, a carrier NAT, or a browser on a slow link: many slow
    /// handshakes from one address, in nobody's way while there is room.
    #[test]
    fn a_shared_address_keeps_its_slow_handshakes_while_there_is_room() {
        let mut registry = Registry::default();
        let start = Instant::now();
        for n in 0..4 {
            registry.admit_one(ip(1), at(start, n)).unwrap();
        }
        assert_eq!(
            registry.entries.len(),
            4,
            "nothing evicted with room to spare"
        );
    }

    #[test]
    fn one_address_cannot_hold_the_pool() {
        let mut registry = Registry::default();
        let start = Instant::now();
        // Inside the deadline, so it is eviction that frees the pool below and
        // not the reaper.
        for n in 0..20 {
            assert!(registry.admit_one(ip(1), at(start, n)).is_some());
        }
        assert_eq!(registry.entries.len(), policy().capacity);
        assert!(
            registry.entries.iter().all(|e| e.ip == ip(1)),
            "the whole pool, while nobody else wanted it"
        );
        // So the rest of the pool is there for everyone else.
        for n in 2..6 {
            assert!(registry.admit_one(ip(n), at(start, 20)).is_some());
        }
        assert!(registry.entries.iter().all(|e| e.ip != ip(1)));
    }

    /// With the share counted per network, spreading fast handshakes across
    /// its addresses does not keep a network under its share.
    #[test]
    fn a_network_spread_across_addresses_cannot_hold_the_pool() {
        let mut registry = Registry::default();
        let start = Instant::now();
        let network = mask(ip(0), (24, 48));
        for n in 0..4 {
            registry
                .admit::<SystemGoalkeeper>(ip(n), network, start, false, policy())
                .unwrap();
        }
        // Each address holds one, but the /24 holds four, over its share of
        // two, so even its fast handshakes give way.
        let elsewhere = IpAddr::from([10, 0, 1, 1]);
        assert!(
            registry
                .admit::<SystemGoalkeeper>(elsewhere, elsewhere, start, false, policy())
                .is_some()
        );
        assert!(registry.entries.iter().any(|e| e.ip == elsewhere));
    }

    /// In a full pool, the address holding the most gives way before an older
    /// handshake of an address holding one.
    #[test]
    fn the_biggest_holder_is_evicted_first() {
        let mut registry = Registry::default();
        let start = Instant::now();
        registry.admit_one(ip(2), at(start, 0)).unwrap();
        for n in 1..4 {
            registry.admit_one(ip(1), at(start, n)).unwrap();
        }
        assert!(registry.admit_one(ip(9), at(start, 4)).is_some());
        assert_eq!(registry.entries.iter().filter(|e| e.ip == ip(1)).count(), 2);
        assert!(
            registry.entries.iter().any(|e| e.ip == ip(2)),
            "the lone, older handshake survives"
        );
        // And the biggest holder's oldest went, not its newest.
        assert!(!registry.entries.iter().any(|e| e.accepted == at(start, 1)));
    }

    /// One address cannot fill a pool with handshakes too young to evict.
    #[test]
    fn an_address_over_its_share_loses_even_fast_handshakes() {
        let mut registry = Registry::default();
        let start = Instant::now();
        registry.admit_one(ip(2), start).unwrap();
        for _ in 0..3 {
            registry.admit_one(ip(1), start).unwrap();
        }
        assert!(registry.admit_one(ip(9), start).is_some());
        assert_eq!(registry.entries.iter().filter(|e| e.ip == ip(1)).count(), 2);
        assert!(registry.entries.iter().any(|e| e.ip == ip(2)));
    }

    /// A handshake whose peer has sent its ClientHello is evicted after one
    /// whose peer has not, however old: one that has not even sent that is no
    /// browser on a slow link.
    #[test]
    fn handshakes_that_have_heard_hello_go_last() {
        let mut registry = Registry::default();
        let start = Instant::now();
        let heard = registry.admit_one(ip(1), at(start, 0)).unwrap();
        registry.heard(heard.id);
        for n in 2..5 {
            registry.admit_one(ip(n), at(start, n as u64)).unwrap();
        }
        assert!(registry.admit_one(ip(9), at(start, 4)).is_some());
        assert!(
            registry.entries.iter().any(|e| e.ip == ip(1)),
            "the oldest, but it heard hello"
        );
        assert!(!registry.entries.iter().any(|e| e.ip == ip(2)));
    }

    /// Hello is a tiebreak among the evictable, not protection: a pool full of
    /// slow handshakes that all heard it still takes newcomers. Heard on
    /// arrival, as QUIC's are.
    #[test]
    fn hello_does_not_make_a_handshake_unevictable() {
        let mut registry = Registry::default();
        let start = Instant::now();
        for n in 0..4 {
            let slot: Option<Slot<SystemGoalkeeper>> =
                registry.admit(ip(n), ip(n), at(start, n as u64), true, policy());
            assert!(slot.is_some());
        }
        assert!(registry.entries.iter().all(|e| e.hello));
        assert!(registry.admit_one(ip(9), at(start, 4)).is_some());
        assert!(!registry.entries.iter().any(|e| e.ip == ip(0)));
    }

    /// The many-addresses version of the slow flood: nobody over their share,
    /// so it comes down to slow and old, and fast newcomers still get in.
    #[test]
    fn a_distributed_slow_flood_still_admits_newcomers() {
        let mut registry = Registry::default();
        let start = Instant::now();
        for n in 0..4 {
            registry.admit_one(ip(n), at(start, 0)).unwrap();
        }
        for n in 10..14 {
            assert!(registry.admit_one(ip(n), at(start, 2)).is_some());
        }
        assert!(registry.entries.iter().all(|e| e.ip >= ip(10)));
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
        let refused: Option<Slot<SystemGoalkeeper>> =
            registry.admit(ip(9), ip(9), start, false, pressured);
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

    #[test]
    fn names_who_was_killed_and_refused() {
        let mut registry = Registry::default();
        let start = Instant::now();
        let _slots: Vec<_> = (0..4)
            .map(|n| registry.admit_one(ip(n), start).unwrap())
            .collect();
        // Full of fast handshakes: refused, twice.
        assert!(registry.admit_one(ip(9), start).is_none());
        assert!(registry.admit_one(ip(9), start).is_none());
        // Past the deadline: all four reaped for the arrival.
        assert!(registry.admit_one(ip(8), at(start, 6)).is_some());

        let batch = &registry.batch;
        assert_eq!(batch.refused.get(&ip(9)), Some(&2));
        assert_eq!(batch.refused.len(), 1);
        for n in 0..4 {
            assert_eq!(batch.killed.get(&ip(n)), Some(&1));
        }
        assert_eq!(batch.killed.len(), 4);
        assert_eq!(batch.events, 6);
        assert_eq!(batch.started, Some(start));
    }

    #[test]
    fn logs_only_enough_over_long_enough() {
        let start = Instant::now();
        let mut registry = Registry::default();
        for _ in 0..BATCH_EVENTS - 1 {
            registry.batch.refused(ip(1), start);
        }
        let late = start + BATCH_SPAN;
        assert!(registry.take_due_batch(late).is_none(), "too few");

        registry.batch.refused(ip(1), start);
        assert!(
            registry
                .take_due_batch(late - Duration::from_millis(1))
                .is_none(),
            "too soon"
        );

        let batch = registry.take_due_batch(late).unwrap();
        assert_eq!(batch.refused.get(&ip(1)), Some(&BATCH_EVENTS));
        assert_eq!(registry.batch, Batch::default(), "the next starts empty");
    }

    #[test]
    fn stops_naming_past_the_cap() {
        let start = Instant::now();
        let mut batch = Batch::default();
        for n in 0..=MAX_ADDRESSES as u32 {
            batch.refused(IpAddr::from(n.to_be_bytes()), start);
        }
        assert_eq!(batch.refused.len(), MAX_ADDRESSES);
        assert_eq!(batch.refused_unnamed, 1);
        assert_eq!(batch.events, MAX_ADDRESSES as u32 + 1);
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
}
