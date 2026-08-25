//! Rationing RAM: what is held right now, by whom, and who gives it back first.
//!
//! Under a flood, memory is as scarce as CPU and as contested as the link.
//! Goalkeeper divides what it controls between priorities the way
//! [`crate::resource::bandwidth`] divides the wire: the buffers it configures
//! in hyper and quinn, the socket buffers it sets through the kernel, and the
//! handshake state it lets accumulate.
//!
//! # A controller, not a ladder
//!
//! Memory is a stock rather than a flow, so there is no window. The ledger
//! carries live occupancy, a reservation is released when its guard drops, and
//! refusing reclaims nothing, so memory has to be taken back through the levers
//! the bandwidth ledger already drives.
//!
//! Buffers therefore start descending at a setpoint below the limit, worst
//! levels first and the floor preserved. Refusal is the backstop, and the last
//! word: nothing here disconnects a connection over memory. It sheds quickly
//! and returns slowly, as TCP halves on loss and creeps on success, since a
//! buffer that is too small is slow and one that is too large is an
//! out-of-memory kill.
//!
//! # Once a second, in powers of two
//!
//! The controller runs on its own interval, a second by default, since a stock
//! moves far slower than the bandwidth epoch. See
//! [`set_memory_interval`][crate::Goalkeeper::set_memory_interval].
//!
//! Targets are quantised to powers of two, which is what the kernel does with
//! them anyway, with a deadband of one bucket to shrink and two to grow.

use crate::executor::priority::Priority;
use crate::{Goalkeeper, ProvideGoalkeeper, SystemGoalkeeper};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// How RAM is rationed.
#[derive(Copy, Clone, Debug)]
pub(crate) struct Config {
    /// What goalkeeper may authorise in total.
    ///
    /// Authorised, not resident: this bounds the buffers goalkeeper configures
    /// and the reservations it hands out. It does not own the allocator, so a
    /// true ceiling is still a cgroup, which reaches it through
    /// [`crate::resource`].
    pub limit: u64,
    /// The share of the limit the controller aims to stay under.
    ///
    /// Under one, so buffers begin descending before anything is refused.
    pub setpoint: f32,
    /// The share of the limit reserved for the levels below the cutoff, so that
    /// being outranked costs a connection almost all its buffers rather than
    /// all of them. A stranger's handshake still has to be able to finish.
    pub floor: f32,
    /// How often the controller runs.
    pub interval: Duration,
    /// The share of the gap to the target closed per tick when shedding.
    pub shrink_step: f32,
    /// The same when returning memory. Smaller by design; see the module docs.
    pub grow_step: f32,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            // Unlimited until told otherwise. A guessed RAM ceiling would be
            // wrong on most hosts, in the direction that breaks a working
            // deployment.
            limit: u64::MAX,
            setpoint: 0.8,
            floor: 0.1,
            interval: Duration::from_secs(1),
            // Sheds most of the gap in one tick, returns a tenth of it.
            shrink_step: 0.5,
            grow_step: 0.1,
        }
    }
}

/// Memory that has been authorised, released by dropping.
///
/// # Why the level does not travel with it
///
/// A bandwidth [`Grant`] freezes its level because it lives for part of one
/// window, so a re-levelling inside that window washes out when the window
/// rolls. A reservation lives as long as whatever it authorises, which for a
/// connection is the connection.
///
/// Freezing the level would leave a connection admitted as a stranger and then
/// established as a player booked against strangers forever: real strangers
/// would be cut off early, the player level would over-authorise, and the
/// controller would shrink the buffers of the players it was protecting.
///
/// So a connection's reservations are booked against the connection and follow
/// it when it is re-levelled; see [`crate::conn::Conn::try_reserve`]. Only a
/// reservation belonging to no connection has a fixed level, and it is
/// [`Priority::Main`].
///
/// Against [`SystemGoalkeeper`] the provider is zero-sized, so an unattributed
/// reservation is two words and a drop.
///
/// [`Grant`]: crate::resource::bandwidth::Grant
#[derive(Debug)]
pub struct Reservation<P: ProvideGoalkeeper = SystemGoalkeeper> {
    bytes: u64,
    /// Where it is booked *now*. Moves with the connection, if it has one.
    booking: Booking<P>,
    provider: P,
}

/// Which entry in the ledger a reservation is currently charged to.
#[derive(Debug)]
enum Booking<P: ProvideGoalkeeper> {
    /// Belongs to a connection, and follows it between levels.
    Conn(crate::conn::Conn<P>),
    /// Belongs to no connection, so it has nowhere to follow.
    Fixed(u8),
}

impl<P: ProvideGoalkeeper> Reservation<P> {
    pub(crate) fn fixed(bytes: u64, level: u8, provider: P) -> Self {
        Self {
            bytes,
            booking: Booking::Fixed(level),
            provider,
        }
    }

    pub(crate) fn attributed(bytes: u64, conn: crate::conn::Conn<P>, provider: P) -> Self {
        Self {
            bytes,
            booking: Booking::Conn(conn),
            provider,
        }
    }

    /// How much this authorises.
    pub fn bytes(&self) -> u64 {
        self.bytes
    }

    /// The level it is charged to right now.
    pub fn priority(&self) -> Priority {
        match &self.booking {
            Booking::Conn(conn) => Priority::from_level(conn.ram_level()),
            Booking::Fixed(level) => Priority::from_level(*level),
        }
    }
}

impl<P: ProvideGoalkeeper> Drop for Reservation<P> {
    fn drop(&mut self) {
        let bytes = self.bytes;
        // Released where it is booked now, not where it was taken. For a
        // connection that has been re-levelled those differ, and releasing at
        // the old level would leave the new one permanently overdrawn.
        let level = match &self.booking {
            Booking::Conn(conn) => {
                conn.release_ram(bytes);
                return;
            }
            Booking::Fixed(level) => *level,
        };
        self.provider
            .limiter
            .with_process(|_, _, memory| memory.release(level, bytes));
    }
}

/// What the ledger is holding, for whoever reports on the process.
///
/// Read through the methods rather than as an array, so a report is written in
/// terms of [`Priority`]. See [`crate::executor::Tasks`].
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct Usage {
    held: [u64; Priority::LEVELS],
    limit: u64,
    cutoff: u8,
}

impl Usage {
    /// Bytes authorised at `priority` right now.
    pub fn held(&self, priority: Priority) -> u64 {
        self.held[priority.level() as usize]
    }

    /// Bytes authorised across every level.
    pub fn held_total(&self) -> u64 {
        self.held.iter().sum()
    }

    /// What goalkeeper may authorise in total.
    pub fn limit(&self) -> u64 {
        self.limit
    }

    /// Bytes authorised, level by level, most urgent first.
    pub fn held_by_priority(&self) -> impl Iterator<Item = (Priority, u64)> + '_ {
        self.held
            .iter()
            .enumerate()
            .map(|(level, &bytes)| (Priority::from_level(level as u8), bytes))
    }

    /// The worst level still able to reserve.
    ///
    /// Compare with [`Ord`] rather than arithmetic.
    pub fn cutoff(&self) -> Priority {
        Priority::from_level(self.cutoff)
    }
}

/// Live occupancy, and the controller's position.
///
/// Owned by [`Goalkeeper`], inside the per-address limiter's lock, as the
/// bandwidth ledger is: a reservation consults the level occupancy and the
/// connection's address together.
pub(crate) struct Ledger {
    pub(crate) config: Config,
    /// Bytes outstanding per level. Not a per-window spend: entries fall only
    /// when a [`Reservation`] drops.
    held: [u64; Priority::LEVELS],
    /// When the controller last ran.
    ticked: Option<Instant>,
    /// The share of the way from unpressured to fully pressured, in `0..=1`.
    ///
    /// One scalar for every knob the controller drives, so the handshake pool's
    /// capacity, deadline and slow threshold move together.
    glide: f32,
}

impl Default for Ledger {
    fn default() -> Self {
        Self {
            config: Config::default(),
            held: [0; Priority::LEVELS],
            ticked: None,
            glide: 0.0,
        }
    }
}

impl Ledger {
    /// Charges `bytes` to `level` if the level may still hold them.
    ///
    /// [`None`] means refused, which is the backstop rather than the plan: by
    /// then the controller has been shrinking buffers for seconds and did not
    /// keep up.
    pub(crate) fn reserve(&mut self, level: u8, bytes: u64) -> Option<u64> {
        let at = (level as usize).min(Priority::LEVELS - 1);
        let allowance = self.allowance(level);
        if self.held[at].saturating_add(bytes) > allowance {
            return None;
        }
        self.held[at] = self.held[at].saturating_add(bytes);
        Some(bytes)
    }

    /// Charges `bytes` to `level` whether or not it can afford them.
    ///
    /// For memory that is already held and is only changing which entry it is
    /// counted under. See [`rebook`].
    pub(crate) fn force(&mut self, level: u8, bytes: u64) {
        let at = (level as usize).min(Priority::LEVELS - 1);
        self.held[at] = self.held[at].saturating_add(bytes);
    }

    /// Gives `bytes` back to `level`.
    pub(crate) fn release(&mut self, level: u8, bytes: u64) {
        let at = (level as usize).min(Priority::LEVELS - 1);
        self.held[at] = self.held[at].saturating_sub(bytes);
    }

    /// Bytes outstanding across every level.
    pub(crate) fn total(&self) -> u64 {
        self.held.iter().sum()
    }

    /// How full the process is, where one is at the limit.
    ///
    /// This is what [`crate::resource`] reads as the RAM axis, closing the loop
    /// the same way the bandwidth ledger closes the network one.
    pub(crate) fn fullness(&self) -> f32 {
        if self.config.limit == 0 || self.config.limit == u64::MAX {
            0.0
        } else {
            self.total() as f32 / self.config.limit as f32
        }
    }

    /// What the controller is currently willing to authorise in total.
    ///
    /// Not the limit: the controller aims at [`Config::setpoint`] and glides
    /// down from there under pressure, recovering slack before a refusal is
    /// needed.
    fn budget(&self) -> u64 {
        if self.config.limit == u64::MAX {
            return u64::MAX;
        }
        let aim = self.config.limit as f64 * self.config.setpoint.clamp(0.0, 1.0) as f64;
        // Glide shrinks the aim rather than the limit, so a fully pressured
        // process still authorises the floor and not zero.
        (aim * (1.0 - self.glide.clamp(0.0, 1.0) as f64 * 0.5)) as u64
    }

    /// How many bytes `level` may hold at once.
    ///
    /// The same two pools as [`crate::bandwidth`]: a premium served strictly
    /// best-first, and a floor divided among the levels the premium did not
    /// reach. See that module for why the boundary test is `>=`.
    pub(crate) fn allowance(&self, level: u8) -> u64 {
        let budget = self.budget();
        if budget == u64::MAX {
            return u64::MAX;
        }
        let floor = (budget as f64 * self.config.floor.clamp(0.0, 1.0) as f64) as u64;
        let premium = budget.saturating_sub(floor);
        let level = (level as usize).min(Priority::LEVELS - 1);

        let better: u64 = self.held[..level].iter().sum();
        let from_premium = premium.saturating_sub(better);

        let mut cumulative = 0u64;
        let mut boundary = Priority::LEVELS;
        for (at, bytes) in self.held.iter().enumerate() {
            cumulative = cumulative.saturating_add(*bytes);
            if cumulative >= premium {
                boundary = at;
                break;
            }
        }

        let worse = self.held[(boundary + 1).min(Priority::LEVELS)..]
            .iter()
            .filter(|bytes| **bytes > 0)
            .count();
        let from_floor = if level > boundary {
            floor / worse.max(1) as u64
        } else if level == boundary && worse == 0 {
            floor
        } else {
            0
        };

        from_premium.saturating_add(from_floor)
    }

    /// The worst level that could still reserve anything.
    fn cutoff(&self) -> u8 {
        for level in 0..Priority::LEVELS {
            let at = level as u8;
            if self.allowance(at) <= self.held[level] {
                return at;
            }
        }
        Priority::LEVELS as u8
    }

    /// Runs the controller if [`Config::interval`] has passed.
    ///
    /// Returns whether it ran, so callers that reconfigure sockets only do so
    /// on a tick.
    pub(crate) fn tick(&mut self, now: Instant) -> bool {
        // The first call establishes the cadence rather than being measured
        // against a zero it just wrote. `get_or_insert` makes `is_some` true
        // before the comparison, so sample the state first.
        let first = self.ticked.is_none();
        let ticked = *self.ticked.get_or_insert(now);
        if !first && now.saturating_duration_since(ticked) < self.config.interval {
            return false;
        }
        self.ticked = Some(now);

        // Where the controller wants to be: nothing held is zero pressure, at
        // or past the setpoint is full pressure.
        let aim = self.config.setpoint.clamp(0.01, 1.0);
        let target = (self.fullness() / aim).clamp(0.0, 1.0);

        // Sheds quickly, returns slowly: too small is slow, too large is an
        // out-of-memory kill.
        let step = if target > self.glide {
            self.config.shrink_step
        } else {
            self.config.grow_step
        };
        self.glide += (target - self.glide) * step.clamp(0.0, 1.0);
        self.glide = self.glide.clamp(0.0, 1.0);
        true
    }

    /// Where the controller has glided to, in `0..=1`.
    pub(crate) fn glide(&self) -> f32 {
        self.glide
    }

    pub(crate) fn usage(&self) -> Usage {
        Usage {
            held: self.held,
            limit: self.config.limit,
            cutoff: self.cutoff(),
        }
    }
}

/// The most flow-control buffering a connection may be granted, from its
/// level's share of what the controller is willing to authorise.
///
/// The counterpart of the bandwidth-delay product: that asks how much a
/// connection needs to keep the link busy, this asks how much the process can
/// afford to let it hold. The connection gets the smaller.
///
/// Halved, since a connection has one of these per direction.
pub(crate) fn window_ceiling<P: ProvideGoalkeeper>(conn: &crate::conn::Conn<P>) -> u64 {
    let level = conn.priority().level();
    conn.provider().limiter.with_process(|_, _, memory| {
        let allowance = memory.allowance(level);
        if allowance == u64::MAX {
            u64::MAX
        } else {
            (allowance / 2).max(1)
        }
    })
}

/// Rounds `bytes` down to a power of two, which is the granularity anything
/// downstream actually honours.
///
/// The kernel rounds these numbers anyway, so a target carried to the byte is
/// precision that never reaches the socket. See the module docs.
pub(crate) fn quantise(bytes: u64) -> u64 {
    if bytes == 0 {
        return 0;
    }
    1u64 << (u64::BITS - 1 - bytes.leading_zeros())
}

/// Whether a newly computed target is different enough from what is applied to
/// be worth a syscall.
///
/// One bucket to shrink, two to grow, the same asymmetry as the glide. Keeps a
/// target sitting on a boundary from flapping every second.
#[cfg(feature = "web_transport")]
pub(crate) fn worth_applying(applied: u64, target: u64) -> bool {
    if applied == 0 {
        return target > 0;
    }
    if target < applied {
        target <= applied / 2
    } else {
        target >= applied.saturating_mul(4)
    }
}

/// Adjusts one configured field, leaving the rest alone.
pub(crate) fn set_config(gk: &Goalkeeper, f: impl FnOnce(&mut Config)) {
    gk.limiter
        .with_process(|_, _, memory| f(&mut memory.config));
}

/// See [`crate::ProvideGoalkeeper::memory_usage`].
pub(crate) fn usage_of(gk: &Goalkeeper) -> Usage {
    gk.limiter.with_process(|_, _, memory| memory.usage())
}

/// Charges `bytes` at `level` to nothing in particular, or refuses.
pub(crate) fn reserve_fixed<P: ProvideGoalkeeper>(
    provider: &P,
    level: u8,
    bytes: u64,
) -> Option<Reservation<P>> {
    provider
        .limiter
        .with_process(|_, _, memory| memory.reserve(level, bytes))?;
    Some(Reservation::fixed(bytes, level, provider.clone()))
}

/// Charges `bytes` to `conn`'s current level, or refuses.
///
/// Booked against the connection rather than the level, so it follows the
/// connection when it is re-levelled. See [`Reservation`].
pub(crate) fn reserve_for<P: ProvideGoalkeeper>(
    conn: &crate::conn::Conn<P>,
    bytes: u64,
) -> Option<Reservation<P>> {
    conn.charge_ram(bytes)?;
    Some(Reservation::attributed(
        bytes,
        conn.clone(),
        conn.provider().clone(),
    ))
}

/// Moves everything a connection holds to the level it is now at, under the
/// ledger's own lock.
///
/// `booked` is where the connection's memory is currently charged and `held` is
/// how much: both are read inside the lock, and `booked` is updated there, so a
/// concurrent charge cannot land between reading the amount and moving it. Two
/// relaxed atomics read outside would let one thread move bytes the other had
/// just added at a different level, and nothing recomputes the ledger from
/// truth afterwards, so the error would be permanent.
///
/// Re-levelling is not an allocation: the memory is already held, and refusing
/// to move it would only leave it misattributed. A level that ends up over its
/// allowance this way is what the controller is for; it reserves nothing more
/// until it is back under.
pub(crate) fn rebook(gk: &Goalkeeper, booked: &AtomicU8, held: &AtomicU64, to: u8) {
    gk.limiter.with_process(|_, _, memory| {
        let from = booked.swap(to, Ordering::Relaxed);
        if from == to {
            return;
        }
        let bytes = held.load(Ordering::Relaxed);
        if bytes == 0 {
            return;
        }
        memory.release(from, bytes);
        memory.force(to, bytes);
    });
}

/// How full the ledger is, for the pressure axis.
pub(crate) fn fullness_of(gk: &Goalkeeper) -> f32 {
    gk.limiter.with_process(|_, _, memory| memory.fullness())
}

/// Runs the controller on the ledger, from the executor's probe.
///
/// Returns whether it ran, and where it has glided to.
pub(crate) fn tick_of(gk: &Goalkeeper) -> (bool, f32) {
    let now = Instant::now();
    gk.limiter.with_process(|_, _, memory| {
        let ran = memory.tick(now);
        (ran, memory.glide())
    })
}

/// How often the controller runs, which is also how long the heartbeat takes to
/// come all the way round.
pub(crate) fn interval_of(gk: &Goalkeeper) -> Duration {
    gk.limiter
        .with_process(|_, _, memory| memory.config.interval)
}

/// How many groups the heartbeat is split across.
///
/// Eight flattens the burst without making a rotation so long that a group
/// waits appreciably longer than the controller's own interval for its turn.
const SHARDS: usize = 8;

/// The controller's heartbeat, for anything that should act on the controller's
/// cadence rather than run a timer of its own.
///
/// # Why it is sharded
///
/// A single beat is a thundering herd: every listener becomes runnable in the
/// same turn, each taking the process lock two or three times, and what it
/// delays is whatever else wanted the schedule at that instant.
///
/// So listeners are dealt round-robin into groups and the groups are beaten in
/// rotation, one per call, spaced `interval / SHARDS` apart. Each listener is
/// still served once per interval, at most an eighth wake together, and no
/// listener holds a timer. The staggering is a property of the rotation rather
/// than of jitter, so it does not decay as connections come and go.
///
/// # Why `watch` and not `Notify`
///
/// A beat must not be missable. `Notify::notify_waiters` stores nothing for a
/// task that is not parked when it fires, so a listener still finishing the
/// previous beat's work would wake a whole rotation late. A
/// [`watch`](tokio::sync::watch) carries a version that is compared rather than
/// awaited, so a receiver that fell behind is told the moment it asks. The
/// value counts beats; only that it changed matters.
pub(crate) struct Heartbeat {
    groups: [tokio::sync::watch::Sender<u64>; SHARDS],
    /// Hands out groups in turn, so listeners spread evenly however they
    /// arrive.
    #[cfg(feature = "web_transport")]
    assign: std::sync::atomic::AtomicUsize,
    /// Where the rotation is, and when it last moved.
    rotation: Mutex<Rotation>,
}

#[derive(Default)]
struct Rotation {
    next: usize,
    /// [`None`] until the first beat, which establishes the cadence rather than
    /// being measured against a zero it just wrote.
    beaten: Option<Instant>,
}

impl Default for Heartbeat {
    fn default() -> Self {
        Self {
            groups: std::array::from_fn(|_| tokio::sync::watch::Sender::new(0)),
            #[cfg(feature = "web_transport")]
            assign: std::sync::atomic::AtomicUsize::new(0),
            rotation: Mutex::new(Rotation::default()),
        }
    }
}

impl Heartbeat {
    /// Joins a group, and returns what to await for its beats.
    ///
    /// Sees every beat after this call and none before it, so a subscriber
    /// cannot be woken for a rotation it was not part of.
    #[cfg(feature = "web_transport")]
    pub(crate) fn subscribe(&self) -> tokio::sync::watch::Receiver<u64> {
        let group = self
            .assign
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.groups[group % SHARDS].subscribe()
    }

    /// Moves the rotation on if this group's turn has come round.
    ///
    /// Called far more often than it beats, so the common path is a lock and a
    /// comparison. Beating cannot fail; `send_modify` does not care whether
    /// anyone is listening.
    pub(crate) fn beat_due(&self, now: Instant, interval: Duration) {
        let step = interval / SHARDS as u32;
        let mut rotation = self.rotation.lock().unwrap();
        if let Some(beaten) = rotation.beaten
            && now.saturating_duration_since(beaten) < step
        {
            return;
        }
        rotation.beaten = Some(now);
        let group = rotation.next;
        rotation.next = (group + 1) % SHARDS;
        // Dropped before waking anyone, since a listener that runs inline would
        // re-enter this on the same thread.
        drop(rotation);
        self.groups[group].send_modify(|beats| *beats = beats.wrapping_add(1));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::executor::priority::UserPriority::*;

    /// Which listeners saw a beat since the last time this was asked, marking
    /// them seen so the next call reports only what is new.
    #[cfg(feature = "web_transport")]
    fn woken(listeners: &mut [tokio::sync::watch::Receiver<u64>]) -> Vec<usize> {
        let mut seen = Vec::new();
        for (index, listener) in listeners.iter_mut().enumerate() {
            if listener.has_changed().unwrap() {
                listener.borrow_and_update();
                seen.push(index);
            }
        }
        seen
    }

    /// The herd is dealt into groups and the groups are beaten in turn, so a
    /// beat wakes a fraction of the listeners rather than all of them.
    #[cfg(feature = "web_transport")]
    #[test]
    fn a_beat_wakes_one_group_and_the_rotation_covers_everyone() {
        let heartbeat = Heartbeat::default();
        // Two per group, so this also sees that a group moves together.
        let mut listeners: Vec<_> = (0..SHARDS * 2).map(|_| heartbeat.subscribe()).collect();
        let interval = Duration::from_secs(8);
        let step = interval / SHARDS as u32;
        let start = Instant::now();

        // The first beat establishes the cadence rather than being measured
        // against a zero it just wrote.
        heartbeat.beat_due(start, interval);
        assert_eq!(
            woken(&mut listeners),
            vec![0, SHARDS],
            "the first group, and both of its members"
        );

        // Before the next group is due, nothing moves.
        heartbeat.beat_due(start + step / 2, interval);
        assert!(woken(&mut listeners).is_empty(), "the rotation moved early");

        heartbeat.beat_due(start + step, interval);
        assert_eq!(woken(&mut listeners), vec![1, SHARDS + 1]);

        // The rest of the rotation, which should reach everyone exactly once.
        for group in 2..SHARDS {
            heartbeat.beat_due(start + step * group as u32, interval);
            assert_eq!(woken(&mut listeners), vec![group, SHARDS + group]);
        }

        // Round again, back to the first group.
        heartbeat.beat_due(start + step * SHARDS as u32, interval);
        assert_eq!(woken(&mut listeners), vec![0, SHARDS]);
    }

    fn ledger(limit: u64) -> Ledger {
        let mut ledger = Ledger::default();
        ledger.config.limit = limit;
        ledger
    }

    #[test]
    fn quantising_rounds_down_to_a_power_of_two() {
        assert_eq!(quantise(0), 0);
        assert_eq!(quantise(1), 1);
        assert_eq!(quantise(1023), 512);
        assert_eq!(quantise(1024), 1024);
        assert_eq!(quantise(1025), 1024);
    }

    /// One bucket down, two up, so a value hovering on a boundary does not
    /// spend a syscall every second.
    #[cfg(feature = "web_transport")]
    #[test]
    fn a_target_on_a_boundary_does_not_flap() {
        assert!(worth_applying(1024, 512), "halving is worth applying");
        assert!(!worth_applying(1024, 1023), "a byte is not");
        assert!(!worth_applying(1024, 2048), "one bucket up is not enough");
        assert!(worth_applying(1024, 4096), "two is");
        assert!(!worth_applying(1024, 768), "within the bucket, either way");
    }

    /// A player outranks a stranger for RAM exactly as it does for the link.
    #[test]
    fn a_stranger_is_cut_off_before_a_player_is() {
        let mut ledger = ledger(1_000_000);
        // The strangers take everything they can.
        let stranger = Priority::New.level();
        while ledger.reserve(stranger, 64 * 1024).is_some() {}
        let player = Priority::User(L0).level();

        // Headroom, not allowance: the question is what each level may still
        // take. The premium is served best-first, so a player arriving after
        // the flood finds it untouched.
        let room = |ledger: &Ledger, level: u8| {
            ledger
                .allowance(level)
                .saturating_sub(ledger.usage().held(Priority::from_level(level)))
        };
        let floor = (ledger.budget() as f64 * ledger.config.floor as f64) as u64;

        assert!(
            room(&ledger, player) > room(&ledger, stranger) * 4,
            "a flood of strangers took the memory a player had not asked for yet"
        );
        assert!(
            room(&ledger, stranger) <= floor,
            "the strangers were held to more than the floor"
        );
        assert!(
            ledger.reserve(player, 64 * 1024).is_some(),
            "the player was refused RAM a flood of strangers had taken"
        );
    }

    /// Being outranked costs a level almost everything but never everything, so
    /// a stranger's handshake can still finish.
    #[test]
    fn the_floor_leaves_the_worst_levels_something() {
        let mut ledger = ledger(1_000_000);
        let player = Priority::User(L0).level();
        // The player takes the whole premium pool.
        while ledger.reserve(player, 64 * 1024).is_some() {}

        assert!(
            ledger.allowance(Priority::New.level()) > 0,
            "a stranger was left no RAM at all, so its handshake can never finish"
        );
    }

    /// Releasing gives the bytes back, and re-booking moves them without asking
    /// whether the destination could have afforded them.
    #[test]
    fn re_booking_moves_bytes_between_levels() {
        let mut ledger = ledger(1_000_000);
        let stranger = Priority::New.level();
        let player = Priority::User(L0).level();
        ledger
            .reserve(stranger, 4096)
            .expect("an empty ledger admits");

        ledger.release(stranger, 4096);
        ledger.force(player, 4096);
        assert_eq!(ledger.total(), 4096, "the bytes were lost or duplicated");
        assert_eq!(
            ledger.usage().held(Priority::New),
            0,
            "the stranger level is still carrying an established player's memory"
        );
        assert_eq!(ledger.usage().held(Priority::User(L0)), 4096);
    }

    /// The controller sheds faster than it returns, and settles rather than
    /// oscillating when occupancy holds steady.
    #[test]
    fn the_controller_sheds_quickly_and_returns_slowly() {
        let mut ledger = ledger(1_000_000);
        let mut now = Instant::now();
        ledger.tick(now);

        // Fill past the setpoint.
        let level = Priority::User(L0).level();
        while ledger.reserve(level, 64 * 1024).is_some() {}

        now += Duration::from_secs(1);
        ledger.tick(now);
        let after_one = ledger.glide();
        assert!(after_one > 0.0, "the controller did not react at all");

        // Steady occupancy settles rather than oscillating.
        let mut previous = after_one;
        for _ in 0..10 {
            now += Duration::from_secs(1);
            ledger.tick(now);
            assert!(
                ledger.glide() >= previous - 0.01,
                "the controller oscillated under steady occupancy"
            );
            previous = ledger.glide();
        }

        // Releasing returns memory, but slowly.
        let held = ledger.total();
        ledger.release(level, held);
        now += Duration::from_secs(1);
        ledger.tick(now);
        assert!(
            ledger.glide() < previous,
            "the controller never gave the memory back"
        );
        assert!(
            ledger.glide() > previous * 0.5,
            "the controller returned memory as fast as it took it"
        );
    }

    /// Below the interval nothing happens, so a caller may poll freely.
    #[test]
    fn the_controller_runs_at_its_own_cadence() {
        let mut ledger = ledger(1_000_000);
        let now = Instant::now();
        assert!(ledger.tick(now), "the first tick establishes the cadence");
        assert!(!ledger.tick(now + Duration::from_millis(100)));
        assert!(ledger.tick(now + Duration::from_secs(1)));
    }
}
