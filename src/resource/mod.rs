//! How close the process is to its limits, along three axes.
//!
//! Each axis is the worse of two sources: what goalkeeper measures for itself,
//! how late its scheduling runs and how much of the bandwidth budget is spent,
//! and what the application reports, memory above all. Goalkeeper resamples
//! every window, so it is what reacts to a burst; a user-supplied value stands
//! until replaced and is never aged out.
//!
//! Scheduling lag rather than whole-machine utilisation, since a game loop that
//! is effectively single-threaded can be entirely saturated on a four-core box
//! that `/proc` calls 25% busy.

pub mod bandwidth;
/// Only TLS and QUIC have crypto to ration, so without them there is no pool
/// and nothing that could take a slot in one.
#[cfg(feature = "tls")]
pub mod handshake;
pub mod ip_limiter;
pub mod memory;

use crate::Goalkeeper;
use std::time::{Duration, Instant};

/// How close each axis is to its limit, from `0.0` (idle) to `1.0` (at it).
///
/// Values above `1.0` are meaningful, twice the budget being `2.0`, and are
/// left unclamped so reporting can tell "just over" from "hopeless".
#[derive(Copy, Clone, Debug, Default, PartialEq)]
pub struct Pressure {
    /// How far behind the schedule is running. Measured internally.
    pub cpu: f32,
    /// How much of the bandwidth budget is spent. Measured internally.
    pub network: f32,
    /// How close memory is to its ceiling. Never measured internally, since the
    /// meaningful ceiling is a deployment's business: a cgroup limit, the host's
    /// RAM, or an application's own budget.
    pub ram: f32,
}

impl Pressure {
    /// The worst axis, which is what admission decisions turn on.
    pub fn worst(&self) -> f32 {
        self.cpu.max(self.network).max(self.ram)
    }

    /// The worst of the axes a computation competes for.
    ///
    /// Network is left out: a saturated uplink says nothing about whether there
    /// is a core to finish a handshake with. It belongs in [`Self::worst`],
    /// where the question is whether to admit another connection.
    pub fn worst_compute(&self) -> f32 {
        self.cpu.max(self.ram)
    }

    /// The worse of each axis, taken independently.
    fn max(self, other: Self) -> Self {
        Self {
            cpu: self.cpu.max(other.cpu),
            network: self.network.max(other.network),
            ram: self.ram.max(other.ram),
        }
    }
}

/// How pressure is derived and when it bites.
///
/// Set through [`crate::Goalkeeper`]'s per-field setters rather than as a
/// struct, so changing one number cannot silently revert another.
#[derive(Copy, Clone, Debug)]
pub(crate) struct Config {
    /// Pressure at which the process is considered strained.
    pub enter: f32,
    /// Pressure at which it stops being considered strained.
    ///
    /// Lower than [`Self::enter`], since shedding load lowers pressure, which
    /// would re-admit and raise it again. The gap is what makes it settle.
    pub leave: f32,
    /// How long a verdict stands before it may flip, however the samples move.
    ///
    /// Guards the same oscillation from the other side, and hides a single
    /// unlucky window.
    pub dwell: Duration,
    /// Weight given to the newest sample, in `0..=1`.
    ///
    /// The rest is carried over, so a lone bad window moves the number a little
    /// and a bad second moves it a lot.
    pub smoothing: f32,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            enter: 0.925,
            leave: 0.875,
            dwell: Duration::from_secs(1),
            // At one sample per 100ms window, roughly a one-second memory.
            smoothing: 0.25,
        }
    }
}

/// How long one bandwidth reading stands before silence is read as idle.
///
/// Not configurable; a property of the ledger's cadence rather than a policy.
const NETWORK_TTL: Duration = Duration::from_secs(1);

/// Owned by [`crate::Goalkeeper`], which is where the lock lives.
pub(crate) struct State {
    config: Config,
    /// Smoothed internal samples. `ram` is always zero here.
    internal: Pressure,
    user: Pressure,
    /// When the ledger last reported. It rolls lazily, off traffic, so without
    /// a TTL a link that saturates and then goes silent would leave its last
    /// reading standing forever.
    network_at: Option<Instant>,
    /// The current verdict, and when it last changed.
    strained: Verdict,
    /// Where the handshake pool has glided to, in `0..=1`.
    ///
    /// A continuous position rather than a verdict, so the pool travels between
    /// its two policies instead of switching. Halving it in one step would
    /// evict a burst of handshakes that were about to finish, costing exactly
    /// the CPU the tightening meant to save.
    ///
    /// Driven by [`Pressure::worst_compute`], so a saturated link does not move
    /// it and a short memory does.
    compute_glide: f32,
    /// The share of the gap closed per tick. Asymmetric in use; see [`glide`].
    glide_step: f32,
    /// The same as [`Self::strained`], over [`Pressure::worst_compute`].
    ///
    /// A verdict of its own, since sharing the hysteresis would let a busy link
    /// hold the crypto pool small after the CPU had recovered, or the reverse.
    compute_strained: Verdict,
}

/// A hysteretic yes-or-no over some measure of pressure.
#[derive(Copy, Clone, Default)]
struct Verdict {
    on: bool,
    since: Option<Instant>,
}

impl Verdict {
    const fn new() -> Self {
        Self {
            on: false,
            since: None,
        }
    }

    /// Re-decides, honouring both thresholds and the dwell.
    fn settle(&mut self, now: Instant, worst: f32, config: &Config) {
        let wants = if self.on {
            worst >= config.leave
        } else {
            worst >= config.enter
        };
        if wants == self.on {
            return;
        }
        if let Some(since) = self.since
            && now.saturating_duration_since(since) < config.dwell
        {
            return;
        }
        self.on = wants;
        self.since = Some(now);
    }
}

impl Default for State {
    fn default() -> Self {
        Self::new()
    }
}

impl State {
    const fn new() -> Self {
        Self {
            config: Config {
                enter: 0.75,
                leave: 0.5,
                dwell: Duration::from_secs(1),
                smoothing: 0.25,
            },
            internal: Pressure {
                cpu: 0.0,
                network: 0.0,
                ram: 0.0,
            },
            user: Pressure {
                cpu: 0.0,
                network: 0.0,
                ram: 0.0,
            },
            network_at: None,
            compute_glide: 0.0,
            glide_step: 0.25,
            strained: Verdict::new(),
            compute_strained: Verdict::new(),
        }
    }

    /// What goalkeeper measured, with a silent ledger read as no traffic.
    fn fresh_internal(&self, now: Instant) -> Pressure {
        let stale =
            !matches!(self.network_at, Some(at) if now.saturating_duration_since(at) < NETWORK_TTL);
        Pressure {
            network: if stale { 0.0 } else { self.internal.network },
            ..self.internal
        }
    }

    fn combined(&self, now: Instant) -> Pressure {
        self.fresh_internal(now).max(self.user)
    }

    /// Folds one sample into `slot`, weighted by [`Config::smoothing`].
    fn smooth(&self, slot: &mut f32, sample: f32) {
        let alpha = self.config.smoothing.clamp(0.0, 1.0);
        *slot = *slot * (1.0 - alpha) + sample * alpha;
    }

    /// Re-decides both verdicts.
    fn settle(&mut self, now: Instant) {
        let combined = self.combined(now);
        self.strained.settle(now, combined.worst(), &self.config);
        self.compute_strained
            .settle(now, combined.worst_compute(), &self.config);
    }
}

fn with_of<R>(gk: &Goalkeeper, f: impl FnOnce(&mut State) -> R) -> R {
    f(&mut gk.pressure.lock().unwrap())
}

/// Adjusts one configured field, leaving the rest alone.
pub(crate) fn set_config(gk: &Goalkeeper, f: impl FnOnce(&mut Config)) {
    with_of(gk, |state| f(&mut state.config));
}

/// Replaces one axis of what the application knows, and re-decides.
pub(crate) fn set_user_axis(gk: &Goalkeeper, f: impl FnOnce(&mut Pressure)) {
    let now = Instant::now();
    with_of(gk, |state| {
        f(&mut state.user);
        state.settle(now);
    });
}

/// See [`crate::ProvideGoalkeeper::internal_pressure`].
pub(crate) fn internal_pressure(gk: &Goalkeeper) -> Pressure {
    let now = Instant::now();
    with_of(gk, |state| state.fresh_internal(now))
}

/// See [`crate::ProvideGoalkeeper::user_pressure`].
pub(crate) fn user_pressure(gk: &Goalkeeper) -> Pressure {
    with_of(gk, |state| state.user)
}

/// See [`crate::ProvideGoalkeeper::pressure`].
pub(crate) fn pressure(gk: &Goalkeeper) -> Pressure {
    let now = Instant::now();
    with_of(gk, |state| state.combined(now))
}

/// See [`crate::ProvideGoalkeeper::strained`].
pub(crate) fn strained_of(gk: &Goalkeeper) -> bool {
    let now = Instant::now();
    with_of(gk, |state| {
        state.settle(now);
        state.strained.on
    })
}

/// The same over CPU and memory alone. See [`Pressure::worst_compute`].
pub(crate) fn compute_strained_of(gk: &Goalkeeper) -> bool {
    let now = Instant::now();
    with_of(gk, |state| {
        state.settle(now);
        state.compute_strained.on
    })
}

/// The process's verdict, for the internals that have no handle to hand.
pub(crate) fn strained() -> bool {
    strained_of(crate::system())
}

/// Reports how late the schedule is running, as a fraction of one window.
///
/// Called once per window by the executor's probe. Zero means the probe woke on
/// time, one that it woke a whole window late.
pub(crate) fn record_cpu_sample_of(gk: &Goalkeeper, late: Duration, window: Duration) {
    let now = Instant::now();
    let sample = if window.is_zero() {
        0.0
    } else {
        late.as_secs_f32() / window.as_secs_f32()
    };
    with_of(gk, |state| {
        let mut cpu = state.internal.cpu;
        state.smooth(&mut cpu, sample);
        state.internal.cpu = cpu;
        state.settle(now);
    });
}

/// Advances the handshake pool's position toward what the pressure warrants.
///
/// Called once per memory-controller tick, the crate's slow cadence, since a
/// pool that resized every hundred milliseconds would react to noise.
///
/// Tightens four times faster than it relaxes: being too small is slow, and
/// being too large is the failure the pool exists to prevent.
pub(crate) fn glide(gk: &Goalkeeper) {
    let now = Instant::now();
    with_of(gk, |state| {
        let enter = state.config.enter.max(0.01);
        let target = (state.combined(now).worst_compute() / enter).clamp(0.0, 1.0);
        let step = if target > state.compute_glide {
            state.glide_step
        } else {
            state.glide_step / 4.0
        };
        state.compute_glide += (target - state.compute_glide) * step.clamp(0.0, 1.0);
        state.compute_glide = state.compute_glide.clamp(0.0, 1.0);
    });
}

/// Where the handshake pool has glided to, in `0..=1`.
///
/// The position is kept whatever the features, since [`glide`] is one number on
/// the controller's tick; only the pool that reads it is behind `tls`.
#[cfg(feature = "tls")]
pub(crate) fn compute_glide_of(gk: &Goalkeeper) -> f32 {
    with_of(gk, |state| state.compute_glide)
}

/// The share of the gap the pool closes per tick when tightening.
#[cfg(feature = "tls")]
pub(crate) fn set_glide_step(gk: &Goalkeeper, step: f32) {
    with_of(gk, |state| state.glide_step = step);
}

/// Reports how full the RAM ledger is, where one is at the limit.
///
/// Called once per controller tick, closing the loop on memory the way
/// [`record_network_sample`] closes it on the link.
///
/// Not smoothed. The other two axes are noisy samples of a rate; this is a
/// direct reading of a stock, and averaging it would only delay the response.
pub(crate) fn record_memory_of(gk: &Goalkeeper, fullness: f32) {
    let now = Instant::now();
    with_of(gk, |state| {
        state.internal.ram = fullness;
        state.settle(now);
    });
}

/// Reports how much of the window's byte budget was spent, in either direction.
///
/// Called once per window by the bandwidth ledger, as it rolls.
pub(crate) fn record_network_sample_of(gk: &Goalkeeper, spent: f32) {
    let now = Instant::now();
    with_of(gk, |state| {
        let mut network = state.internal.network;
        state.smooth(&mut network, spent);
        state.internal.network = network;
        state.network_at = Some(now);
        state.settle(now);
    });
}

/// The process's, for the ledger as it rolls.
pub(crate) fn record_network_sample(spent: f32) {
    record_network_sample_of(crate::system(), spent);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ArcGoalkeeper;

    /// An instance of its own for each test.
    ///
    /// These assert on `internal`, which on the process's instance is written
    /// by the executor's lateness probe whenever another test runs a schedule.
    fn goalkeeper() -> ArcGoalkeeper {
        ArcGoalkeeper::new()
    }

    /// All three axes at once, which only a test wants; the shipped setters are
    /// per axis.
    fn set_user_pressure_all(gk: &ArcGoalkeeper, p: Pressure) {
        gk.set_user_cpu_pressure(p.cpu);
        gk.set_user_network_pressure(p.network);
        gk.set_user_ram_pressure(p.ram);
    }

    #[test]
    fn the_worse_of_the_two_sources_wins_on_each_axis() {
        let gk = goalkeeper();
        with_of(&gk, |state| state.internal.cpu = 0.9);
        set_user_pressure_all(
            &gk,
            Pressure {
                cpu: 0.1,
                network: 0.0,
                ram: 0.8,
            },
        );

        let combined = gk.pressure();
        assert_eq!(combined.cpu, 0.9, "the user must not talk goalkeeper down");
        assert_eq!(combined.ram, 0.8, "only the user knows this axis");
    }

    #[test]
    fn a_user_value_stands_until_it_is_replaced() {
        let gk = goalkeeper();
        set_user_pressure_all(
            &gk,
            Pressure {
                ram: 1.0,
                ..Pressure::default()
            },
        );
        std::thread::sleep(Duration::from_millis(20));
        assert_eq!(
            gk.pressure().ram,
            1.0,
            "a value was aged out rather than believed"
        );

        set_user_pressure_all(&gk, Pressure::default());
        assert_eq!(gk.pressure().ram, 0.0, "clearing it did not clear it");
    }

    #[test]
    fn the_verdict_does_not_chatter_between_the_thresholds() {
        let gk = goalkeeper();
        gk.set_pressure_dwell(Duration::ZERO);

        // Over `enter`, so it engages.
        set_user_pressure_all(
            &gk,
            Pressure {
                ram: 0.8,
                ..Pressure::default()
            },
        );
        assert!(gk.strained());

        // Under `enter` but not under `leave`, so still engaged.
        set_user_pressure_all(
            &gk,
            Pressure {
                ram: 0.6,
                ..Pressure::default()
            },
        );
        assert!(gk.strained(), "fell out at the level that would re-admit");

        set_user_pressure_all(
            &gk,
            Pressure {
                ram: 0.4,
                ..Pressure::default()
            },
        );
        assert!(!gk.strained());
    }

    #[test]
    fn the_dwell_holds_a_verdict_briefly() {
        let gk = goalkeeper();
        gk.set_pressure_dwell(Duration::from_secs(30));
        set_user_pressure_all(
            &gk,
            Pressure {
                ram: 0.9,
                ..Pressure::default()
            },
        );
        assert!(gk.strained());

        set_user_pressure_all(&gk, Pressure::default());
        assert!(gk.strained(), "flipped back within the dwell");
    }

    #[test]
    fn one_bad_window_is_not_an_emergency() {
        let gk = goalkeeper();
        let window = Duration::from_millis(100);

        // A whole window late, once. A single hypervisor hiccup must not read
        // as sustained overload.
        record_cpu_sample_of(&gk, window, window);
        assert!(
            gk.internal_pressure().cpu < Config::default().enter,
            "a lone stall crossed the threshold on its own"
        );

        // Sustained, it gets there.
        for _ in 0..20 {
            record_cpu_sample_of(&gk, window, window);
        }
        assert!(gk.internal_pressure().cpu >= Config::default().enter);
    }

    #[test]
    fn a_saturated_link_registers_as_network_pressure() {
        let gk = goalkeeper();
        for _ in 0..20 {
            record_network_sample_of(&gk, 1.0);
        }
        assert!(gk.internal_pressure().network >= Config::default().enter);
        assert_eq!(gk.internal_pressure().cpu, 0.0, "axes are independent");
    }

    /// A full link strains admission and leaves the crypto pool alone.
    ///
    /// The two verdicts exist to disagree here: shrinking the handshake pool
    /// would shed work that costs CPU and almost no bandwidth.
    #[test]
    fn a_full_link_does_not_shrink_the_crypto_pool() {
        let gk = goalkeeper();
        gk.set_pressure_dwell(Duration::ZERO);

        gk.set_user_network_pressure(0.95);
        assert!(
            gk.strained(),
            "a saturated link is a reason to stop admitting connections"
        );
        assert!(
            !gk.compute_strained(),
            "a saturated link is not a reason to stop finishing handshakes"
        );

        // CPU is, and moves both.
        gk.set_user_cpu_pressure(0.95);
        assert!(gk.compute_strained());
    }
}
