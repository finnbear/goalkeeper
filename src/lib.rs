// `deny` rather than `forbid`, so a named exception is possible at all.
//
// There is exactly one, in `tokio_net`: two `setsockopt` calls for socket
// options neither `std` nor `socket2` wraps. Anything new belongs here, where
// it is visible.
#![deny(unsafe_code)]
#![warn(missing_docs)]

//! DoS and DDoS mitigation utilities.
//!
//! A process has work that matters, a game's tick or an established player's
//! socket, and work a stranger can create at will: a TLS handshake, an HTTP
//! request, a flood of bytes. The second must never crowd out the first, by
//! CPU, bandwidth, memory or sheer number.
//!
//! Everything is reached through [`Goalkeeper`], which owns every budget:
//!
//! - [`executor`] rations **CPU**, a priority scheduler on top of a
//!   caller-supplied tokio runtime. [`executor::priority`] is the ladder it
//!   sorts by.
//! - [`resource`] rations everything a peer can consume: bytes
//!   ([`resource::bandwidth`]), memory ([`resource::memory`]), connections per
//!   address ([`resource::ip_limiter`]) and, under `tls`, concurrent crypto
//!   (`resource::handshake`). The module itself is how close the process is to
//!   each of its limits.
//! - [`conn`] is the per-connection state the rest of it hangs off: the kill
//!   switch, the byte metering, the priority.
//!
#![cfg_attr(
    feature = "http",
    doc = " - [`http`] serves HTTP/1, HTTP/2, HTTPS and WebSockets."
)]
#![cfg_attr(
    feature = "web_transport",
    doc = " - [`web_transport`] serves WebTransport over QUIC."
)]
//!
//! Only the transports are features. The scheduler feeds the pressure the
//! ledgers read and the ledgers are what a connection is metered against, so
//! none of that is separable.
//!
//! Nothing here builds or owns an async runtime; goalkeeper schedules on top of
//! whatever the caller supplies.
//!
//! # One instance, or several
//!
//! A process wants exactly one, since these budgets are the host's. That is
//! [`SystemGoalkeeper`], a zero-sized handle to a `static`. Tests want an
//! instance of their own, so one test's flood is not another's noise; that is
//! [`ArcGoalkeeper`].
//!
//! Both `Deref` to a [`Goalkeeper`], so the API is inherent methods there and
//! `SystemGoalkeeper.set_memory_limit(..)` is the same call as
//! `goalkeeper.set_memory_limit(..)`. [`ProvideGoalkeeper`] holds what hands
//! back something outliving the call: a permit, a session, a slot, a
//! reservation, a server. Each is generic over the provider and remembers which
//! instance issued it, so a guard cannot give its claim back to the wrong one.
//! The parameter defaults to [`SystemGoalkeeper`], which is zero-sized.

pub mod conn;
pub mod executor;
#[cfg(feature = "http")]
pub mod http;
pub mod rate_limiter;
pub mod resource;
pub mod tcp;
pub(crate) mod tokio_net;
#[cfg(feature = "web_transport")]
pub mod web_transport;

use crate::rate_limiter::{RateLimiterProps, Units};
use crate::resource::Pressure;
use crate::resource::bandwidth::Direction;
use crate::resource::ip_limiter::{ActiveSession, ConnectionPermit, IpStats};
use std::net::IpAddr;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};

/// The process's one instance, behind [`SystemGoalkeeper`].
///
/// A unit test that reaches this shares one limiter with every other test in
/// its binary, so their counts, ledgers and pressure bleed together and an
/// assertion passes or fails by running order. The initializer panics under
/// `cfg(test)` to forbid it: a test wanting an instance constructs its own with
/// [`ArcGoalkeeper::new`]. Integration tests, examples and benches build the
/// crate without that cfg and get the real instance, since they exercise the
/// process-wide thing on purpose.
static SYSTEM: LazyLock<Goalkeeper> = LazyLock::new(system_init);

#[cfg(test)]
fn system_init() -> Goalkeeper {
    panic!(
        "a unit test used the process-wide Goalkeeper; construct an ArcGoalkeeper::new() instead"
    )
}

#[cfg(not(test))]
fn system_init() -> Goalkeeper {
    Goalkeeper::default()
}

/// Everything the crate rations, for one process or one test.
///
/// Carries almost the whole API, reached through a [`ProvideGoalkeeper`]'s
/// [`Deref`][std::ops::Deref], so `SystemGoalkeeper.foo()` lands here. Only the
/// operations that mint a guard are on the trait, since those have to know
/// which handle they were reached through.
#[derive(Default)]
pub struct Goalkeeper {
    /// The priority scheduler, which rations CPU.
    pub(crate) executor: crate::executor::Executor,
    /// The per-address limiter, which rations connections and bytes, and,
    /// behind the same lock, the bandwidth ledger, which divides the link
    /// between priorities.
    pub(crate) limiter: crate::resource::ip_limiter::IpLimiter,
    /// Handshake slots, which ration concurrent crypto.
    #[cfg(feature = "tls")]
    pub(crate) handshakes: crate::resource::handshake::HandshakeSemaphore,
    /// One beat per memory-controller tick.
    ///
    /// A governed connection sizes its flow-control windows from what the
    /// controller last decided, so it parks here rather than running a timer of
    /// its own and waking to recompute a number that has not moved.
    pub(crate) controller: crate::resource::memory::Heartbeat,
    /// How close the process is to its limits, and the hysteresis around it.
    ///
    /// Fed by the executor's lateness probe, the ledger's spend and whatever
    /// the application reports; read by the limiter and the handshake pool. The
    /// junction the other three meet at, which is why they share one owner.
    pub(crate) pressure: Mutex<crate::resource::State>,
}

/// A handle to a [`Goalkeeper`], and the operations that need to know which one.
///
/// Almost the whole API is on [`Goalkeeper`] itself and reached through
/// [`Deref`][std::ops::Deref], so `SystemGoalkeeper.set_memory_limit(..)` and
/// `goalkeeper.set_memory_limit(..)` are the same call. Left here are the
/// methods handing back something that outlives the call: a permit, a session,
/// a reservation. Those cannot be inherent, since `Deref` erases which handle
/// they were reached through and a guard has to know which instance to give its
/// claim back to.
///
/// The line between the two halves: does this hand back something that outlives
/// the call? If so it is here, if not it is on [`Goalkeeper`].
///
/// No name may appear on both sides. Inherent methods win method resolution
/// silently, so a collision would shadow the trait without a diagnostic.
/// `Unpin` because a provider is a handle, never something pinned: without it
/// every guard generic over one would infect the types holding it, and a
/// wrapper around a socket could not forward the traits it is driven through.
pub trait ProvideGoalkeeper:
    Clone + Send + Sync + Unpin + 'static + std::ops::Deref<Target = Goalkeeper>
{
    /// Whether a new connection from `ip` is permissible.
    ///
    /// [`Some`] means accept it and hold the permit for its life; [`None`]
    /// means refuse. `label` names the transport for the warning log, e.g.
    /// `"TCP connection"`.
    fn connection_permit(&self, ip: IpAddr, label: &'static str) -> Option<ConnectionPermit<Self>> {
        // Read before the limiter lock, never inside it: the ledger takes the
        // pressure lock when it rolls a window, so taking them the other way
        // round here would be a lock-order inversion. Passed in rather than
        // read from within, so the limiter answers about this instance.
        let strained = self.strained();
        let ip = self
            .limiter
            .with(|limiter| limiter.connection_permit(ip, label, strained))?;
        Some(ConnectionPermit::new(ip, self.clone()))
    }

    /// Marks `ip` as carrying meaningful activity for as long as the guard
    /// lives.
    ///
    /// This is what earns an address a larger allowance, so take one only once
    /// something has established the session is real.
    fn active_session(&self, ip: IpAddr) -> ActiveSession<Self> {
        self.limiter.with(|limiter| limiter.enter_session(ip));
        ActiveSession::new(ip, self.clone())
    }

    /// Claims a slot for a handshake from `ip` that arrived at `accepted`.
    ///
    /// [`None`] means there was no room and nothing evictable: every handshake
    /// in flight is fast, so none deserves to be cancelled for a newcomer.
    ///
    /// `accepted` is when the connection arrived rather than when the task
    /// carrying it was scheduled, so time spent waiting its turn counts against
    /// it.
    #[cfg(feature = "tls")]
    fn handshake_slot(
        &self,
        ip: IpAddr,
        accepted: Instant,
    ) -> Option<crate::resource::handshake::Slot<Self>> {
        crate::resource::handshake::slot(self, ip, accepted)
    }

    /// Reserves `bytes` that belong to no connection, or refuses.
    ///
    /// For an application's own structures. Anything belonging to a connection
    /// should go through [`crate::conn::Conn::try_reserve`] instead, so that
    /// priority applies to it.
    fn try_reserve(&self, bytes: u64) -> Option<crate::resource::memory::Reservation<Self>> {
        crate::resource::memory::reserve_fixed(
            self,
            crate::executor::priority::Priority::Main.level(),
            bytes,
        )
    }
}

/// Everything that does not need to know which handle it was reached through.
impl Goalkeeper {
    // ------------------------------------------------------------ addresses

    /// Records `bytes` moved by `ip` in `dir`, updating whether it is over its
    /// allowance that way.
    pub fn record_address_bandwidth(&self, ip: IpAddr, dir: Direction, bytes: Units) {
        let now = Instant::now();
        self.limiter
            .with(|limiter| limiter.record_bandwidth(ip, dir, bytes, now));
    }

    /// Whether `ip` is currently over its allowance in `dir`.
    pub fn address_over_bandwidth(&self, ip: IpAddr, dir: Direction) -> bool {
        self.limiter.with(|limiter| limiter.over_bandwidth(ip, dir))
    }

    /// Rate limits some custom, expensive action per address. `true` means
    /// block it.
    pub fn should_limit_custom(&self, ip: IpAddr, usage: Units) -> bool {
        let now = Instant::now();
        self.limiter
            .with(|limiter| limiter.should_limit_custom(ip, usage, now))
    }

    /// Visits the statistics for each tracked address. The visitor must not
    /// block.
    pub fn address_stats(&self, mut visitor: impl FnMut(IpAddr, IpStats)) {
        self.limiter.with(|limiter| {
            for (ip, stats) in limiter.stats() {
                visitor(ip, stats);
            }
        })
    }

    /// Outstanding [`ConnectionPermit`]s across all addresses.
    pub fn total_connections(&self) -> u32 {
        self.limiter.with(|limiter| limiter.total_connections())
    }

    /// Connections the limiter was asked about, and how many it withheld, since
    /// this was last asked.
    ///
    /// Reading resets, so consecutive readings partition the time between them.
    /// Nothing depends on it being called, but there should be one caller: a
    /// second would silently take part of the first's window.
    pub fn permit_counts(&self) -> (u32, u32) {
        self.limiter.with(|limiter| limiter.take_permit_counts())
    }

    /// Bytes per second one address may move before being throttled, and how
    /// many in a burst, both before scaling for active sessions.
    ///
    /// The rate must be under a billion: a period is derived by dividing a
    /// second by it, and above that the period rounds to nothing.
    ///
    /// Default: `500_000`, `1_000_000`
    pub fn set_address_bandwidth_limits(&self, bytes_per_second: Units, bytes_burst: Units) {
        self.limiter
            .with(|limiter| limiter.set_bandwidth_limits(bytes_per_second, bytes_burst));
    }

    /// How much of the base allowance each active session adds.
    ///
    /// One means an address with three sessions gets four times the base. Zero
    /// disables scaling.
    ///
    /// Default: `1`
    pub fn set_per_active_session(&self, factor: u32) {
        self.limiter
            .with(|limiter| limiter.set_per_active_session(factor));
    }

    /// Connections per active session an address may hold, ordinarily and for
    /// the rare address that has earned the benefit of the doubt.
    ///
    /// For an HTTP/1-only server, 4–6; for HTTP/2 with HTTP/1 WebSockets, 2;
    /// for HTTP/2 throughout, 1.
    ///
    /// Default: `1`, `6`
    pub fn set_connections_per_active(&self, p90: u32, p99: u32) {
        self.limiter
            .with(|limiter| limiter.set_connections_per_active(p90, p99));
    }

    /// Connections across all addresses before each address is afforded fewer,
    /// and before new ones are refused outright.
    ///
    /// Default: `1000`, `2000`
    pub fn set_total_connection_limits(&self, soft: u32, hard: u32) {
        self.limiter
            .with(|limiter| limiter.set_total_connection_limits(soft, hard));
    }

    /// How long an incident is remembered.
    ///
    /// Default: `5m`
    pub fn set_ddos_memory(&self, memory: Duration) {
        self.limiter.with(|limiter| limiter.set_ddos_memory(memory));
    }

    /// The rate limit [`Self::should_limit_custom`] applies, for whatever the
    /// caller finds expensive.
    ///
    /// Default: no limit
    pub fn set_custom_limit(&self, props: RateLimiterProps) {
        self.limiter.with(|limiter| limiter.set_custom_limit(props));
    }

    // ------------------------------------------------------------- pressure

    /// How close the process is to its limits, the worse of what goalkeeper
    /// measured and what the application reported, per axis.
    pub fn pressure(&self) -> Pressure {
        crate::resource::pressure(self)
    }

    /// What goalkeeper measured for itself, smoothed. `ram` is always zero.
    pub fn internal_pressure(&self) -> Pressure {
        crate::resource::internal_pressure(self)
    }

    /// What the application last supplied.
    pub fn user_pressure(&self) -> Pressure {
        crate::resource::user_pressure(self)
    }

    /// Whether the process is currently considered strained, which tightens
    /// admission and the handshake pool before any count alone would.
    ///
    /// Hysteretic: crossing the upper threshold turns this on and only falling
    /// below the lower one turns it off, no sooner than the dwell after the
    /// last change. May be read as often as a caller likes without chattering.
    pub fn strained(&self) -> bool {
        crate::resource::strained_of(self)
    }

    /// Whether the process is short of what a computation needs: CPU and
    /// memory, but not link.
    ///
    /// The verdict the handshake pool is sized against, since a handshake is
    /// expensive in CPU and nearly free on the wire. See
    /// [`crate::resource::Pressure::worst_compute`], and prefer
    /// [`Self::strained`] for anything whose cost is mostly bytes.
    pub fn compute_strained(&self) -> bool {
        crate::resource::compute_strained_of(self)
    }

    /// What the application knows about how far behind the schedule is.
    ///
    /// Each axis is optional in effect: one left at zero loses to goalkeeper's
    /// own measurement, so an application that only tracks memory sets that
    /// alone. What is set stands until it is set again.
    ///
    /// Default: `0.0`
    pub fn set_user_cpu_pressure(&self, pressure: f32) {
        crate::resource::set_user_axis(self, |user| user.cpu = pressure);
    }

    /// What the application knows about how much of the link is spent. See
    /// [`Self::set_user_cpu_pressure`].
    ///
    /// Default: `0.0`
    pub fn set_user_network_pressure(&self, pressure: f32) {
        crate::resource::set_user_axis(self, |user| user.network = pressure);
    }

    /// How close memory is to its ceiling.
    ///
    /// The one axis goalkeeper never measures for itself, since the meaningful
    /// ceiling is a deployment's: a cgroup limit, the host's RAM, or an
    /// application's own budget.
    ///
    /// Default: `0.0`
    pub fn set_user_ram_pressure(&self, pressure: f32) {
        crate::resource::set_user_axis(self, |user| user.ram = pressure);
    }

    /// Pressure at which the process is considered strained, and at which it
    /// stops being, applied to every axis at once.
    ///
    /// The second is lower, since shedding load lowers pressure, which would
    /// re-admit and raise it again. The gap is what makes it settle; `enter`
    /// below `leave` is a bug and asserts in debug.
    ///
    /// Each axis otherwise carries its own band, since they are not alike. This
    /// flattens the three to one and so discards that distinction; to keep it,
    /// set the axes individually with [`Self::set_cpu_pressure_thresholds`] and
    /// its siblings.
    ///
    /// Default: CPU `0.925`/`0.875`, RAM `0.8`/`0.75`, network `0.925`/`0.875`
    pub fn set_pressure_thresholds(&self, enter: f32, leave: f32) {
        let band = crate::resource::Thresholds::new(enter, leave);
        crate::resource::set_config(self, |config| {
            config.cpu = band;
            config.ram = band;
            config.network = band;
        });
    }

    /// The strain band for scheduling lateness alone. See
    /// [`Self::set_pressure_thresholds`] for the shape of the pair.
    ///
    /// Default: `0.925`/`0.875`
    pub fn set_cpu_pressure_thresholds(&self, enter: f32, leave: f32) {
        let band = crate::resource::Thresholds::new(enter, leave);
        crate::resource::set_config(self, |config| config.cpu = band);
    }

    /// The strain band for memory alone. See
    /// [`Self::set_pressure_thresholds`] for the shape of the pair.
    ///
    /// Default: `0.8`/`0.75`
    pub fn set_ram_pressure_thresholds(&self, enter: f32, leave: f32) {
        let band = crate::resource::Thresholds::new(enter, leave);
        crate::resource::set_config(self, |config| config.ram = band);
    }

    /// The strain band for the bandwidth budget alone. See
    /// [`Self::set_pressure_thresholds`] for the shape of the pair.
    ///
    /// The budget is set under the wire, so a value over one is a link over its
    /// budget rather than over its capacity; a band may sit there deliberately.
    ///
    /// Default: `0.925`/`0.875`
    pub fn set_network_pressure_thresholds(&self, enter: f32, leave: f32) {
        let band = crate::resource::Thresholds::new(enter, leave);
        crate::resource::set_config(self, |config| config.network = band);
    }

    /// How long a verdict stands before it may flip, however the samples move.
    ///
    /// Guards the same oscillation from the other side, and hides one unlucky
    /// window.
    ///
    /// Default: `1s`
    pub fn set_pressure_dwell(&self, dwell: Duration) {
        crate::resource::set_config(self, |config| config.dwell = dwell);
    }

    /// Weight given to the newest sample, in `0..=1`.
    ///
    /// The rest is carried over, so one bad window moves the number a little
    /// and a bad second moves it a lot.
    ///
    /// Default: `0.25`, roughly a one-second memory
    pub fn set_pressure_smoothing(&self, smoothing: f32) {
        crate::resource::set_config(self, |config| config.smoothing = smoothing);
    }

    // ------------------------------------------------------------- schedule

    /// Spawns `future` at `priority`.
    pub fn spawn<F>(
        &self,
        priority: crate::executor::priority::Priority,
        future: F,
    ) -> async_task::Task<F::Output>
    where
        F: std::future::Future + Send + 'static,
        F::Output: Send + 'static,
    {
        self.executor.spawn(priority, future)
    }

    /// Like [`Self::spawn`], but joining an existing priority handle so the new
    /// task moves with everything else serving that connection.
    pub fn spawn_with<F>(
        &self,
        priority: crate::executor::priority::SharedPriority,
        future: F,
    ) -> async_task::Task<F::Output>
    where
        F: std::future::Future + Send + 'static,
        F::Output: Send + 'static,
    {
        self.executor.spawn_with(priority, future)
    }

    /// Drives the schedule until `future` completes.
    ///
    /// Nothing here owns a runtime: this is a future, and it is the caller's
    /// `block_on` that turns it.
    pub fn run_until<F: std::future::Future>(
        &self,
        future: F,
    ) -> impl std::future::Future<Output = F::Output> {
        self.executor.run_until(self, future)
    }

    /// Live task counts, for whoever reports on the process.
    pub fn tasks(&self) -> crate::executor::Tasks {
        self.executor.tasks()
    }

    /// How often shares bit, and the start of a fresh measurement window.
    ///
    /// Reading resets. See [`Self::permit_counts`].
    pub fn throttling(&self) -> crate::executor::Throttling {
        self.executor.throttling()
    }

    /// How long a share lasts before it is refilled.
    ///
    /// Sets how finely cumulative hogging is punished and how long a punished
    /// task waits. Does not bound aggregate CPU or protect the root task, which
    /// is preemption's job.
    ///
    /// Default: `100ms`
    pub fn set_schedule_window(&self, window: Duration) {
        self.executor
            .set_config_with(|config| config.window = window);
    }

    /// How many equal shares of a window one task may take.
    ///
    /// An equal split is the wrong ceiling because activity is not: a handshake
    /// mid-negotiation legitimately wants several polls where a task idling on
    /// a socket wants one.
    ///
    /// Default: `4`
    pub fn set_oversubscribe(&self, shares: u32) {
        self.executor
            .set_config_with(|config| config.oversubscribe = shares);
    }

    /// Consecutive windows a task must exhaust its share in before losing that
    /// headroom.
    ///
    /// More than one, since a host that stalls charges the whole stall to
    /// whichever task happened to be mid-poll.
    ///
    /// Default: `3`
    pub fn set_penalty_windows(&self, windows: u32) {
        self.executor
            .set_config_with(|config| config.penalty_windows = windows);
    }

    /// How long a queue's head waits before it may be served out of turn, and
    /// the interval that doubling is measured in.
    ///
    /// Default: `100ms`
    pub fn set_aging_base(&self, base: Duration) {
        self.executor
            .set_config_with(|config| config.aging_base = base);
    }

    /// Fraction of a window that may be spent on tasks running only because
    /// they aged, so a cohort that ages together cannot take the schedule over.
    ///
    /// Default: `0.1`
    pub fn set_override_budget(&self, fraction: f32) {
        self.executor
            .set_config_with(|config| config.override_budget = fraction);
    }

    // ----------------------------------------------------------- handshakes
    //
    // Behind `tls`, since the pool rations crypto and a plaintext listener has
    // none: without it these would report zero forever and configure something
    // nothing consults.

    /// What has happened to handshakes since this was last asked, and the start
    /// of a fresh window.
    ///
    /// Reading resets, so consecutive readings partition the time between them.
    /// Nothing depends on it being called, but there should be one caller: a
    /// second would silently take part of the first's window.
    #[cfg(feature = "tls")]
    pub fn handshake_counts(&self) -> crate::resource::handshake::Counts {
        crate::resource::handshake::counts(self)
    }

    /// Handshakes allowed in flight at once, unloaded and under pressure.
    ///
    /// Not a cap on connections, which the per-address limiter bounds. The pool
    /// glides between the two rather than switching, so they are the ends of a
    /// range, and every handshake setting moves with them: a smaller pool with
    /// unchanged patience sheds more legitimate traffic, not less.
    ///
    /// Default: `32`, `16`
    #[cfg(feature = "tls")]
    pub fn set_handshake_capacity(&self, normal: usize, pressured: usize) {
        crate::resource::handshake::set_policy(self, |p, pressed| {
            p.capacity = if pressed { pressured } else { normal }
        });
    }

    /// How long a handshake may go unfinished before the next arrival reaps it,
    /// whether or not its slot is wanted.
    ///
    /// Generous, since a client on a slow link legitimately needs a second or
    /// two.
    ///
    /// Default: `15s`, `3s`
    #[cfg(feature = "tls")]
    pub fn set_handshake_deadline(&self, normal: Duration, pressured: Duration) {
        crate::resource::handshake::set_policy(self, |p, pressed| {
            p.deadline = if pressed { pressured } else { normal }
        });
    }

    /// How long a handshake may take before it becomes evictable.
    ///
    /// Comfortably longer than the round trip or two a real one costs.
    ///
    /// Default: `1s`, `500ms`
    #[cfg(feature = "tls")]
    pub fn set_handshake_slow(&self, normal: Duration, pressured: Duration) {
        crate::resource::handshake::set_policy(self, |p, pressed| {
            p.slow = if pressed { pressured } else { normal }
        });
    }

    /// Slow handshakes one address may hold at once.
    ///
    /// Qualified on slow, since an unqualified cap would punish a browser
    /// opening several connections at once or a NAT presenting thousands of
    /// clients as one address.
    ///
    /// Default: `2`, `2`
    #[cfg(feature = "tls")]
    pub fn set_handshake_slow_per_ip(&self, normal: usize, pressured: usize) {
        crate::resource::handshake::set_policy(self, |p, pressed| {
            p.slow_per_ip = if pressed { pressured } else { normal }
        });
    }

    // ------------------------------------------------------------ bandwidth

    /// What the ledger has seen this window, for whoever reports on the
    /// process.
    pub fn bandwidth_usage(&self) -> crate::resource::bandwidth::Usage {
        crate::resource::bandwidth::usage_of(self)
    }

    /// Bytes the whole process may move in `dir` in one window.
    ///
    /// For a caller dividing that among connections rather than asking about
    /// one, such as a session bounded before it has moved anything and so with
    /// no ration to consult.
    pub fn budget_per_window(&self, dir: Direction) -> u64 {
        crate::resource::bandwidth::budget_per_window_of(self, dir)
    }

    /// How long a ration lasts, for a caller pacing itself against one.
    pub fn bandwidth_window(&self) -> Duration {
        crate::resource::bandwidth::window_of(self)
    }

    /// Which window the ledger is in.
    ///
    /// For a caller that reconfigures something once per window rather than
    /// once per operation, such as a socket option whose syscall costs more
    /// than the precision is worth.
    pub fn bandwidth_epoch(&self) -> u64 {
        crate::resource::bandwidth::epoch_of(self)
    }

    /// Bytes per second the host may send, and may receive.
    ///
    /// Set these under the link rather than equal to it, at the rate below
    /// which congestion on the local physical link is insignificant.
    ///
    /// A link at its limit queues and then drops. Queueing is latency for
    /// everyone on the link, including the traffic goalkeeper is protecting,
    /// and dropping costs more capacity than the discarded packet as well as
    /// collapsing congestion windows for connections that did nothing wrong.
    /// Neither respects priority.
    ///
    /// So the budget has to run out before the wire does, and the shortfall is
    /// divided here rather than by a queue upstream. The headroom is the price.
    ///
    /// Default: `112_500_000`, `4_000_000_000`, being 90% and 80% of the 40/1
    /// Gbps a cheap VPS is typically allocated.
    pub fn set_bandwidth_limits(&self, tx_bytes_per_second: u64, rx_bytes_per_second: u64) {
        crate::resource::bandwidth::set_config(self, |config| {
            config.max_tx_bytes_per_second = tx_bytes_per_second;
            config.max_rx_bytes_per_second = rx_bytes_per_second;
        });
    }

    /// The share of the link the levels below the cutoff divide between them.
    ///
    /// Priority without a floor is starvation: a stranger's handshake still has
    /// to complete, or it holds a slot and a permit forever.
    ///
    /// Default: `0.1`
    pub fn set_bandwidth_floor(&self, fraction: f32) {
        crate::resource::bandwidth::set_config(self, |config| config.floor = fraction);
    }

    /// How long a bandwidth budget lasts before it is refilled.
    ///
    /// Shorter reacts faster and parks for less time; longer tolerates burstier
    /// traffic.
    ///
    /// Default: `100ms`
    pub fn set_bandwidth_window(&self, window: Duration) {
        crate::resource::bandwidth::set_config(self, |config| config.window = window);
    }

    // --------------------------------------------------------------- memory

    /// What the RAM ledger is holding, for whoever reports on the process.
    pub fn memory_usage(&self) -> crate::resource::memory::Usage {
        crate::resource::memory::usage_of(self)
    }

    /// What goalkeeper may authorise in total.
    ///
    /// Authorised, not resident: this bounds the buffers goalkeeper configures
    /// and the reservations it hands out. It does not own the allocator, so a
    /// true ceiling is still a cgroup; report that through
    /// [`Self::set_user_ram_pressure`] and both are respected.
    ///
    /// Default: unlimited, since a guess would be wrong on most hosts
    pub fn set_memory_limit(&self, bytes: u64) {
        crate::resource::memory::set_config(self, |config| config.limit = bytes);
    }

    /// The share of the limit the controller aims to stay under.
    ///
    /// Under one, so buffers begin descending before anything is refused, while
    /// giving slack back is still cheap.
    ///
    /// Default: `0.8`
    pub fn set_memory_setpoint(&self, fraction: f32) {
        crate::resource::memory::set_config(self, |config| config.setpoint = fraction);
    }

    /// The share of the limit reserved for the levels below the cutoff.
    ///
    /// Being outranked should cost a connection almost all its buffers, never
    /// quite all of them: a stranger whose handshake can never finish holds its
    /// slot and its permit forever.
    ///
    /// Default: `0.1`
    pub fn set_memory_floor(&self, fraction: f32) {
        crate::resource::memory::set_config(self, |config| config.floor = fraction);
    }

    /// How often the memory controller runs.
    ///
    /// Slower than the bandwidth epoch, since memory is a stock rather than a
    /// flow and chasing it faster would spend a `setsockopt` per socket per
    /// direction on noise.
    ///
    /// Default: `1s`
    pub fn set_memory_interval(&self, interval: Duration) {
        crate::resource::memory::set_config(self, |config| config.interval = interval);
    }

    /// The share of the gap to the target closed per tick when shedding memory,
    /// and when returning it.
    ///
    /// Asymmetric by design, the second the smaller: a buffer that is too small
    /// is slow, and one that is too large is an out-of-memory kill.
    ///
    /// Default: `0.5`, `0.1`
    pub fn set_memory_steps(&self, shrink: f32, grow: f32) {
        crate::resource::memory::set_config(self, |config| {
            config.shrink_step = shrink;
            config.grow_step = grow;
        });
    }

    /// The share of the gap the handshake pool closes per tick when tightening.
    ///
    /// The pool glides between its unloaded and pressured settings rather than
    /// switching, so a burst does not evict handshakes that were about to
    /// finish. It relaxes at a quarter of this.
    ///
    /// Default: `0.25`
    #[cfg(feature = "tls")]
    pub fn set_handshake_glide_step(&self, step: f32) {
        crate::resource::set_glide_step(self, step);
    }

    /// How long a connection may spend over its byte ration, while being
    /// throttled, before it is killed rather than merely slowed.
    ///
    /// Backpressure is the ordinary answer; this is the escalation for a peer
    /// that ignores it. [`None`] never kills.
    ///
    /// Default: `Some(5s)`
    pub fn set_bandwidth_kill_after(&self, after: Option<Duration>) {
        crate::resource::bandwidth::set_config(self, |config| config.kill_after = after);
    }
}

/// The process's [`Goalkeeper`], as a handle that costs nothing to hold.
///
/// Zero-sized, so a guard parameterised on this is exactly as large as it would
/// be without the parameter at all.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, Hash)]
pub struct SystemGoalkeeper;

/// The borrow is a known address, so reaching the ledger through this compiles
/// to nothing at all.
impl std::ops::Deref for SystemGoalkeeper {
    type Target = Goalkeeper;

    fn deref(&self) -> &Goalkeeper {
        &SYSTEM
    }
}

impl ProvideGoalkeeper for SystemGoalkeeper {}

/// An instance of its own, for tests and for callers with two independent
/// workloads.
///
/// Cloning shares one instance. Guards parameterised on this hold a clone, so
/// an instance outlives every permit, session and connection it issued.
#[derive(Clone, Debug, Default)]
pub struct ArcGoalkeeper(Arc<Goalkeeper>);

impl ArcGoalkeeper {
    /// A [`Goalkeeper`] of its own, sharing nothing with any other.
    pub fn new() -> Self {
        Self::default()
    }
}

impl std::ops::Deref for ArcGoalkeeper {
    type Target = Goalkeeper;

    fn deref(&self) -> &Goalkeeper {
        &self.0
    }
}

impl ProvideGoalkeeper for ArcGoalkeeper {}

impl std::fmt::Debug for Goalkeeper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Opaque, since every field is behind a lock and a `Debug` that took
        // them would deadlock whoever printed one while holding it.
        f.debug_struct("Goalkeeper").finish_non_exhaustive()
    }
}
