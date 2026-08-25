//! What priority buys, measured against the scheduler it is layered on.
//!
//! Hundreds of tasks are spawned, each assigned one of `N` distinct user
//! priorities at random, and each doing the same small unit of work over and
//! over. The same workload then runs on bare `tokio::spawn`, which has no notion
//! of priority and serves its queue first-come-first-served.
//!
//! Two numbers come out of each run:
//!
//! - **latency (top)**: how long a task at the best priority waits between
//!   asking to be polled again and being polled, at the 99th percentile. What
//!   priority exists to protect, so it should barely move as `N` grows and the
//!   task is outnumbered by worse-priority work.
//! - **throughput (all)**: units of work completed per second across every
//!   task. What priority costs, since picking a task is more work than popping
//!   a queue.
//!
//! `N = 1` is the control. With every task at the same priority there is nothing
//! to order, so the two schedulers are doing the same job and any difference is
//! pure overhead.
//!
//! Assignment is seeded, so both schedulers see the same distribution, and both
//! run on a `current_thread` runtime, since goalkeeper schedules on top of the
//! caller's runtime rather than replacing it.

use goalkeeper::ArcGoalkeeper;
use goalkeeper::executor::priority::{Priority, UserPriority};
use std::hint::black_box;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Enough tasks that the ordering between them matters.
const TASKS: usize = 512;
/// Long enough to cover several of the executor's 100ms windows, so shares
/// refill a few times rather than being measured mid-window.
const RUN: Duration = Duration::from_millis(750);
/// Iterations of the spin below in one unit of work, a few microseconds, so a
/// full round of every task is a couple of milliseconds and a task waiting its
/// turn waits a visible amount of time.
const WORK: u32 = 5_000;

/// The eight user priorities this varies over, best first.
const LEVELS: [UserPriority; 8] = [
    UserPriority::L0,
    UserPriority::L1,
    UserPriority::L2,
    UserPriority::L3,
    UserPriority::L4,
    UserPriority::L5,
    UserPriority::L6,
    UserPriority::L7,
];

/// Seeded so the two schedulers are handed the same assignment. `rand` is not a
/// dependency of this crate and one xorshift is not worth making it one.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
}

/// Which priority each task gets, and which of them count as "top".
fn assignment(n: usize) -> Vec<usize> {
    let mut rng = Rng(0x9E3779B97F4A7C15);
    let mut levels: Vec<usize> = (0..TASKS).map(|_| rng.next() as usize % n).collect();
    // The best level must be occupied for its latency to mean anything. With
    // 512 tasks and at most 8 levels it always would be, but a benchmark that
    // is *usually* measuring something is not measuring anything.
    levels[0] = 0;
    levels
}

/// Burns a few microseconds without touching the allocator or the clock, so
/// what is being measured is scheduling and not `malloc`.
fn spin(iterations: u32) {
    let mut x = 0u64;
    for i in 0..iterations {
        x = x.wrapping_mul(6364136223846793005).wrapping_add(i as u64);
    }
    black_box(x);
}

/// One task: ask to be polled again, note how long that took, do a unit of
/// work, repeat. Returns its own wait times.
async fn worker(stop: Arc<AtomicBool>, done: Arc<AtomicU64>) -> Vec<Duration> {
    let mut waits = Vec::new();
    while !stop.load(Ordering::Relaxed) {
        let asked = Instant::now();
        tokio::task::yield_now().await;
        waits.push(asked.elapsed());

        spin(WORK);
        done.fetch_add(1, Ordering::Relaxed);
    }
    waits
}

struct Report {
    /// 99th percentile wait of the tasks at the best priority.
    top_p99: Duration,
    /// Units of work per second, across every task.
    throughput: f64,
}

fn report(top_waits: Vec<Duration>, done: u64, elapsed: Duration) -> Report {
    let mut waits = top_waits;
    waits.sort_unstable();
    let top_p99 = if waits.is_empty() {
        Duration::ZERO
    } else {
        // Nearest-rank, which needs no interpolation and cannot index past the
        // end.
        let rank = (waits.len() as f64 * 0.99).ceil() as usize;
        waits[rank.saturating_sub(1).min(waits.len() - 1)]
    };
    Report {
        top_p99,
        throughput: done as f64 / elapsed.as_secs_f64(),
    }
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

/// The workload on goalkeeper's executor, with priorities honoured.
fn on_goalkeeper(n: usize) -> Report {
    let levels = assignment(n);
    let stop = Arc::new(AtomicBool::new(false));
    let done = Arc::new(AtomicU64::new(0));
    let counted = Arc::clone(&done);
    // Its own instance, so what is measured is a schedule with nothing else in
    // it.
    let gk = ArcGoalkeeper::new();
    let driven = gk.clone();

    let (top_waits, elapsed) = runtime().block_on(driven.run_until(async move {
        let tasks: Vec<_> = levels
            .iter()
            .map(|&level| {
                let priority = Priority::User(LEVELS[level]);
                let task = gk.spawn(priority, worker(stop.clone(), done.clone()));
                (level, task)
            })
            .collect();

        let started = Instant::now();
        tokio::time::sleep(RUN).await;
        stop.store(true, Ordering::Relaxed);
        let elapsed = started.elapsed();

        let mut top_waits = Vec::new();
        for (level, task) in tasks {
            let waits = task.await;
            if level == 0 {
                top_waits.extend(waits);
            }
        }
        (top_waits, elapsed)
    }));

    report(top_waits, counted.load(Ordering::Relaxed), elapsed)
}

/// The same workload on bare tokio, where the assignment is recorded but
/// ignored, which is the point of the comparison.
fn on_tokio(n: usize) -> Report {
    let levels = assignment(n);
    let stop = Arc::new(AtomicBool::new(false));
    let done = Arc::new(AtomicU64::new(0));
    let counted = Arc::clone(&done);

    let (top_waits, elapsed) = runtime().block_on(async move {
        let tasks: Vec<_> = levels
            .iter()
            .map(|&level| {
                let task = tokio::spawn(worker(stop.clone(), done.clone()));
                (level, task)
            })
            .collect();

        let started = Instant::now();
        tokio::time::sleep(RUN).await;
        stop.store(true, Ordering::Relaxed);
        let elapsed = started.elapsed();

        let mut top_waits = Vec::new();
        for (level, task) in tasks {
            let waits = task.await.unwrap();
            if level == 0 {
                top_waits.extend(waits);
            }
        }
        (top_waits, elapsed)
    });

    report(top_waits, counted.load(Ordering::Relaxed), elapsed)
}

fn main() {
    println!(
        "{TASKS} tasks, {}ms per run, work unit ≈ {WORK} iterations\n",
        RUN.as_millis()
    );
    println!("        latency (top, p99)      throughput (all, kunits/s)");
    println!("  N     goalkeeper     tokio    goalkeeper        tokio");
    println!("  ---   ----------   -------    ----------   ----------");

    for n in 1..=LEVELS.len() {
        let gk = on_goalkeeper(n);
        let tk = on_tokio(n);
        println!(
            "  {n}     {:>8.0?}   {:>7.0?}    {:>10.1}   {:>10.1}",
            gk.top_p99,
            tk.top_p99,
            gk.throughput / 1000.0,
            tk.throughput / 1000.0,
        );
    }
}
