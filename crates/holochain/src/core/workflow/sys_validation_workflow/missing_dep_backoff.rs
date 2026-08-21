//! Retry scheduling for sys validation dependencies that cannot be found.
//!
//! Sys validation holds an in-memory map of the dependencies needed by the ops currently awaiting
//! validation. Dependencies that are not held locally are re-checked locally and re-fetched from
//! the network on every pass of the workflow.
//!
//! That is the right behaviour for a dependency that is simply late: it will show up within a few
//! seconds and the op can be validated. It is pathological for a dependency that *cannot* be
//! found: an op referencing an action that no living chain holds, which is what is left behind by
//! a re-key, or by a chain that never gossiped. Those dependencies never resolve, so the workflow
//! re-checks every one of them, every retry interval, forever. On a node holding thousands of such
//! ops that is a spin, not a workload: the local re-checks saturate the database read pool and the
//! network fetches produce a `NoPeersForLocation` per dependency per interval.
//!
//! [`MissingDepRetry`] gives each missing dependency its own exponential backoff so that the cost
//! of a dependency that keeps failing decays towards zero.
//!
//! Each missing dependency carries two independent schedules, each advanced only by its own
//! failures:
//!
//! - the **local re-check** schedule, capped at [`MAX_LOCAL_RECHECK_DELAY`]. This bounds how long
//!   it can take to notice that a dependency has arrived by some other route (gossip, publish,
//!   another op being integrated), so the cap is deliberately short.
//! - the **network fetch** schedule, capped at [`MAX_NETWORK_RETRY_DELAY`]. A network fetch for a
//!   dependency that has already failed many times is the expensive, futile half, so its cap is
//!   long.
//!
//! Both start due immediately, so a dependency that is merely late is looked for on the very first
//! pass exactly as it was before, and the first few retries are still at the base interval. Only a
//! dependency that keeps failing decays towards the caps.
//!
//! After [`UNFETCHABLE_ATTEMPT_BUDGET`] failed *network* fetches a dependency is reported as
//! *unfetchable*. That is a reporting state, not a decision about the data: the dependency keeps
//! being swept at the capped intervals, and the ops that need it stay in `AwaitingSysDeps`. Nothing
//! is dropped and nothing is treated as valid. The conductor stops paying full price for it, and
//! says so.

use std::time::{Duration, Instant};

/// The longest a missing dependency will go without being re-checked against the local databases.
///
/// This bounds how stale the workflow's view of a dependency can be when the dependency arrives by
/// a route other than the workflow's own fetch, so it is deliberately short.
pub const MAX_LOCAL_RECHECK_DELAY: Duration = Duration::from_secs(60);

/// The longest a missing dependency will go without being re-fetched from the network.
pub const MAX_NETWORK_RETRY_DELAY: Duration = Duration::from_secs(60 * 60);

/// The number of failed network fetches after which a dependency is reported as unfetchable.
///
/// With the default 10s base the delays run 10s, 20s, 40s ... capped at an hour, so this is
/// reached after roughly three hours of failing to find the dependency anywhere on the network.
pub const UNFETCHABLE_ATTEMPT_BUDGET: u32 = 12;

/// The fraction by which a computed delay is randomly shortened or lengthened.
///
/// Jitter matters here because the whole missing set fails together, so without it every
/// dependency would come due in the same instant and reproduce the storm in bursts.
pub const JITTER_FRACTION: f64 = 0.25;

/// The base delay used when a caller has no configured sys validation retry delay to hand.
pub const DEFAULT_RETRY_BASE: Duration = Duration::from_secs(10);

/// Exponential backoff delay for the `attempts`-th failure, capped at `cap`.
///
/// `attempts` is 1-based: the delay after the first failure is `base`.
pub fn backoff_delay(base: Duration, attempts: u32, cap: Duration) -> Duration {
    if attempts == 0 {
        return Duration::ZERO;
    }

    // Saturate rather than overflow. Any shift beyond the cap lands on the cap anyway.
    let shift = (attempts - 1).min(31);
    let multiplier = 1u32 << shift;

    match base.checked_mul(multiplier) {
        Some(delay) => delay.min(cap),
        None => cap,
    }
}

/// Apply [`JITTER_FRACTION`] jitter to a delay.
///
/// `r` is expected in `[0.0, 1.0)`; `r == 0.5` leaves the delay unchanged.
pub fn apply_jitter(delay: Duration, r: f64) -> Duration {
    let factor = 1.0 + JITTER_FRACTION * (2.0 * r.clamp(0.0, 1.0) - 1.0);
    delay.mul_f64(factor)
}

/// The retry schedule for a single dependency that is not held locally.
#[derive(Clone, Debug)]
pub struct MissingDepRetry {
    /// How many local searches for this dependency have come back empty.
    local_misses: u32,
    /// How many network fetches for this dependency have come back empty.
    network_misses: u32,
    /// The earliest instant at which the local databases should be searched again.
    next_local_recheck: Instant,
    /// The earliest instant at which the network should be asked again.
    next_network_attempt: Instant,
    /// Whether the transition to unfetchable has already been reported.
    reported_unfetchable: bool,
}

impl MissingDepRetry {
    /// A dependency we have just discovered to be missing. Both schedules are due immediately.
    pub fn new(now: Instant) -> Self {
        Self {
            local_misses: 0,
            network_misses: 0,
            next_local_recheck: now,
            next_network_attempt: now,
            reported_unfetchable: false,
        }
    }

    /// The number of local searches that came back empty.
    pub fn local_misses(&self) -> u32 {
        self.local_misses
    }

    /// The number of network fetches that came back empty.
    pub fn network_misses(&self) -> u32 {
        self.network_misses
    }

    /// Whether the local databases should be searched for this dependency now.
    pub fn due_for_local_recheck(&self, now: Instant) -> bool {
        now >= self.next_local_recheck
    }

    /// Whether the network should be asked for this dependency now.
    pub fn due_for_network_fetch(&self, now: Instant) -> bool {
        now >= self.next_network_attempt
    }

    /// Whether this dependency has failed often enough to be reported as unfetchable.
    ///
    /// Being unfetchable does not drop the dependency or resolve the ops that need it. It means the
    /// conductor has stopped paying full price to look for it, and can say so.
    pub fn is_unfetchable(&self) -> bool {
        self.network_misses >= UNFETCHABLE_ATTEMPT_BUDGET
    }

    /// Record that a local search for this dependency came back empty.
    pub fn record_local_miss(&mut self, now: Instant, base: Duration) {
        self.record_local_miss_with_jitter(now, base, rand::random::<f64>())
    }

    /// [`Self::record_local_miss`] with the jitter source injected, for deterministic tests.
    pub fn record_local_miss_with_jitter(&mut self, now: Instant, base: Duration, r: f64) {
        self.local_misses = self.local_misses.saturating_add(1);
        self.next_local_recheck = now
            + apply_jitter(
                backoff_delay(base, self.local_misses, MAX_LOCAL_RECHECK_DELAY),
                r,
            );
    }

    /// Record that a network fetch for this dependency came back empty.
    ///
    /// Returns `true` if this failure is the transition into the unfetchable state, so that the
    /// caller can report it exactly once.
    pub fn record_network_miss(&mut self, now: Instant, base: Duration) -> bool {
        self.record_network_miss_with_jitter(now, base, rand::random::<f64>())
    }

    /// [`Self::record_network_miss`] with the jitter source injected, for deterministic tests.
    pub fn record_network_miss_with_jitter(
        &mut self,
        now: Instant,
        base: Duration,
        r: f64,
    ) -> bool {
        self.network_misses = self.network_misses.saturating_add(1);
        self.next_network_attempt = now
            + apply_jitter(
                backoff_delay(base, self.network_misses, MAX_NETWORK_RETRY_DELAY),
                r,
            );

        if self.is_unfetchable() && !self.reported_unfetchable {
            self.reported_unfetchable = true;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: Duration = Duration::from_secs(10);

    #[test]
    fn backoff_doubles_from_the_base_delay() {
        assert_eq!(
            backoff_delay(BASE, 0, MAX_NETWORK_RETRY_DELAY),
            Duration::ZERO
        );
        assert_eq!(backoff_delay(BASE, 1, MAX_NETWORK_RETRY_DELAY), BASE);
        assert_eq!(
            backoff_delay(BASE, 2, MAX_NETWORK_RETRY_DELAY),
            Duration::from_secs(20)
        );
        assert_eq!(
            backoff_delay(BASE, 3, MAX_NETWORK_RETRY_DELAY),
            Duration::from_secs(40)
        );
        assert_eq!(
            backoff_delay(BASE, 4, MAX_NETWORK_RETRY_DELAY),
            Duration::from_secs(80)
        );
    }

    #[test]
    fn backoff_saturates_at_the_cap_and_never_overflows() {
        assert_eq!(
            backoff_delay(BASE, 20, MAX_NETWORK_RETRY_DELAY),
            MAX_NETWORK_RETRY_DELAY
        );
        // A very large miss count must not panic or wrap around to a short delay.
        assert_eq!(
            backoff_delay(BASE, u32::MAX, MAX_NETWORK_RETRY_DELAY),
            MAX_NETWORK_RETRY_DELAY
        );
        assert_eq!(
            backoff_delay(BASE, u32::MAX, MAX_LOCAL_RECHECK_DELAY),
            MAX_LOCAL_RECHECK_DELAY
        );
    }

    #[test]
    fn jitter_stays_within_the_declared_fraction() {
        let d = Duration::from_secs(100);
        assert_eq!(apply_jitter(d, 0.5), d);
        assert_eq!(apply_jitter(d, 0.0), Duration::from_secs(75));
        assert_eq!(apply_jitter(d, 1.0), Duration::from_secs(125));
        // Out of range input is clamped rather than producing a wild delay.
        assert_eq!(apply_jitter(d, 5.0), Duration::from_secs(125));
        assert_eq!(apply_jitter(d, -5.0), Duration::from_secs(75));
    }

    #[test]
    fn a_new_missing_dependency_is_due_immediately() {
        let now = Instant::now();
        let retry = MissingDepRetry::new(now);

        // A dependency that is merely late must be looked for on the very first pass, locally and
        // on the network, exactly as it was before backoff existed.
        assert!(retry.due_for_local_recheck(now));
        assert!(retry.due_for_network_fetch(now));
        assert!(!retry.is_unfetchable());
        assert_eq!(retry.local_misses(), 0);
        assert_eq!(retry.network_misses(), 0);
    }

    #[test]
    fn the_two_schedules_advance_independently() {
        let now = Instant::now();
        let mut retry = MissingDepRetry::new(now);

        retry.record_local_miss_with_jitter(now, BASE, 0.5);

        // A local miss must not defer the network fetch: on the first pass the local search fails
        // and the network is asked immediately afterwards.
        assert!(!retry.due_for_local_recheck(now));
        assert!(retry.due_for_network_fetch(now));

        retry.record_network_miss_with_jitter(now, BASE, 0.5);
        assert!(!retry.due_for_network_fetch(now));
        assert!(retry.due_for_network_fetch(now + BASE));
    }

    #[test]
    fn local_rechecks_cap_out_while_network_fetches_keep_climbing() {
        let now = Instant::now();
        let mut retry = MissingDepRetry::new(now);

        for _ in 0..6 {
            retry.record_local_miss_with_jitter(now, BASE, 0.5);
            retry.record_network_miss_with_jitter(now, BASE, 0.5);
        }

        // Six misses -> raw delay 320s. The local schedule is capped to 60s, so a dependency that
        // arrives by gossip is still noticed within a minute, while the futile network fetch has
        // backed off to 320s.
        assert!(retry.due_for_local_recheck(now + MAX_LOCAL_RECHECK_DELAY));
        assert!(!retry.due_for_network_fetch(now + MAX_LOCAL_RECHECK_DELAY));
        assert!(retry.due_for_network_fetch(now + Duration::from_secs(320)));
    }

    #[test]
    fn the_unfetchable_transition_is_reported_exactly_once() {
        let now = Instant::now();
        let mut retry = MissingDepRetry::new(now);

        let mut transitions = 0;
        for _ in 0..(UNFETCHABLE_ATTEMPT_BUDGET + 5) {
            if retry.record_network_miss_with_jitter(now, BASE, 0.5) {
                transitions += 1;
            }
        }

        assert_eq!(transitions, 1);
        assert!(retry.is_unfetchable());
    }

    #[test]
    fn a_dependency_below_the_budget_is_not_unfetchable() {
        let now = Instant::now();
        let mut retry = MissingDepRetry::new(now);

        for _ in 0..(UNFETCHABLE_ATTEMPT_BUDGET - 1) {
            assert!(!retry.record_network_miss_with_jitter(now, BASE, 0.5));
            assert!(!retry.is_unfetchable());
        }

        // The budget-th failure is the transition.
        assert!(retry.record_network_miss_with_jitter(now, BASE, 0.5));
        assert!(retry.is_unfetchable());
    }

    #[test]
    fn local_misses_alone_never_declare_a_dependency_unfetchable() {
        let now = Instant::now();
        let mut retry = MissingDepRetry::new(now);

        // Only the network can say "nobody has this". A dependency that has merely not been found
        // in the local databases must never be reported as unfetchable.
        for _ in 0..(UNFETCHABLE_ATTEMPT_BUDGET * 3) {
            retry.record_local_miss_with_jitter(now, BASE, 0.5);
        }

        assert!(!retry.is_unfetchable());
    }

    #[test]
    fn an_unfetchable_dependency_is_still_swept_at_the_capped_intervals() {
        let now = Instant::now();
        let mut retry = MissingDepRetry::new(now);

        for _ in 0..(UNFETCHABLE_ATTEMPT_BUDGET + 3) {
            retry.record_local_miss_with_jitter(now, BASE, 0.5);
            retry.record_network_miss_with_jitter(now, BASE, 0.5);
        }

        assert!(retry.is_unfetchable());
        // Never dropped, never abandoned: it comes due again at the caps.
        assert!(retry.due_for_local_recheck(now + MAX_LOCAL_RECHECK_DELAY));
        assert!(retry.due_for_network_fetch(now + MAX_NETWORK_RETRY_DELAY));
    }
}
