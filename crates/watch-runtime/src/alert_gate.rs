//! Rate limiting for conditions that flap between sampling rounds.
//!
//! `quality` is a per-round verdict assembled from four independent samples
//! (process completeness, socket collector state, activity state and the
//! traffic counter). A single missing `lsof` sample or an empty counter flips
//! it to "degraded" and the next round usually flips it back. Paging on the
//! first bad round turns the watchdog into a recurring interruption, and the
//! notification queue only suppresses duplicates that are still pending or on
//! screen — dismissing one lets the next bad round raise it again.
//!
//! This gate sits in front of the notifier: a condition has to hold for a
//! sustained streak before the first alert, and repeats are held back for a
//! quiet period. Both counters are independent, so a gap that recovers costs
//! nothing and a long outage still gets one reminder per quiet period.

use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct AlertGate {
    required: u32,
    quiet: Duration,
    streak: u32,
    last_sent: Option<Instant>,
}

impl AlertGate {
    pub fn new(required: u32, quiet: Duration) -> Self {
        Self {
            required: required.max(1),
            quiet,
            streak: 0,
            last_sent: None,
        }
    }

    /// Feeds one round of observation.
    ///
    /// Returns `true` at most once per quiet period, and only after the
    /// condition has held for `required` consecutive rounds.
    pub fn observe(&mut self, failing: bool) -> bool {
        self.observe_at(failing, Instant::now())
    }

    /// Same as [`Self::observe`] with an explicit clock, so the quiet period
    /// and the streak can be exercised without sleeping.
    pub fn observe_at(&mut self, failing: bool, at: Instant) -> bool {
        if !failing {
            self.streak = 0;
            return false;
        }
        self.streak = self.streak.saturating_add(1);
        if self.streak < self.required {
            return false;
        }
        if self
            .last_sent
            .is_some_and(|last| at.saturating_duration_since(last) < self.quiet)
        {
            return false;
        }
        self.last_sent = Some(at);
        // Reset the streak: once the quiet period lapses, a fresh episode must
        // again prove itself with a sustained streak instead of firing on the
        // first isolated bad round.
        self.streak = 0;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const REQUIRED: u32 = 3;
    const QUIET: Duration = Duration::from_secs(60);

    fn gate() -> AlertGate {
        AlertGate::new(REQUIRED, QUIET)
    }

    #[test]
    fn a_single_bad_round_never_alerts() {
        let mut gate = gate();
        assert!(!gate.observe(true));
        assert!(!gate.observe(true));
    }

    #[test]
    fn a_sustained_streak_alerts_on_the_nth_round() {
        let mut gate = gate();
        assert!(!gate.observe(true));
        assert!(!gate.observe(true));
        assert!(gate.observe(true));
    }

    #[test]
    fn recovering_between_rounds_resets_the_streak() {
        let mut gate = gate();
        assert!(!gate.observe(true));
        assert!(!gate.observe(true));
        assert!(!gate.observe(false));
        assert!(!gate.observe(true));
        assert!(!gate.observe(true));
        assert!(gate.observe(true));
    }

    #[test]
    fn repeats_inside_the_quiet_period_are_held_back() {
        let start = Instant::now();
        let mut gate = gate();
        for _ in 0..REQUIRED {
            gate.observe_at(true, start);
        }
        // The first round of this loop already sent the alert; every further
        // sustained round inside the quiet period must stay silent.
        for step in 1..REQUIRED * 4 {
            let at = start + Duration::from_secs(u64::from(step));
            assert!(!gate.observe_at(true, at));
        }
    }

    #[test]
    fn a_new_episode_after_the_quiet_period_needs_its_own_streak() {
        let start = Instant::now();
        let mut gate = gate();
        for _ in 0..REQUIRED {
            gate.observe_at(true, start);
        }
        let later = start + QUIET + Duration::from_secs(1);
        assert!(!gate.observe_at(true, later));
        assert!(!gate.observe_at(true, later));
        assert!(gate.observe_at(true, later));
    }
}
