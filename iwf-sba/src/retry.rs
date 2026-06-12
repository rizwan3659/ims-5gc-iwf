//! Retry policy: bounded attempts, exponential backoff with full jitter,
//! and a hard idempotency gate — non-idempotent SBI operations (POST,
//! PATCH without preconditions) are never replayed after an ambiguous
//! failure, because a duplicated `ue-authentications` POST is worse than a
//! failed one.

use std::time::Duration;

use iwf_core::ports::SbiMethod;

/// Retry tuning.
#[derive(Debug, Clone, Copy)]
pub struct RetryPolicy {
    /// Total attempts including the first (1 = no retries).
    pub max_attempts: u32,
    /// Backoff before retry `n` is `base * 2^(n-1)`, capped at `cap`,
    /// then jittered uniformly in `[0, backoff)` (full jitter).
    pub base: Duration,
    /// Upper bound for any single backoff.
    pub cap: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        RetryPolicy {
            max_attempts: 3,
            base: Duration::from_millis(50),
            cap: Duration::from_millis(500),
        }
    }
}

impl RetryPolicy {
    /// Whether attempt `attempt` (1-based, the one that just failed) may be
    /// followed by another try for `method`.
    pub fn may_retry(&self, method: SbiMethod, attempt: u32) -> bool {
        method.idempotent() && attempt < self.max_attempts
    }

    /// Jittered backoff to sleep before retry following failed `attempt`.
    pub fn backoff(&self, attempt: u32) -> Duration {
        let exp = self
            .base
            .saturating_mul(1u32 << attempt.saturating_sub(1).min(16));
        let capped = exp.min(self.cap);
        // Full jitter: uniform in [0, capped). Avoids synchronized retry
        // storms across pods after a shared failure.
        capped.mul_f64(rand::random::<f64>())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_idempotent_methods_never_retry() {
        let p = RetryPolicy::default();
        assert!(!p.may_retry(SbiMethod::Post, 1));
        assert!(!p.may_retry(SbiMethod::Patch, 1));
        assert!(p.may_retry(SbiMethod::Get, 1));
        assert!(p.may_retry(SbiMethod::Put, 1));
        assert!(p.may_retry(SbiMethod::Delete, 1));
    }

    #[test]
    fn attempts_are_bounded() {
        let p = RetryPolicy {
            max_attempts: 3,
            ..Default::default()
        };
        assert!(p.may_retry(SbiMethod::Get, 1));
        assert!(p.may_retry(SbiMethod::Get, 2));
        assert!(!p.may_retry(SbiMethod::Get, 3));
    }

    #[test]
    fn backoff_is_capped_and_jittered() {
        let p = RetryPolicy {
            max_attempts: 5,
            base: Duration::from_millis(100),
            cap: Duration::from_millis(300),
        };
        for attempt in 1..=10 {
            let b = p.backoff(attempt);
            assert!(b < Duration::from_millis(301), "attempt {attempt}: {b:?}");
        }
    }
}
