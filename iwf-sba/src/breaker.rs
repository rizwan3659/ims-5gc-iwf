//! Per-endpoint circuit breaker.
//!
//! State machine per endpoint: **Closed** (counting consecutive failures) →
//! **Open** (rejecting instantly until `open_for` elapses) → **Half-open**
//! (admits a single probe; success closes, failure re-opens).
//!
//! Lock discipline: endpoint states live in a `DashMap` keyed by endpoint
//! id; each entry's interior is a small `Mutex`-free struct mutated under
//! the DashMap shard guard. Guards are never held across `.await`.

use std::time::{Duration, Instant};

use dashmap::DashMap;

/// Breaker tuning.
#[derive(Debug, Clone, Copy)]
pub struct BreakerConfig {
    /// Consecutive failures that trip the breaker.
    pub failure_threshold: u32,
    /// How long the breaker stays open before admitting a half-open probe.
    pub open_for: Duration,
}

impl Default for BreakerConfig {
    fn default() -> Self {
        BreakerConfig {
            failure_threshold: 5,
            open_for: Duration::from_secs(10),
        }
    }
}

#[derive(Debug)]
enum State {
    Closed { consecutive_failures: u32 },
    Open { until: Instant },
    HalfOpen { probe_in_flight: bool },
}

/// Circuit breaker over a dynamic set of endpoints.
#[derive(Debug, Default)]
pub struct CircuitBreaker {
    config: BreakerConfig,
    states: DashMap<String, State>,
}

impl CircuitBreaker {
    /// Breaker with the given tuning.
    pub fn new(config: BreakerConfig) -> Self {
        CircuitBreaker {
            config,
            states: DashMap::new(),
        }
    }

    /// May a request be sent to `endpoint` right now? Transitions
    /// Open→Half-open when the window has elapsed and claims the probe slot.
    pub fn admit(&self, endpoint: &str) -> bool {
        let mut entry = self
            .states
            .entry(endpoint.to_owned())
            .or_insert(State::Closed {
                consecutive_failures: 0,
            });
        match &mut *entry {
            State::Closed { .. } => true,
            State::Open { until } => {
                if Instant::now() >= *until {
                    *entry = State::HalfOpen {
                        probe_in_flight: true,
                    };
                    true
                } else {
                    false
                }
            }
            State::HalfOpen { probe_in_flight } => {
                if *probe_in_flight {
                    false
                } else {
                    *probe_in_flight = true;
                    true
                }
            }
        }
    }

    /// Record a successful response.
    pub fn record_success(&self, endpoint: &str) {
        if let Some(mut entry) = self.states.get_mut(endpoint) {
            *entry = State::Closed {
                consecutive_failures: 0,
            };
        }
    }

    /// Record a failure (transport error or 5xx). Returns `true` when this
    /// failure tripped the breaker open.
    pub fn record_failure(&self, endpoint: &str) -> bool {
        let mut entry = self
            .states
            .entry(endpoint.to_owned())
            .or_insert(State::Closed {
                consecutive_failures: 0,
            });
        match &mut *entry {
            State::Closed {
                consecutive_failures,
            } => {
                *consecutive_failures += 1;
                if *consecutive_failures >= self.config.failure_threshold {
                    *entry = State::Open {
                        until: Instant::now() + self.config.open_for,
                    };
                    true
                } else {
                    false
                }
            }
            State::HalfOpen { .. } => {
                *entry = State::Open {
                    until: Instant::now() + self.config.open_for,
                };
                true
            }
            State::Open { .. } => false,
        }
    }

    /// Current state label for metrics/debugging.
    pub fn state_label(&self, endpoint: &str) -> &'static str {
        match self.states.get(endpoint).as_deref() {
            None | Some(State::Closed { .. }) => "closed",
            Some(State::Open { .. }) => "open",
            Some(State::HalfOpen { .. }) => "half_open",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fast_breaker() -> CircuitBreaker {
        CircuitBreaker::new(BreakerConfig {
            failure_threshold: 3,
            open_for: Duration::from_millis(20),
        })
    }

    #[test]
    fn trips_after_threshold_and_recovers_via_half_open() {
        let cb = fast_breaker();
        assert!(cb.admit("udm-1"));
        assert!(!cb.record_failure("udm-1"));
        assert!(!cb.record_failure("udm-1"));
        assert!(cb.record_failure("udm-1"), "third failure trips");
        assert_eq!(cb.state_label("udm-1"), "open");
        assert!(!cb.admit("udm-1"), "open rejects immediately");

        std::thread::sleep(Duration::from_millis(25));
        assert!(cb.admit("udm-1"), "half-open admits one probe");
        assert!(!cb.admit("udm-1"), "second concurrent probe rejected");
        cb.record_success("udm-1");
        assert_eq!(cb.state_label("udm-1"), "closed");
        assert!(cb.admit("udm-1"));
    }

    #[test]
    fn half_open_failure_reopens() {
        let cb = fast_breaker();
        for _ in 0..3 {
            cb.record_failure("ausf-1");
        }
        std::thread::sleep(Duration::from_millis(25));
        assert!(cb.admit("ausf-1"));
        assert!(cb.record_failure("ausf-1"), "probe failure re-opens");
        assert!(!cb.admit("ausf-1"));
    }

    #[test]
    fn success_resets_failure_count() {
        let cb = fast_breaker();
        cb.record_failure("amf-1");
        cb.record_failure("amf-1");
        cb.record_success("amf-1");
        assert!(!cb.record_failure("amf-1"), "count restarted");
        assert_eq!(cb.state_label("amf-1"), "closed");
    }

    #[test]
    fn endpoints_are_isolated() {
        let cb = fast_breaker();
        for _ in 0..3 {
            cb.record_failure("udm-1");
        }
        assert!(!cb.admit("udm-1"));
        assert!(cb.admit("udm-2"), "other endpoint unaffected");
    }
}
