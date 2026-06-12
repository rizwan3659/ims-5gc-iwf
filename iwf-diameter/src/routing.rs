//! Request routing (RFC 6733 §6.1): realm- and application-based route
//! selection over peer groups, with round-robin, least-connections and
//! weighted balancing.
//!
//! Lock discipline: the route table is read-mostly (rebuilt only on config
//! reload) and held in an `arc_swap`-style snapshot by the caller; per-peer
//! dynamic state (active transaction counts, availability) lives in atomics
//! so the hot path takes no locks. Expected contention: none on reads;
//! rebuilds are O(routes) and happen off the hot path.

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

use crate::error::DiameterError;

/// Balancing strategy for a peer group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Strategy {
    /// Strict rotation over available members.
    RoundRobin,
    /// Member with the fewest in-flight transactions.
    LeastConnections,
    /// Random selection proportional to configured weight.
    Weighted,
}

/// Dynamic, lock-free per-peer routing state shared with the peer task.
#[derive(Debug, Default)]
pub struct PeerRouteState {
    /// Peer is in OPEN state and accepting traffic.
    pub available: AtomicBool,
    /// In-flight transaction count (least-connections input).
    pub in_flight: AtomicUsize,
    /// Cumulative requests routed (metrics).
    pub routed_total: AtomicU64,
}

/// One member of a peer group.
#[derive(Debug, Clone)]
pub struct RouteMember {
    /// Peer Origin-Host, key into the peer registry.
    pub peer_host: String,
    /// Selection priority: members with the lowest value are tried first;
    /// higher values are fallback (RFC 6733 routing-table semantics).
    pub priority: u16,
    /// Weight among same-priority members (Weighted strategy).
    pub weight: u32,
    /// Shared dynamic state.
    pub state: Arc<PeerRouteState>,
}

/// A routing entry: destination realm + application → peer group.
#[derive(Debug, Clone)]
pub struct Route {
    /// Destination-Realm to match (exact, case-insensitive per RFC 6733 §6.1).
    pub realm: String,
    /// Application-Id to match; `None` matches any application.
    pub application: Option<u32>,
    /// Balancing strategy within a priority tier.
    pub strategy: Strategy,
    /// Group members.
    pub members: Vec<RouteMember>,
}

/// Immutable route table snapshot. Rebuilt on config change and swapped in
/// atomically by the holder (`ArcSwap<RouteTable>` in `iwf-node`).
#[derive(Debug, Default)]
pub struct RouteTable {
    routes: Vec<Route>,
    rr_cursor: AtomicUsize,
}

impl RouteTable {
    /// Build a table from configured routes.
    pub fn new(routes: Vec<Route>) -> Self {
        RouteTable {
            routes,
            rr_cursor: AtomicUsize::new(0),
        }
    }

    /// Select a peer for (`realm`, `application`).
    ///
    /// Selection walks matching routes, then priority tiers (lowest first),
    /// applying the route's strategy among *available* members of the tier.
    pub fn select(&self, realm: &str, application: u32) -> Result<&RouteMember, DiameterError> {
        let route = self
            .routes
            .iter()
            .find(|r| {
                r.realm.eq_ignore_ascii_case(realm)
                    && r.application.map_or(true, |a| a == application)
            })
            .ok_or_else(|| DiameterError::NoRoute {
                realm: realm.to_owned(),
                application,
            })?;

        // Group available members by ascending priority.
        let mut priorities: Vec<u16> = route
            .members
            .iter()
            .filter(|m| m.state.available.load(Ordering::Acquire))
            .map(|m| m.priority)
            .collect();
        priorities.sort_unstable();
        priorities.dedup();

        for tier in priorities {
            let candidates: Vec<&RouteMember> = route
                .members
                .iter()
                .filter(|m| m.priority == tier && m.state.available.load(Ordering::Acquire))
                .collect();
            if candidates.is_empty() {
                continue;
            }
            let chosen = match route.strategy {
                Strategy::RoundRobin => {
                    let n = self.rr_cursor.fetch_add(1, Ordering::Relaxed);
                    candidates[n % candidates.len()]
                }
                Strategy::LeastConnections => candidates
                    .iter()
                    .min_by_key(|m| m.state.in_flight.load(Ordering::Relaxed))
                    .copied()
                    .unwrap_or(candidates[0]),
                Strategy::Weighted => {
                    let total: u64 = candidates.iter().map(|m| u64::from(m.weight.max(1))).sum();
                    let mut ticket = rand::random::<u64>() % total.max(1);
                    let mut pick = candidates[0];
                    for m in &candidates {
                        let w = u64::from(m.weight.max(1));
                        if ticket < w {
                            pick = m;
                            break;
                        }
                        ticket -= w;
                    }
                    pick
                }
            };
            chosen.state.routed_total.fetch_add(1, Ordering::Relaxed);
            return Ok(chosen);
        }

        Err(DiameterError::NoRoute {
            realm: realm.to_owned(),
            application,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn member(host: &str, priority: u16, weight: u32, up: bool) -> RouteMember {
        let state = Arc::new(PeerRouteState::default());
        state.available.store(up, Ordering::Release);
        RouteMember {
            peer_host: host.to_owned(),
            priority,
            weight,
            state,
        }
    }

    fn table(strategy: Strategy, members: Vec<RouteMember>) -> RouteTable {
        RouteTable::new(vec![Route {
            realm: "ims.example.org".to_owned(),
            application: Some(crate::dictionary::APP_CX),
            strategy,
            members,
        }])
    }

    #[test]
    fn round_robin_rotates_over_available() {
        let t = table(
            Strategy::RoundRobin,
            vec![
                member("a", 0, 1, true),
                member("b", 0, 1, true),
                member("c", 0, 1, false), // down, must be skipped
            ],
        );
        let mut seen = Vec::new();
        for _ in 0..4 {
            seen.push(
                t.select("ims.example.org", crate::dictionary::APP_CX)
                    .expect("route")
                    .peer_host
                    .clone(),
            );
        }
        assert!(seen.contains(&"a".to_owned()) && seen.contains(&"b".to_owned()));
        assert!(!seen.contains(&"c".to_owned()));
    }

    #[test]
    fn least_connections_prefers_idle_peer() {
        let busy = member("busy", 0, 1, true);
        busy.state.in_flight.store(10, Ordering::Relaxed);
        let idle = member("idle", 0, 1, true);
        let t = table(Strategy::LeastConnections, vec![busy, idle]);
        let chosen = t
            .select("ims.example.org", crate::dictionary::APP_CX)
            .expect("route");
        assert_eq!(chosen.peer_host, "idle");
    }

    #[test]
    fn priority_tier_failover() {
        let t = table(
            Strategy::RoundRobin,
            vec![member("primary", 0, 1, false), member("backup", 1, 1, true)],
        );
        let chosen = t
            .select("ims.example.org", crate::dictionary::APP_CX)
            .expect("route");
        assert_eq!(chosen.peer_host, "backup");
    }

    #[test]
    fn realm_match_is_case_insensitive() {
        let t = table(Strategy::RoundRobin, vec![member("a", 0, 1, true)]);
        assert!(t
            .select("IMS.Example.ORG", crate::dictionary::APP_CX)
            .is_ok());
    }

    #[test]
    fn no_route_when_all_down() {
        let t = table(Strategy::RoundRobin, vec![member("a", 0, 1, false)]);
        assert!(matches!(
            t.select("ims.example.org", crate::dictionary::APP_CX),
            Err(DiameterError::NoRoute { .. })
        ));
    }

    #[test]
    fn weighted_respects_weights_statistically() {
        let t = table(
            Strategy::Weighted,
            vec![member("heavy", 0, 9, true), member("light", 0, 1, true)],
        );
        let mut heavy = 0u32;
        for _ in 0..2000 {
            if t.select("ims.example.org", crate::dictionary::APP_CX)
                .expect("route")
                .peer_host
                == "heavy"
            {
                heavy += 1;
            }
        }
        // Expect ~90%; accept a generous band to avoid flakiness.
        assert!(heavy > 1500, "heavy selected only {heavy}/2000");
    }
}
