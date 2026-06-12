//! Session and pending-transaction management.
//!
//! Two concerns live here:
//! 1. **Pending answer correlation**: every relayed/originated request is
//!    parked in a `DashMap` keyed by Hop-by-Hop id until its answer arrives
//!    or the transaction deadline passes (RFC 6733 §6.2: Hop-by-Hop is the
//!    answer-matching key).
//! 2. **Session-Id generation** per RFC 6733 §8.8:
//!    `<DiameterIdentity>;<high 32 bits>;<low 32 bits>[;<optional value>]`.
//!
//! Lock discipline: `DashMap` shards internally (16 shards by default);
//! expected contention is low because keys are uniformly distributed
//! Hop-by-Hop ids. No await points are held across shard guards.

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use dashmap::DashMap;
use tokio::sync::oneshot;

use crate::error::DiameterError;
use crate::message::Message;

/// A parked request awaiting its answer.
#[derive(Debug)]
pub struct PendingTx {
    /// Completes with the answer message.
    pub responder: oneshot::Sender<Message>,
    /// Absolute deadline; the reaper fails the transaction past this point.
    pub deadline: Instant,
    /// Peer the request was sent to (for failover bookkeeping).
    pub peer_host: String,
}

/// Concurrent pending-transaction table.
#[derive(Debug, Default)]
pub struct SessionTable {
    pending: DashMap<u32, PendingTx>,
    hbh_counter: AtomicU32,
    active_sessions: AtomicU64,
}

impl SessionTable {
    /// Empty table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Allocate the next Hop-by-Hop identifier (monotonic, wrapping).
    pub fn next_hop_by_hop(&self) -> u32 {
        self.hbh_counter.fetch_add(1, Ordering::Relaxed)
    }

    /// Park a request. Returns the receiver the caller awaits, bounded by
    /// `timeout`.
    pub fn park(
        &self,
        hop_by_hop: u32,
        peer_host: String,
        timeout: Duration,
    ) -> oneshot::Receiver<Message> {
        let (tx, rx) = oneshot::channel();
        self.pending.insert(
            hop_by_hop,
            PendingTx {
                responder: tx,
                deadline: Instant::now() + timeout,
                peer_host,
            },
        );
        self.active_sessions.fetch_add(1, Ordering::Relaxed);
        rx
    }

    /// Complete a parked transaction with its answer.
    pub fn complete(&self, answer: Message) -> Result<(), DiameterError> {
        let hbh = answer.header.hop_by_hop;
        let (_, entry) = self
            .pending
            .remove(&hbh)
            .ok_or(DiameterError::UnmatchedAnswer(hbh))?;
        self.active_sessions.fetch_sub(1, Ordering::Relaxed);
        // Receiver dropped means the caller already timed out; not an error.
        let _ = entry.responder.send(answer);
        Ok(())
    }

    /// Drop every transaction parked on `peer_host` (peer failed); the
    /// receivers see a closed channel and surface `PeerUnavailable`.
    /// Returns how many transactions were failed over.
    pub fn fail_peer(&self, peer_host: &str) -> usize {
        let keys: Vec<u32> = self
            .pending
            .iter()
            .filter(|e| e.value().peer_host == peer_host)
            .map(|e| *e.key())
            .collect();
        let mut dropped = 0;
        for k in keys {
            if self.pending.remove(&k).is_some() {
                self.active_sessions.fetch_sub(1, Ordering::Relaxed);
                dropped += 1;
            }
        }
        dropped
    }

    /// Reap transactions past their deadline. Run periodically (the node
    /// drives this at 4 Hz). Returns the number reaped.
    pub fn reap_expired(&self) -> usize {
        let now = Instant::now();
        let keys: Vec<u32> = self
            .pending
            .iter()
            .filter(|e| e.value().deadline <= now)
            .map(|e| *e.key())
            .collect();
        let mut reaped = 0;
        for k in keys {
            if self.pending.remove(&k).is_some() {
                self.active_sessions.fetch_sub(1, Ordering::Relaxed);
                reaped += 1;
            }
        }
        reaped
    }

    /// Number of in-flight transactions (exported as
    /// `iwf_active_sessions_total`).
    pub fn active(&self) -> u64 {
        self.active_sessions.load(Ordering::Relaxed)
    }
}

/// Session-Id generator per RFC 6733 §8.8. The `<high 32 bits>` half is
/// seconds since the epoch at process start (monotonic across restarts) and
/// `<low 32 bits>` a process-local counter, giving global uniqueness for a
/// given Origin-Host.
#[derive(Debug)]
pub struct SessionIdGenerator {
    identity: String,
    high: u32,
    low: AtomicU32,
}

impl SessionIdGenerator {
    /// Generator for this node's DiameterIdentity.
    pub fn new(identity: impl Into<String>) -> Self {
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0); // clock before 1970 — degrade to counter-only uniqueness
        SessionIdGenerator {
            identity: identity.into(),
            high: (secs & 0xFFFF_FFFF) as u32,
            low: AtomicU32::new(0),
        }
    }

    /// Allocate the next Session-Id string.
    pub fn next(&self) -> String {
        let low = self.low.fetch_add(1, Ordering::Relaxed);
        format!("{};{};{}", self.identity, self.high, low)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dictionary as dict;
    use crate::message::MessageBuilder;

    fn answer(hbh: u32) -> Message {
        let req = MessageBuilder::request(dict::CMD_UAR, dict::APP_CX)
            .ids(hbh, 0)
            .build();
        MessageBuilder::answer_to(&req.header)
            .std(
                dict::AVP_RESULT_CODE,
                crate::avp::AvpValue::U32(dict::RC_SUCCESS),
            )
            .build()
    }

    #[tokio::test]
    async fn park_and_complete() {
        let table = SessionTable::new();
        let hbh = table.next_hop_by_hop();
        let rx = table.park(hbh, "hss".to_owned(), Duration::from_secs(5));
        assert_eq!(table.active(), 1);
        table.complete(answer(hbh)).expect("complete");
        let got = rx.await.expect("answer delivered");
        assert_eq!(got.result_code(), Some(dict::RC_SUCCESS));
        assert_eq!(table.active(), 0);
    }

    #[tokio::test]
    async fn unmatched_answer_is_error() {
        let table = SessionTable::new();
        assert!(matches!(
            table.complete(answer(0xDEAD)),
            Err(DiameterError::UnmatchedAnswer(0xDEAD))
        ));
    }

    #[tokio::test]
    async fn fail_peer_drops_only_that_peer() {
        let table = SessionTable::new();
        let rx_a = table.park(1, "hss-a".to_owned(), Duration::from_secs(5));
        let _rx_b = table.park(2, "hss-b".to_owned(), Duration::from_secs(5));
        assert_eq!(table.fail_peer("hss-a"), 1);
        assert_eq!(table.active(), 1);
        assert!(rx_a.await.is_err(), "sender dropped → receiver errors");
    }

    #[tokio::test]
    async fn reaper_expires_past_deadline() {
        let table = SessionTable::new();
        let rx = table.park(7, "hss".to_owned(), Duration::from_millis(0));
        // Deadline is already past.
        assert_eq!(table.reap_expired(), 1);
        assert!(rx.await.is_err());
    }

    #[test]
    fn session_ids_are_unique_and_well_formed() {
        let g = SessionIdGenerator::new("iwf.example.org");
        let a = g.next();
        let b = g.next();
        assert_ne!(a, b);
        assert!(a.starts_with("iwf.example.org;"));
        assert_eq!(a.split(';').count(), 3);
    }
}
