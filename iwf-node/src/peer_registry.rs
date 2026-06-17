//! Outbound Diameter origination: a registry of OPEN peer connections keyed
//! by Origin-Host, so the node can *originate* a request into an existing
//! connection (Cx RTR/PPR, Sh PNR, Rx RAR/ASR, Ro re-auth) and correlate the
//! answer.
//!
//! The Diameter front-end is otherwise server-only: each connection's reader
//! dispatches incoming requests and its writer drains an answer queue
//! (`diameter_front.rs`). Origination reuses that **same writer queue** — we
//! push a request frame onto it — and adds a per-connection *pending* table
//! (Hop-by-Hop id → waiter) so the reader can hand the matching answer back to
//! the originator. No second socket, no second writer task.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use iwf_diameter::message::Message;
use tokio::sync::{mpsc, oneshot};

/// Why an origination could not produce an answer.
#[derive(Debug, thiserror::Error)]
pub enum OriginateError {
    /// No OPEN connection is registered for that Origin-Host (the peer never
    /// connected, or dropped). The caller maps this to a 404/410 toward the
    /// 5GC notifier and forgets the binding.
    #[error("no connected peer {0}")]
    UnknownPeer(String),
    /// The peer did not answer within the budget.
    #[error("peer {host} did not answer within {timeout:?}")]
    Timeout {
        /// Target Origin-Host.
        host: String,
        /// The elapsed budget.
        timeout: Duration,
    },
    /// The connection closed (writer gone / reader dropped the waiter) before
    /// an answer arrived.
    #[error("connection to {0} closed before answer")]
    ConnectionGone(String),
}

/// Per-connection origination state. Clonable handle shared between the
/// connection task (which owns the reader/writer) and the registry.
#[derive(Clone)]
struct PeerHandle {
    /// The connection's existing answer/writer queue — we push requests here.
    out_tx: mpsc::Sender<Message>,
    /// Hop-by-Hop id → answer waiter, shared with the connection's reader loop.
    pending: Pending,
    /// Monotonic Hop-by-Hop allocator for this connection.
    hbh: Arc<AtomicU32>,
    /// Monotonic End-to-End allocator for this connection.
    e2e: Arc<AtomicU32>,
}

/// Hop-by-Hop id → oneshot waiter, shared between a connection's reader loop
/// and the [`PeerRegistry`].
pub type Pending = Arc<Mutex<HashMap<u32, oneshot::Sender<Message>>>>;

/// Registry of OPEN peer connections available for origination.
#[derive(Default)]
pub struct PeerRegistry {
    peers: Mutex<HashMap<String, PeerHandle>>,
}

impl std::fmt::Debug for PeerRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let n = crate::lock::guard(&self.peers).len();
        f.debug_struct("PeerRegistry").field("peers", &n).finish()
    }
}

impl PeerRegistry {
    /// Empty registry.
    pub fn new() -> Self {
        PeerRegistry::default()
    }

    /// Register an OPEN connection (called once CER/CEA completes). Returns the
    /// shared `pending` table the connection's reader loop must consult when it
    /// receives an answer (Hop-by-Hop → waiter); see [`Self::resolve_answer`].
    ///
    /// Re-registering the same Origin-Host (reconnect) replaces the old handle;
    /// the previous connection's waiters fail when its reader drops them.
    pub fn register(&self, origin_host: &str, out_tx: mpsc::Sender<Message>) -> Pending {
        let pending: Pending = Arc::new(Mutex::new(HashMap::new()));
        let handle = PeerHandle {
            out_tx,
            pending: pending.clone(),
            hbh: Arc::new(AtomicU32::new(rand_seed())),
            e2e: Arc::new(AtomicU32::new(rand_seed())),
        };
        crate::lock::guard(&self.peers).insert(origin_host.to_owned(), handle);
        pending
    }

    /// Remove a connection on disconnect. Any still-pending waiters are dropped
    /// with the `pending` table by the connection task.
    pub fn deregister(&self, origin_host: &str) {
        crate::lock::guard(&self.peers).remove(origin_host);
    }

    /// Originate `msg` to `origin_host` and await its answer.
    ///
    /// Allocates Hop-by-Hop / End-to-End ids on the target connection, sets
    /// them on the header, registers a waiter, pushes the request onto the
    /// connection's writer queue, and waits up to `timeout`. On timeout the
    /// waiter is removed so a late answer is simply ignored.
    pub async fn originate(
        &self,
        origin_host: &str,
        mut msg: Message,
        timeout: Duration,
    ) -> Result<Message, OriginateError> {
        let (out_tx, pending, hbh, e2e) = {
            // Lock failure is no longer possible (a poisoned lock is recovered,
            // not misreported as `UnknownPeer`); the only `UnknownPeer` is a
            // genuinely-unregistered peer.
            let peers = crate::lock::guard(&self.peers);
            let h = peers
                .get(origin_host)
                .ok_or_else(|| OriginateError::UnknownPeer(origin_host.to_owned()))?;
            (
                h.out_tx.clone(),
                h.pending.clone(),
                h.hbh.fetch_add(1, Ordering::Relaxed),
                h.e2e.fetch_add(1, Ordering::Relaxed),
            )
        };

        msg.header.hop_by_hop = hbh;
        msg.header.end_to_end = e2e;

        let (tx, rx) = oneshot::channel();
        crate::lock::guard(&pending).insert(hbh, tx);

        if out_tx.send(msg).await.is_err() {
            crate::lock::guard(&pending).remove(&hbh);
            return Err(OriginateError::ConnectionGone(origin_host.to_owned()));
        }

        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(answer)) => Ok(answer),
            Ok(Err(_)) => Err(OriginateError::ConnectionGone(origin_host.to_owned())),
            Err(_) => {
                crate::lock::guard(&pending).remove(&hbh);
                Err(OriginateError::Timeout {
                    host: origin_host.to_owned(),
                    timeout,
                })
            }
        }
    }

    /// Deliver an answer received by a connection's reader loop to its waiter.
    /// Returns `true` if a waiter matched (an originated request); `false`
    /// means the answer was unsolicited and the caller may ignore it.
    ///
    /// Static so the reader loop can call it with just the connection's
    /// `pending` table (no registry lookup on the hot path).
    pub fn resolve_answer(pending: &Pending, hop_by_hop: u32, answer: Message) -> bool {
        let waiter = crate::lock::guard(pending).remove(&hop_by_hop);
        match waiter {
            Some(tx) => tx.send(answer).is_ok(),
            None => false,
        }
    }
}

/// A non-zero-ish starting id per connection so concurrent connections don't
/// all begin at 0 (purely cosmetic for tracing; correlation is per-connection).
fn rand_seed() -> u32 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(1);
    nanos | 1
}

#[cfg(test)]
mod tests {
    use super::*;
    use iwf_diameter::avp::AvpValue;
    use iwf_diameter::dictionary as dict;
    use iwf_diameter::message::MessageBuilder;

    fn req() -> Message {
        MessageBuilder::request(dict::CMD_PNR, dict::APP_SH).build()
    }

    #[tokio::test]
    async fn originate_then_resolve_round_trips() {
        let registry = Arc::new(PeerRegistry::new());
        let (tx, mut rx) = mpsc::channel::<Message>(8);
        let pending = registry.register("as.ims.example.org", tx);

        // Simulate the connection's reader/writer: echo an answer carrying the
        // request's (registry-assigned) Hop-by-Hop id.
        let pending_reader = pending.clone();
        let echo = tokio::spawn(async move {
            let sent = rx.recv().await.expect("originated request");
            assert!(sent.header.flags.request());
            let answer = MessageBuilder::answer_to(&sent.header)
                .std(dict::AVP_RESULT_CODE, AvpValue::U32(dict::RC_SUCCESS))
                .build();
            assert!(PeerRegistry::resolve_answer(
                &pending_reader,
                sent.header.hop_by_hop,
                answer
            ));
        });

        let answer = registry
            .originate("as.ims.example.org", req(), Duration::from_secs(2))
            .await
            .expect("answer");
        assert_eq!(answer.result_code(), Some(dict::RC_SUCCESS));
        echo.await.expect("echo task");
    }

    #[tokio::test]
    async fn unknown_peer_errors() {
        let registry = PeerRegistry::new();
        let err = registry
            .originate("nope.example.org", req(), Duration::from_millis(50))
            .await
            .expect_err("unknown");
        assert!(matches!(err, OriginateError::UnknownPeer(_)));
    }

    #[tokio::test]
    async fn timeout_when_no_answer() {
        let registry = PeerRegistry::new();
        let (tx, _rx) = mpsc::channel::<Message>(8); // never drained-for-answer
        registry.register("slow.example.org", tx);
        let err = registry
            .originate("slow.example.org", req(), Duration::from_millis(80))
            .await
            .expect_err("timeout");
        assert!(matches!(err, OriginateError::Timeout { .. }));
    }

    #[tokio::test]
    async fn connection_gone_when_writer_closed() {
        let registry = PeerRegistry::new();
        let (tx, rx) = mpsc::channel::<Message>(8);
        registry.register("gone.example.org", tx);
        drop(rx); // receiver gone → send fails
        let err = registry
            .originate("gone.example.org", req(), Duration::from_millis(80))
            .await
            .expect_err("gone");
        assert!(matches!(err, OriginateError::ConnectionGone(_)));
    }

    #[tokio::test]
    async fn deregister_removes_peer() {
        let registry = PeerRegistry::new();
        let (tx, _rx) = mpsc::channel::<Message>(1);
        registry.register("p.example.org", tx);
        registry.deregister("p.example.org");
        // After deregister, origination no longer finds the peer.
        let err = registry
            .originate("p.example.org", req(), Duration::from_millis(50))
            .await
            .expect_err("gone after deregister");
        assert!(matches!(err, OriginateError::UnknownPeer(_)));
    }
}
