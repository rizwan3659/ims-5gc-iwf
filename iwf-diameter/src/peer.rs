//! Peer state machine (RFC 6733 §5.6) and watchdog behaviour (RFC 3539).
//!
//! The FSM is implemented as a pure transition function over
//! ([`PeerState`], [`PeerEvent`]) → ([`PeerState`], [`Vec<PeerAction>`]) so it
//! is unit-testable without sockets; the async connection task in
//! [`crate::transport`] feeds it events and executes the returned actions.
//!
//! Election (§5.6.4) is implemented by Origin-Host comparison: on a
//! connection collision the connection initiated by the lexicographically
//! greater Origin-Host wins, matching the RFC's tie-break.

use std::time::Duration;

/// Configuration knobs of one peer relationship.
#[derive(Debug, Clone)]
pub struct PeerConfig {
    /// Peer Origin-Host (DiameterIdentity) expected in CER/CEA.
    pub host: String,
    /// Peer realm.
    pub realm: String,
    /// Transport address, `host:port`.
    pub address: String,
    /// Watchdog base interval Tw (RFC 3539 §3.4.1; default 30 s). Actual
    /// firing time is jittered ±2 s by the connection task.
    pub watchdog_interval: Duration,
    /// Reconnect timer Tc (RFC 6733 §2.1; default 30 s).
    pub reconnect_interval: Duration,
    /// Bound for the outbound message queue (backpressure threshold).
    pub send_queue_depth: usize,
}

impl Default for PeerConfig {
    fn default() -> Self {
        PeerConfig {
            host: String::new(),
            realm: String::new(),
            address: String::new(),
            watchdog_interval: Duration::from_secs(30),
            reconnect_interval: Duration::from_secs(30),
            send_queue_depth: 4096,
        }
    }
}

/// FSM states, named per RFC 6733 §5.6 table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerState {
    /// No connection and none being attempted.
    Closed,
    /// We initiated TCP connect, waiting for it to complete.
    WaitConnAck,
    /// CER sent, waiting for CEA.
    WaitICea,
    /// Connection collision: waiting for the election to settle.
    WaitConnAckElect,
    /// Election winner pending the loser's teardown.
    WaitReturns,
    /// Capabilities exchanged on a connection we initiated.
    IOpen,
    /// Capabilities exchanged on a connection the peer initiated.
    ROpen,
    /// DPR sent, waiting for DPA.
    Closing,
}

impl PeerState {
    /// Whether application traffic may be sent (§5.6: I-Open/R-Open only).
    pub fn open(&self) -> bool {
        matches!(self, PeerState::IOpen | PeerState::ROpen)
    }

    /// Stable label for metrics (`iwf_peer_state`).
    pub fn label(&self) -> &'static str {
        match self {
            PeerState::Closed => "closed",
            PeerState::WaitConnAck => "wait_conn_ack",
            PeerState::WaitICea => "wait_i_cea",
            PeerState::WaitConnAckElect => "wait_conn_ack_elect",
            PeerState::WaitReturns => "wait_returns",
            PeerState::IOpen => "i_open",
            PeerState::ROpen => "r_open",
            PeerState::Closing => "closing",
        }
    }
}

/// Events fed to the FSM (RFC 6733 §5.6.1 vocabulary).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerEvent {
    /// Administrative start: begin connecting.
    Start,
    /// Our outbound TCP connect completed.
    IRcvConnAck,
    /// Our outbound TCP connect failed.
    IRcvConnNack,
    /// Peer opened an inbound connection and sent CER.
    RRcvCer,
    /// CEA received on our outbound connection (success Result-Code).
    IRcvCea,
    /// CEA received with a failure Result-Code.
    IRcvCeaFailed,
    /// Watchdog: DWR received.
    RcvDwr,
    /// Watchdog: DWA received.
    RcvDwa,
    /// Watchdog timer Tw fired with no traffic since the last DWR.
    TwExpired,
    /// Watchdog: a second Tw elapsed with no DWA — peer is dead.
    WatchdogFailed,
    /// DPR received.
    RcvDpr,
    /// DPA received.
    RcvDpa,
    /// Administrative stop: send DPR and drain.
    Stop,
    /// Transport reported the connection lost.
    PeerDisc,
    /// Collision detected: inbound CER while our outbound is in progress,
    /// and the local Origin-Host wins the election (§5.6.4).
    WinElection,
    /// Collision detected and the local Origin-Host loses the election.
    LoseElection,
}

impl PeerEvent {
    fn name(&self) -> &'static str {
        match self {
            PeerEvent::Start => "Start",
            PeerEvent::IRcvConnAck => "I-Rcv-Conn-Ack",
            PeerEvent::IRcvConnNack => "I-Rcv-Conn-Nack",
            PeerEvent::RRcvCer => "R-Rcv-CER",
            PeerEvent::IRcvCea => "I-Rcv-CEA",
            PeerEvent::IRcvCeaFailed => "I-Rcv-CEA-Failed",
            PeerEvent::RcvDwr => "Rcv-DWR",
            PeerEvent::RcvDwa => "Rcv-DWA",
            PeerEvent::TwExpired => "Tw-Expired",
            PeerEvent::WatchdogFailed => "Watchdog-Failed",
            PeerEvent::RcvDpr => "Rcv-DPR",
            PeerEvent::RcvDpa => "Rcv-DPA",
            PeerEvent::Stop => "Stop",
            PeerEvent::PeerDisc => "Peer-Disc",
            PeerEvent::WinElection => "Win-Election",
            PeerEvent::LoseElection => "Lose-Election",
        }
    }
}

/// Side effects the connection task must execute after a transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerAction {
    /// Open the outbound TCP (TLS) connection.
    Connect,
    /// Send CER on the outbound connection.
    SendCer,
    /// Send CEA (success) on the inbound connection.
    SendCea,
    /// Send DWR.
    SendDwr,
    /// Send DWA.
    SendDwa,
    /// Send DPR with cause REBOOTING.
    SendDpr,
    /// Send DPA, then expect the peer to close.
    SendDpa,
    /// Tear down the transport immediately.
    Disconnect,
    /// Tear down the *initiator* connection only (election lost).
    DisconnectInitiator,
    /// Arm the reconnect timer Tc.
    ArmReconnect,
    /// Arm / re-arm the watchdog timer Tw.
    ArmWatchdog,
    /// Fail over: requeue pending requests to an alternate peer and mark
    /// this peer unavailable for routing.
    Failover,
}

/// Pure-transition peer FSM. The owning task serializes events, so no
/// interior mutability is needed; contention is zero by construction.
#[derive(Debug)]
pub struct PeerFsm {
    state: PeerState,
    /// Count of unanswered DWRs (RFC 3539: fail after the second miss).
    pending_dwr: u8,
}

impl Default for PeerFsm {
    fn default() -> Self {
        Self::new()
    }
}

impl PeerFsm {
    /// A new FSM in `Closed`.
    pub fn new() -> Self {
        PeerFsm {
            state: PeerState::Closed,
            pending_dwr: 0,
        }
    }

    /// Current state.
    pub fn state(&self) -> PeerState {
        self.state
    }

    /// Apply `event`, returning the actions to execute. Unexpected events in
    /// a given state follow §5.6.2's error column: they are answered with a
    /// `Disconnect` of the offending connection rather than a panic, and the
    /// violation is surfaced for logging via the returned action list being
    /// paired with `tracing` at the call site.
    pub fn on_event(&mut self, event: PeerEvent) -> Vec<PeerAction> {
        use PeerAction as A;
        use PeerEvent as E;
        use PeerState as S;

        let (next, actions): (S, Vec<A>) = match (self.state, event) {
            // ---- bring-up -------------------------------------------------
            (S::Closed, E::Start) => (S::WaitConnAck, vec![A::Connect]),
            (S::Closed, E::RRcvCer) => (S::ROpen, vec![A::SendCea, A::ArmWatchdog]),
            (S::WaitConnAck, E::IRcvConnAck) => (S::WaitICea, vec![A::SendCer]),
            (S::WaitConnAck, E::IRcvConnNack) => (S::Closed, vec![A::ArmReconnect]),
            (S::WaitICea, E::IRcvCea) => (S::IOpen, vec![A::ArmWatchdog]),
            (S::WaitICea, E::IRcvCeaFailed) => (S::Closed, vec![A::Disconnect, A::ArmReconnect]),

            // ---- collision / election (§5.6.4) ----------------------------
            (S::WaitConnAck, E::RRcvCer) => (S::WaitConnAckElect, vec![]),
            (S::WaitICea, E::RRcvCer) => (S::WaitConnAckElect, vec![]),
            (S::WaitConnAckElect, E::WinElection) => {
                // Our initiator connection survives; answer their CER is
                // skipped — they must tear down per the RFC.
                (S::WaitICea, vec![A::SendCer])
            }
            (S::WaitConnAckElect, E::LoseElection) => (
                S::ROpen,
                vec![A::DisconnectInitiator, A::SendCea, A::ArmWatchdog],
            ),
            (S::WaitConnAckElect, E::IRcvCea) => (S::WaitReturns, vec![]),
            (S::WaitReturns, E::PeerDisc) => (S::IOpen, vec![A::ArmWatchdog]),

            // ---- watchdog (RFC 3539) --------------------------------------
            (s @ (S::IOpen | S::ROpen), E::RcvDwr) => (s, vec![A::SendDwa, A::ArmWatchdog]),
            (s @ (S::IOpen | S::ROpen), E::RcvDwa) => {
                self.pending_dwr = 0;
                (s, vec![A::ArmWatchdog])
            }
            (s @ (S::IOpen | S::ROpen), E::TwExpired) => {
                self.pending_dwr = self.pending_dwr.saturating_add(1);
                if self.pending_dwr >= 2 {
                    (S::Closed, vec![A::Disconnect, A::Failover, A::ArmReconnect])
                } else {
                    (s, vec![A::SendDwr, A::ArmWatchdog])
                }
            }
            (S::IOpen | S::ROpen, E::WatchdogFailed) => {
                (S::Closed, vec![A::Disconnect, A::Failover, A::ArmReconnect])
            }

            // ---- disconnect (§5.4) ----------------------------------------
            (S::IOpen | S::ROpen, E::Stop) => (S::Closing, vec![A::SendDpr]),
            (S::Closing, E::RcvDpa) => (S::Closed, vec![A::Disconnect]),
            (S::IOpen | S::ROpen, E::RcvDpr) => {
                (S::Closed, vec![A::SendDpa, A::Disconnect, A::Failover])
            }
            (S::IOpen | S::ROpen, E::PeerDisc) => (S::Closed, vec![A::Failover, A::ArmReconnect]),
            (S::Closing, E::PeerDisc) => (S::Closed, vec![]),
            (S::WaitConnAck | S::WaitICea, E::PeerDisc) => (S::Closed, vec![A::ArmReconnect]),
            (S::Closed, E::PeerDisc) => (S::Closed, vec![]),
            (S::Closed, E::Stop) => (S::Closed, vec![]),

            // ---- anything else is a protocol violation (§5.6.2 error row) --
            (state, event) => {
                tracing::warn!(
                    state = state.label(),
                    event = event.name(),
                    "diameter peer FSM violation; closing connection"
                );
                (S::Closed, vec![A::Disconnect, A::ArmReconnect])
            }
        };

        if next != self.state {
            tracing::debug!(
                from = self.state.label(),
                to = next.label(),
                event = event.name(),
                "peer state transition"
            );
        }
        if !next.open() {
            // leaving OPEN resets watchdog accounting
            if !matches!(next, PeerState::Closing) {
                self.pending_dwr = 0;
            }
        }
        self.state = next;
        actions
    }
}

/// Election per RFC 6733 §5.6.4: the peer with the lexicographically higher
/// Origin-Host (octet-wise comparison) wins and keeps the connection it
/// initiated.
pub fn wins_election(local_host: &str, peer_host: &str) -> bool {
    local_host.as_bytes() > peer_host.as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use PeerAction as A;
    use PeerEvent as E;
    use PeerState as S;

    #[test]
    fn happy_path_initiator() {
        let mut fsm = PeerFsm::new();
        assert_eq!(fsm.on_event(E::Start), vec![A::Connect]);
        assert_eq!(fsm.on_event(E::IRcvConnAck), vec![A::SendCer]);
        assert_eq!(fsm.on_event(E::IRcvCea), vec![A::ArmWatchdog]);
        assert_eq!(fsm.state(), S::IOpen);
        assert!(fsm.state().open());
    }

    #[test]
    fn happy_path_responder() {
        let mut fsm = PeerFsm::new();
        assert_eq!(fsm.on_event(E::RRcvCer), vec![A::SendCea, A::ArmWatchdog]);
        assert_eq!(fsm.state(), S::ROpen);
    }

    #[test]
    fn watchdog_two_misses_fails_peer() {
        let mut fsm = PeerFsm::new();
        fsm.on_event(E::RRcvCer);
        // First Tw expiry: send DWR.
        assert_eq!(fsm.on_event(E::TwExpired), vec![A::SendDwr, A::ArmWatchdog]);
        assert_eq!(fsm.state(), S::ROpen);
        // Second expiry without DWA: declare failure and fail over.
        let actions = fsm.on_event(E::TwExpired);
        assert!(actions.contains(&A::Failover));
        assert_eq!(fsm.state(), S::Closed);
    }

    #[test]
    fn dwa_resets_watchdog_counter() {
        let mut fsm = PeerFsm::new();
        fsm.on_event(E::RRcvCer);
        fsm.on_event(E::TwExpired); // DWR out
        fsm.on_event(E::RcvDwa); // answered
                                 // Next miss starts the count again — must not fail immediately.
        assert_eq!(fsm.on_event(E::TwExpired), vec![A::SendDwr, A::ArmWatchdog]);
        assert_eq!(fsm.state(), S::ROpen);
    }

    #[test]
    fn graceful_disconnect() {
        let mut fsm = PeerFsm::new();
        fsm.on_event(E::RRcvCer);
        assert_eq!(fsm.on_event(E::Stop), vec![A::SendDpr]);
        assert_eq!(fsm.state(), S::Closing);
        assert_eq!(fsm.on_event(E::RcvDpa), vec![A::Disconnect]);
        assert_eq!(fsm.state(), S::Closed);
    }

    #[test]
    fn dpr_from_peer_triggers_failover() {
        let mut fsm = PeerFsm::new();
        fsm.on_event(E::RRcvCer);
        let actions = fsm.on_event(E::RcvDpr);
        assert_eq!(actions, vec![A::SendDpa, A::Disconnect, A::Failover]);
    }

    #[test]
    fn collision_election() {
        assert!(wins_election("hss-b.example.org", "hss-a.example.org"));
        assert!(!wins_election("hss-a.example.org", "hss-b.example.org"));

        let mut fsm = PeerFsm::new();
        fsm.on_event(E::Start);
        fsm.on_event(E::IRcvConnAck); // Wait-I-CEA
        fsm.on_event(E::RRcvCer); // collision
        assert_eq!(fsm.state(), S::WaitConnAckElect);
        let actions = fsm.on_event(E::LoseElection);
        assert!(actions.contains(&A::DisconnectInitiator));
        assert_eq!(fsm.state(), S::ROpen);
    }

    #[test]
    fn violation_closes_connection() {
        let mut fsm = PeerFsm::new();
        // DWA in Closed is nonsensical.
        let actions = fsm.on_event(E::RcvDwa);
        assert!(actions.contains(&A::Disconnect));
        assert_eq!(fsm.state(), S::Closed);
    }
}
