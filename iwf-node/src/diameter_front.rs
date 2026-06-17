//! Diameter front-end: TCP listener, per-connection responder driven by the
//! RFC 6733 peer FSM, ingress backpressure, and graceful drain.
//!
//! Each accepted connection gets:
//! - a **reader task** decoding frames and dispatching them,
//! - a **writer task** consuming a bounded answer queue (backpressure:
//!   when the queue is full the transaction is shed with 3004),
//! - watchdog handling (DWR answered immediately; on our side the
//!   peer's DWR cadence is supervised by an idle timer).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use iwf_admin::Readiness;
use iwf_core::error::CoreError;
use iwf_diameter::avp::AvpValue;
use iwf_diameter::base::{parse_capabilities, LocalIdentity};
use iwf_diameter::dictionary as dict;
use iwf_diameter::message::{Message, MessageBuilder};
use iwf_diameter::peer::{PeerEvent, PeerFsm};
use iwf_diameter::transport::{read_frame, write_frame, DEFAULT_MAX_FRAME};
use iwf_observability::Metrics;
use iwf_translation::TranslationEngine;
use tokio::io::{AsyncWriteExt, BufWriter};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

use crate::peer_registry::PeerRegistry;

/// Shared front-end state.
pub struct DiameterFront {
    config: Arc<iwf_config::Config>,
    engine: Arc<TranslationEngine>,
    metrics: Metrics,
    readiness: Arc<Readiness>,
    in_flight: Arc<AtomicU64>,
    /// Registry of OPEN peers, so the notification path can originate
    /// requests (RTR/PPR/PNR/RAR/ASR) into a live connection.
    peers: Arc<PeerRegistry>,
}

/// Handle used by the shutdown sequence.
pub struct FrontHandle {
    in_flight: Arc<AtomicU64>,
    accept_stop: Arc<tokio::sync::Notify>,
}

impl FrontHandle {
    /// Stop accepting, then wait until in-flight transactions complete or
    /// the drain budget elapses.
    pub async fn drain(&self, budget: Duration) {
        self.accept_stop.notify_waiters();
        let deadline = std::time::Instant::now() + budget;
        while self.in_flight.load(Ordering::Acquire) > 0 {
            if std::time::Instant::now() >= deadline {
                tracing::warn!(
                    remaining = self.in_flight.load(Ordering::Acquire),
                    "drain budget exhausted; abandoning remaining transactions"
                );
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
}

impl DiameterFront {
    /// Build the front-end.
    pub fn new(
        config: Arc<iwf_config::Config>,
        engine: Arc<TranslationEngine>,
        metrics: Metrics,
        readiness: Arc<Readiness>,
        peers: Arc<PeerRegistry>,
    ) -> Self {
        DiameterFront {
            config,
            engine,
            metrics,
            readiness,
            in_flight: Arc::new(AtomicU64::new(0)),
            peers,
        }
    }

    /// Bind and start the accept loop.
    pub async fn spawn(self) -> std::io::Result<FrontHandle> {
        let listener = TcpListener::bind(&self.config.diameter.listen).await?;
        let accept_stop = Arc::new(tokio::sync::Notify::new());
        let handle = FrontHandle {
            in_flight: self.in_flight.clone(),
            accept_stop: accept_stop.clone(),
        };
        let front = Arc::new(self);
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = accept_stop.notified() => {
                        tracing::info!("diameter accept loop stopped (drain)");
                        return;
                    }
                    accepted = listener.accept() => match accepted {
                        Ok((stream, peer_addr)) => {
                            if let Err(e) = stream.set_nodelay(true) {
                                tracing::warn!(error = %e, "set_nodelay failed");
                            }
                            tracing::info!(%peer_addr, "diameter connection accepted");
                            let front = front.clone();
                            tokio::spawn(async move {
                                front.handle_connection(stream).await;
                            });
                        }
                        Err(e) => {
                            tracing::error!(error = %e, "accept failed");
                            tokio::time::sleep(Duration::from_millis(100)).await;
                        }
                    }
                }
            }
        });
        Ok(handle)
    }

    fn local_identity(&self) -> LocalIdentity {
        LocalIdentity {
            origin_host: self.config.diameter.origin_host.clone(),
            origin_realm: self.config.diameter.origin_realm.clone(),
            product_name: "iwf".to_owned(),
            vendor_id: dict::VENDOR_3GPP,
            applications: vec![dict::APP_CX, dict::APP_SH],
            origin_state_id: std::process::id(),
        }
    }

    async fn handle_connection(self: &Arc<Self>, stream: tokio::net::TcpStream) {
        let (mut reader, writer) = stream.into_split();
        // Bounded answer queue: this is the per-connection backpressure
        // boundary called out in the reliability requirements.
        let (answer_tx, mut answer_rx) = mpsc::channel::<Message>(4096);

        // Writer task.
        let writer_task = tokio::spawn(async move {
            let mut writer = BufWriter::new(writer);
            while let Some(message) = answer_rx.recv().await {
                if let Err(e) = write_frame(&mut writer, &message).await {
                    tracing::warn!(error = %e, "diameter write failed");
                    return;
                }
                // Drain whatever else is queued before flushing so bursts
                // coalesce into one syscall, then flush to bound latency.
                while let Ok(more) = answer_rx.try_recv() {
                    if let Err(e) = write_frame(&mut writer, &more).await {
                        tracing::warn!(error = %e, "diameter write failed");
                        return;
                    }
                }
                if let Err(e) = writer.flush().await {
                    tracing::warn!(error = %e, "diameter flush failed");
                    return;
                }
            }
        });

        let mut fsm = PeerFsm::new();
        let local = self.local_identity();
        let mut peer_host = String::from("unknown");
        // Set once the peer reaches OPEN; the reader loop routes answers to
        // these waiters and the connection deregisters on exit.
        let mut pending: Option<crate::peer_registry::Pending> = None;
        let watchdog = self.config.watchdog_interval();
        // Peer supervision: if no traffic (including DWR) arrives within two
        // watchdog intervals the connection is considered dead (RFC 3539).
        let idle_limit = watchdog * 2;

        loop {
            let frame = match tokio::time::timeout(
                idle_limit,
                read_frame(&mut reader, DEFAULT_MAX_FRAME),
            )
            .await
            {
                Err(_) => {
                    tracing::warn!(peer = %peer_host, "peer idle past watchdog budget; closing");
                    break;
                }
                Ok(Err(e)) => {
                    tracing::warn!(peer = %peer_host, error = %e, "diameter read failed");
                    break;
                }
                Ok(Ok(None)) => {
                    tracing::info!(peer = %peer_host, "peer closed connection");
                    break;
                }
                Ok(Ok(Some(frame))) => frame,
            };

            let message = match Message::decode(frame) {
                Ok(m) => m,
                Err(e) => {
                    tracing::warn!(peer = %peer_host, error = %e, "undecodable frame; closing");
                    break;
                }
            };

            match (message.header.command, message.header.flags.request()) {
                (dict::CMD_CER, true) => match parse_capabilities(&message) {
                    Ok(caps)
                        if caps
                            .applications
                            .iter()
                            .any(|a| local.applications.contains(a) || *a == dict::APP_RELAY) =>
                    {
                        peer_host = caps.origin_host.clone();
                        fsm.on_event(PeerEvent::RRcvCer);
                        self.metrics.set_peer_state(&peer_host, fsm.state().label());
                        self.readiness.peer_connected.store(true, Ordering::Release);
                        // Register for origination: the notification path can
                        // now push RTR/PPR/PNR/RAR/ASR into this connection's
                        // writer queue and await the answer via `pending`.
                        pending = Some(self.peers.register(&peer_host, answer_tx.clone()));
                        let cea = local.build_cea(&message, dict::RC_SUCCESS);
                        if answer_tx.send(cea).await.is_err() {
                            break;
                        }
                    }
                    Ok(_) => {
                        let cea = local.build_cea(&message, dict::RC_APPLICATION_UNSUPPORTED);
                        let _ = answer_tx.send(cea).await;
                        break;
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "malformed CER");
                        break;
                    }
                },
                (dict::CMD_DWR, true) => {
                    fsm.on_event(PeerEvent::RcvDwr);
                    if answer_tx.send(local.build_dwa(&message)).await.is_err() {
                        break;
                    }
                }
                (dict::CMD_DPR, true) => {
                    fsm.on_event(PeerEvent::RcvDpr);
                    self.metrics.set_peer_state(&peer_host, fsm.state().label());
                    let _ = answer_tx.send(local.build_dpa(&message)).await;
                    break;
                }
                (_, true) if fsm.state().open() => {
                    self.dispatch_request(message, &answer_tx).await;
                }
                (_, true) => {
                    // Application request before capabilities exchange.
                    tracing::warn!(
                        command = message.header.command,
                        "request before CER/CEA; protocol violation"
                    );
                    break;
                }
                (_, false) => {
                    // Answer to a request we originated (RTR/PPR/PNR/RAR/ASR):
                    // hand it to the waiting originator by Hop-by-Hop id.
                    // Unmatched answers (no waiter) are unsolicited; ignore.
                    let hbh = message.header.hop_by_hop;
                    let matched = pending
                        .as_ref()
                        .is_some_and(|p| PeerRegistry::resolve_answer(p, hbh, message));
                    if !matched {
                        tracing::debug!(hop_by_hop = hbh, "unsolicited answer ignored");
                    }
                }
            }
        }

        fsm.on_event(PeerEvent::PeerDisc);
        self.metrics.set_peer_state(&peer_host, fsm.state().label());
        if pending.is_some() {
            self.peers.deregister(&peer_host);
        }
        drop(answer_tx);
        let _ = writer_task.await;
    }

    async fn dispatch_request(&self, message: Message, answer_tx: &mpsc::Sender<Message>) {
        let interface = match message.header.application {
            dict::APP_CX => "cx",
            dict::APP_SH => "sh",
            dict::APP_SWX => "swx",
            dict::APP_ZH => "zh",
            _ => "other",
        };
        let command = command_label(message.header.command);

        // Ingress shedding: protect latency rather than queue unboundedly.
        let active = self.in_flight.load(Ordering::Acquire);
        if active >= self.config.diameter.max_in_flight {
            self.metrics
                .diameter_requests
                .with_label_values(&[interface, command, "3004"])
                .inc();
            let busy = error_answer(&message, dict::RC_TOO_BUSY, &self.local_identity());
            let _ = answer_tx.try_send(busy);
            return;
        }

        self.in_flight.fetch_add(1, Ordering::AcqRel);
        self.metrics
            .active_sessions
            .set(self.in_flight.load(Ordering::Acquire) as i64);

        let engine = self.engine.clone();
        let metrics = self.metrics.clone();
        let in_flight = self.in_flight.clone();
        let answer_tx = answer_tx.clone();
        let local = self.local_identity();
        let timeout = self.config.transaction_timeout();
        let correlation = iwf_observability::correlation_id();

        tokio::spawn(async move {
            let started = std::time::Instant::now();
            let span = tracing::info_span!(
                "diameter_transaction",
                interface,
                command,
                correlation_id = %correlation
            );
            let _guard = span.enter();

            let result =
                tokio::time::timeout(timeout, engine.translate(&message, &correlation)).await;
            let answer = match result {
                Ok(Ok(answer)) => answer,
                Ok(Err(e)) => {
                    metrics
                        .translation_errors
                        .with_label_values(&["-", error_type(&e)])
                        .inc();
                    error_answer_for(&message, &e, &local)
                }
                Err(_) => {
                    metrics
                        .translation_errors
                        .with_label_values(&["-", "deadline"])
                        .inc();
                    error_answer(&message, dict::RC_UNABLE_TO_DELIVER, &local)
                }
            };

            let result_code = answer
                .result_code()
                .map(|c| c.to_string())
                .unwrap_or_else(|| "experimental".to_owned());
            metrics
                .diameter_requests
                .with_label_values(&[interface, command, &result_code])
                .inc();
            metrics
                .diameter_latency
                .with_label_values(&[interface, command])
                .observe(started.elapsed().as_secs_f64());

            if answer_tx.send(answer).await.is_err() {
                tracing::debug!("connection gone before answer");
            }
            in_flight.fetch_sub(1, Ordering::AcqRel);
            metrics
                .active_sessions
                .set(in_flight.load(Ordering::Acquire) as i64);
        });
    }
}

fn command_label(code: u32) -> &'static str {
    match code {
        dict::CMD_UAR => "UAR",
        dict::CMD_SAR => "SAR",
        dict::CMD_LIR => "LIR",
        dict::CMD_MAR => "MAR",
        dict::CMD_RTR => "RTR",
        dict::CMD_PPR => "PPR",
        dict::CMD_UDR => "UDR",
        dict::CMD_PUR => "PUR",
        dict::CMD_SNR => "SNR",
        dict::CMD_PNR => "PNR",
        _ => "OTHER",
    }
}

fn error_type(e: &CoreError) -> &'static str {
    match e {
        CoreError::NoRule { .. } => "no_rule",
        CoreError::MissingElement(_) => "missing_avp",
        CoreError::NfUnavailable { .. } => "nf_unavailable",
        CoreError::DeadlineExceeded => "deadline",
        CoreError::Overloaded => "overload",
        _ => "other",
    }
}

fn error_answer(request: &Message, result_code: u32, local: &LocalIdentity) -> Message {
    let mut b = MessageBuilder::answer_to(&request.header);
    if let Some(sid) = request.session_id() {
        b = b.std(dict::AVP_SESSION_ID, AvpValue::Utf8(sid.to_owned()));
    }
    b.std(dict::AVP_RESULT_CODE, AvpValue::U32(result_code))
        .std(
            dict::AVP_ORIGIN_HOST,
            AvpValue::Utf8(local.origin_host.clone()),
        )
        .std(
            dict::AVP_ORIGIN_REALM,
            AvpValue::Utf8(local.origin_realm.clone()),
        )
        .build()
}

fn error_answer_for(request: &Message, e: &CoreError, local: &LocalIdentity) -> Message {
    use iwf_core::error::ErrorDisposition::*;
    // Classification lives in `CoreError::disposition` (exhaustive); here we
    // only map the small, stable disposition set onto Diameter Result-Codes.
    // Transient conditions (downstream unavailable, deadline, overload) get a
    // *retryable* code so the peer routes elsewhere — they no longer fall into
    // the permanent 5012 bucket a `_` catch-all produced.
    let code = match e.disposition() {
        Unsupported => dict::RC_COMMAND_UNSUPPORTED, // 3001
        MissingData => dict::RC_MISSING_AVP,         // 5005
        InvalidInput => dict::RC_INVALID_AVP_VALUE,  // 5004
        Unavailable => dict::RC_UNABLE_TO_DELIVER,   // 3002 (transient)
        Overload => dict::RC_TOO_BUSY,               // 3004 (transient)
        // User-unknown is normally surfaced as Experimental-Result 5001 by the
        // rule's answer builder; this plain-Result-Code path is the fallback.
        NotFound | Permanent => dict::RC_UNABLE_TO_COMPLY, // 5012
    };
    error_answer(request, code, local)
}
