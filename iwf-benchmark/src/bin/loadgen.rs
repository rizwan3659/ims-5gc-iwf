//! Diameter load generator for TPS validation.
//!
//! Opens N connections to the target IWF, performs CER/CEA on each, then
//! drives UARs at the requested aggregate rate, reporting achieved TPS and
//! latency percentiles. 100k TPS acceptance runs use multiple generator
//! pods; see docs/runbook.md §Benchmarking.
//!
//! Usage:
//! ```text
//! loadgen <host:port> [--tps N] [--connections N] [--seconds N]
//! ```

#![deny(warnings)]
#![forbid(unsafe_code)]

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use iwf_benchmark::sample_uar;
use iwf_diameter::base::LocalIdentity;
use iwf_diameter::dictionary as dict;
use iwf_diameter::message::Message;
use iwf_diameter::transport::{read_frame, write_frame, DEFAULT_MAX_FRAME};
use tokio::net::TcpStream;

#[derive(Debug, Clone)]
struct Args {
    target: String,
    tps: u64,
    connections: usize,
    seconds: u64,
    /// Send exactly this many requests in total then stop (0 = unlimited,
    /// bounded only by `seconds`). Useful for single-call functional tests.
    count: u64,
}

fn parse_args() -> Result<Args, String> {
    let mut argv = std::env::args().skip(1);
    let target = argv.next().ok_or(
        "usage: loadgen <host:port> [--tps N] [--connections N] [--seconds N] [--count N]",
    )?;
    let mut args = Args {
        target,
        tps: 1000,
        connections: 8,
        seconds: 30,
        count: 0,
    };
    while let Some(flag) = argv.next() {
        let value: u64 = argv
            .next()
            .ok_or(format!("missing value for {flag}"))?
            .parse()
            .map_err(|e| format!("{flag}: {e}"))?;
        match flag.as_str() {
            "--tps" => args.tps = value,
            "--connections" => args.connections = value as usize,
            "--seconds" => args.seconds = value,
            "--count" => args.count = value,
            other => return Err(format!("unknown flag {other}")),
        }
    }
    Ok(args)
}

struct Stats {
    sent: AtomicU64,
    ok: AtomicU64,
    errors: AtomicU64,
    /// Latency histogram: microsecond buckets, fixed width to 100 ms.
    latency_us: Vec<AtomicU64>,
}

const BUCKET_US: u64 = 100;
const BUCKETS: usize = 1000; // 0 .. 100 ms

impl Stats {
    fn new() -> Self {
        Stats {
            sent: AtomicU64::new(0),
            ok: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            latency_us: (0..BUCKETS).map(|_| AtomicU64::new(0)).collect(),
        }
    }

    fn observe(&self, latency: Duration) {
        let bucket = ((latency.as_micros() as u64) / BUCKET_US).min(BUCKETS as u64 - 1);
        self.latency_us[bucket as usize].fetch_add(1, Ordering::Relaxed);
    }

    fn percentile(&self, p: f64) -> Duration {
        let total: u64 = self
            .latency_us
            .iter()
            .map(|b| b.load(Ordering::Relaxed))
            .sum();
        if total == 0 {
            return Duration::ZERO;
        }
        let want = (total as f64 * p).ceil() as u64;
        let mut seen = 0;
        for (i, bucket) in self.latency_us.iter().enumerate() {
            seen += bucket.load(Ordering::Relaxed);
            if seen >= want {
                return Duration::from_micros((i as u64 + 1) * BUCKET_US);
            }
        }
        Duration::from_micros(BUCKETS as u64 * BUCKET_US)
    }
}

async fn connection_loop(
    args: Args,
    per_conn_tps: u64,
    stats: Arc<Stats>,
    stop: Arc<tokio::sync::Notify>,
) -> Result<(), String> {
    let stream = TcpStream::connect(&args.target)
        .await
        .map_err(|e| format!("connect {}: {e}", args.target))?;
    stream.set_nodelay(true).map_err(|e| e.to_string())?;
    let (mut reader, mut writer) = stream.into_split();

    // Capabilities exchange.
    let local = LocalIdentity {
        origin_host: "loadgen.test.example.org".to_owned(),
        origin_realm: "test.example.org".to_owned(),
        product_name: "iwf-loadgen".to_owned(),
        vendor_id: dict::VENDOR_3GPP,
        applications: vec![dict::APP_CX],
        origin_state_id: std::process::id(),
    };
    write_frame(&mut writer, &local.build_cer(1, 1))
        .await
        .map_err(|e| format!("CER: {e}"))?;
    let cea = read_frame(&mut reader, DEFAULT_MAX_FRAME)
        .await
        .map_err(|e| format!("CEA read: {e}"))?
        .ok_or("connection closed during capabilities exchange")?;
    let cea = Message::decode(cea).map_err(|e| format!("CEA decode: {e}"))?;
    if cea.result_code() != Some(dict::RC_SUCCESS) {
        return Err(format!("CEA result {:?}", cea.result_code()));
    }

    // Pending-transaction timestamps keyed by hop-by-hop id.
    let pending: Arc<dashmap_lite::Map> = Arc::new(dashmap_lite::Map::new());

    // Reader half: match answers, record latency.
    let reader_stats = stats.clone();
    let reader_pending = pending.clone();
    let reader_task = tokio::spawn(async move {
        loop {
            match read_frame(&mut reader, DEFAULT_MAX_FRAME).await {
                Ok(Some(frame)) => {
                    if let Ok(answer) = Message::decode(frame) {
                        if answer.header.command == dict::CMD_DWR && answer.header.flags.request() {
                            continue; // watchdog handled by writer below
                        }
                        if let Some(t0) = reader_pending.remove(answer.header.hop_by_hop) {
                            reader_stats.observe(t0.elapsed());
                            reader_stats.ok.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
                Ok(None) | Err(_) => return,
            }
        }
    });

    // Writer half: paced request generation.
    let interval = Duration::from_nanos(1_000_000_000 / per_conn_tps.max(1));
    // Per-connection request cap when --count was given (0 = unlimited).
    let per_conn_count = if args.count > 0 {
        (args.count / args.connections.max(1) as u64).max(1)
    } else {
        0
    };
    let mut next = Instant::now();
    let mut hbh: u32 = 2;
    let mut sent_here: u64 = 0;
    let deadline = Instant::now() + Duration::from_secs(args.seconds);
    loop {
        if Instant::now() >= deadline {
            break;
        }
        if per_conn_count > 0 && sent_here >= per_conn_count {
            break;
        }
        tokio::select! {
            _ = stop.notified() => break,
            _ = tokio::time::sleep_until(tokio::time::Instant::from_std(next)) => {
                hbh = hbh.wrapping_add(1);
                let request = sample_uar(hbh, hbh);
                pending.insert(hbh, Instant::now());
                stats.sent.fetch_add(1, Ordering::Relaxed);
                sent_here += 1;
                if write_frame(&mut writer, &request).await.is_err() {
                    stats.errors.fetch_add(1, Ordering::Relaxed);
                    break;
                }
                next += interval;
                if next < Instant::now() {
                    next = Instant::now(); // fell behind; don't burst
                }
            }
        }
    }

    // Allow stragglers to land.
    tokio::time::sleep(Duration::from_millis(500)).await;
    reader_task.abort();
    Ok(())
}

/// Tiny lock-sharded map (avoids pulling dashmap into the bin's hot loop
/// dependency surface; 64 shards is plenty for one connection's pending set).
mod dashmap_lite {
    use std::collections::HashMap;
    use std::sync::Mutex;
    use std::time::Instant;

    pub struct Map {
        shards: Vec<Mutex<HashMap<u32, Instant>>>,
    }

    impl Map {
        pub fn new() -> Self {
            Map {
                shards: (0..64).map(|_| Mutex::new(HashMap::new())).collect(),
            }
        }
        fn shard(&self, key: u32) -> &Mutex<HashMap<u32, Instant>> {
            &self.shards[(key as usize) & 63]
        }
        pub fn insert(&self, key: u32, value: Instant) {
            if let Ok(mut shard) = self.shard(key).lock() {
                shard.insert(key, value);
            }
        }
        pub fn remove(&self, key: u32) -> Option<Instant> {
            self.shard(key).lock().ok()?.remove(&key)
        }
    }
}

#[tokio::main]
async fn main() {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(2);
        }
    };
    let stats = Arc::new(Stats::new());
    let stop = Arc::new(tokio::sync::Notify::new());
    let per_conn_tps = (args.tps / args.connections as u64).max(1);

    println!(
        "target={} tps={} connections={} seconds={} (per-conn {per_conn_tps} tps)",
        args.target, args.tps, args.connections, args.seconds
    );

    let started = Instant::now();
    let mut tasks = Vec::new();
    for _ in 0..args.connections {
        tasks.push(tokio::spawn(connection_loop(
            args.clone(),
            per_conn_tps,
            stats.clone(),
            stop.clone(),
        )));
    }
    for task in tasks {
        match task.await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => eprintln!("connection error: {e}"),
            Err(e) => eprintln!("task panicked: {e}"),
        }
    }

    let elapsed = started.elapsed().as_secs_f64();
    let sent = stats.sent.load(Ordering::Relaxed);
    let ok = stats.ok.load(Ordering::Relaxed);
    println!(
        "sent={sent} answered={ok} errors={} achieved_tps={:.0}",
        stats.errors.load(Ordering::Relaxed),
        ok as f64 / elapsed,
    );
    println!(
        "latency p50={:?} p95={:?} p99={:?} p999={:?}",
        stats.percentile(0.50),
        stats.percentile(0.95),
        stats.percentile(0.99),
        stats.percentile(0.999),
    );
    // Exit non-zero if more than 0.1% of requests went unanswered.
    if sent > 0 && (sent - ok) * 1000 > sent {
        std::process::exit(1);
    }
}
