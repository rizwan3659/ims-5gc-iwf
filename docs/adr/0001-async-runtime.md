# ADR-0001: Tokio multi-threaded runtime, one process per pod

## Status
Accepted.

## Context
The IWF must sustain ≥100k TPS with p99 internal latency <5 ms. The work is
overwhelmingly I/O-bound (Diameter TCP, HTTP/2 SBI) with small CPU bursts
(codec, rule evaluation). Candidates: (a) Tokio multi-threaded work-stealing
runtime, (b) thread-per-core runtimes (monoio/glommio, io_uring),
(c) hand-rolled epoll loop.

## Decision
Tokio multi-threaded, default worker count = available parallelism (under
Kubernetes this is the cgroup CPU quota, i.e. `resources.limits.cpu`).
Blocking work (none on the hot path) is confined to `spawn_blocking`.

## Consequences / rejected alternatives
- *Thread-per-core (rejected)*: 10–20% potential latency win, but the
  ecosystem (hyper, axum, rustls) is built on Tokio's `Send` model; the
  integration risk and forked-ecosystem maintenance cost outweigh the win at
  our latency budget. Revisit if profiling shows scheduler contention.
- *Hand-rolled epoll (rejected)*: maximal control, unacceptable defect risk
  for a five-nines target; we would re-implement timers, wakers, backpressure.
- Horizontal scale is the primary throughput axis (stateless pods, ADR-0004),
  so per-core efficiency is a cost knob, not a feasibility knob.
