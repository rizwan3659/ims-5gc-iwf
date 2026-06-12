# ADR-0002: Zero-copy Diameter codec on bytes::Bytes

## Status
Accepted.

## Context
At 100k TPS each message is decoded once and (its answer) encoded once.
Per-AVP heap copies would dominate the allocation profile; the 5 ms internal
budget leaves no room for allocator churn at p99.

## Decision
- The transport reads each frame into exactly one `BytesMut` (sized from the
  Message-Length header) and freezes it.
- Every `Avp.data` is a `Bytes` slice handle into that buffer — refcount
  bump, no copy. Grouped AVPs decode recursively over sub-slices with a hard
  depth bound of 8 (decompression-bomb defence).
- Strict validation before any slice: version, 32-bit alignment, declared
  vs actual length, AVP header bounds, vendor-bit/length consistency.
  Malformed input returns `DiameterError`, never panics (proptest-fuzzed).
- Encoding builds one `BytesMut` per answer sized by a pre-computed
  `encoded_len` pass — one allocation per message.

## Consequences / rejected alternatives
- *Wrapping libdiameter / C FFI (rejected, also forbidden by mandate)*:
  memory-safety surface and unsafe interop in the most attacker-exposed
  parser of the node.
- *Owned `Vec<u8>` per AVP (rejected)*: ~10 allocations/message at our AVP
  counts; measured orders-of-magnitude worse allocator pressure.
- Frame buffers live as long as any AVP slice; bounded by the per-connection
  frame cap (1 MiB) and transaction deadlines.
