#!/usr/bin/env bash
# build.sh — compile CDOT-iwf in the COMPILE environment.
#
# Run this where the source + Rust toolchain live. It produces the release
# binaries under target/release/. Nothing here is shipped except those
# artifacts (see package.sh) — source never goes to the running environment.
set -euo pipefail

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$SRC_DIR"

echo "[build] source tree : $SRC_DIR"
command -v cargo >/dev/null 2>&1 || {
    echo "[build] ERROR: cargo not found. Install Rust (rustup) on the build host." >&2
    exit 1
}
echo "[build] toolchain   : $(rustc --version)"

# Open5GS-on-Ubuntu-20.04 has older glibc; building on that host guarantees a
# compatible binary. The pinned Cargo.lock keeps the dependency set stable.
CARGO_INCREMENTAL=0 cargo build --release --locked -p iwf-node -p iwf-benchmark

echo "[build] artifacts:"
ls -lh "$SRC_DIR/target/release/iwf-node" \
       "$SRC_DIR/target/release/loadgen"
echo "[build] OK"
