#!/usr/bin/env bash
# package.sh — assemble the CDOT-iwf RUNTIME tree and tar it up.
#
# Output layout (NO source code, only binary + config + libraries):
#   CDOT-iwf/
#   ├── bin/  cdot_iwf (control), iwf-node (daemon), loadgen (test tool)
#   ├── etc/  config.yaml, rules.yaml, cdot_iwf.env
#   ├── lib/  bundled shared libraries (libgcc_s)
#   ├── log/  (empty; runtime logs land here)
#   └── run/  (empty; pid file lands here)
#
# Usage: package.sh [stage_dir]      (default /tmp/CDOT-iwf)
set -euo pipefail

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HERE="$SRC_DIR/deploy/cdot"
REL="$SRC_DIR/target/release"
STAGE="${1:-/tmp/CDOT-iwf}"

[ -x "$REL/iwf-node" ] || { echo "[pkg] ERROR: no binary; run deploy/cdot/build.sh first." >&2; exit 1; }

echo "[pkg] staging at $STAGE"
rm -rf "$STAGE"
mkdir -p "$STAGE/bin" "$STAGE/etc" "$STAGE/lib" "$STAGE/log" "$STAGE/run"

# --- binaries + control script ---
install -m 0755 "$REL/iwf-node"     "$STAGE/bin/iwf-node"
install -m 0755 "$REL/loadgen"      "$STAGE/bin/loadgen"
install -m 0755 "$HERE/cdot_iwf"    "$STAGE/bin/cdot_iwf"
install -m 0755 "$HERE/tests.sh"    "$STAGE/bin/tests.sh"

# --- configuration ---
install -m 0644 "$HERE/config.yaml"  "$STAGE/etc/config.yaml"
install -m 0644 "$HERE/rules.yaml"   "$STAGE/etc/rules.yaml"
install -m 0640 "$HERE/cdot_iwf.env" "$STAGE/etc/cdot_iwf.env"

# --- bundled libraries ---
# The binary statically links all Rust crates; only glibc + libgcc_s are
# dynamic. glibc/ld are kept system-provided (not relocatable); libgcc_s is
# bundled for version safety. LD_LIBRARY_PATH=<root>/lib is set by cdot_iwf.
for lib in libgcc_s.so.1; do
    p="$(ldd "$REL/iwf-node" | awk -v l="$lib" '$1==l {print $3}')"
    if [ -n "${p:-}" ] && [ -f "$p" ]; then
        install -m 0644 "$p" "$STAGE/lib/"
        echo "[pkg] bundled lib: $lib  <- $p"
    fi
done

echo "[pkg] tree:"
( cd "$(dirname "$STAGE")" && find "$(basename "$STAGE")" -maxdepth 2 | sort )

TARBALL="${STAGE}.tgz"
tar czf "$TARBALL" -C "$(dirname "$STAGE")" "$(basename "$STAGE")"
echo "[pkg] OK -> $TARBALL"
