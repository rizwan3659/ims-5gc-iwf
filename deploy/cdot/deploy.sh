#!/usr/bin/env bash
# deploy.sh — ship the packaged runtime tree to the RUNNING environment and
# install it under <parent>/CDOT-iwf (default /opt). No source is copied.
#
# Usage: deploy.sh <user@host> [install_parent]
#   e.g. deploy.sh root@192.168.179.39 /opt
#
# Auth: uses ssh/scp. For password auth either use an SSH key, or prefix with
#   SSHPASS='...' sshpass -e   (wrap the ssh/scp calls) — see STEPS doc.
set -euo pipefail

TARGET="${1:?usage: deploy.sh user@host [install_parent]}"
PARENT="${2:-/opt}"
PKG="/tmp/CDOT-iwf.tgz"

[ -f "$PKG" ] || { echo "[deploy] ERROR: $PKG missing; run package.sh first." >&2; exit 1; }

echo "[deploy] copying $PKG -> $TARGET:/tmp/"
scp "$PKG" "$TARGET:/tmp/CDOT-iwf.tgz"

echo "[deploy] installing under $PARENT/CDOT-iwf"
ssh "$TARGET" "set -e
    mkdir -p '$PARENT'
    # Stop a previous instance (preserve its etc/ + log/).
    if [ -x '$PARENT/CDOT-iwf/bin/cdot_iwf' ]; then
        '$PARENT/CDOT-iwf/bin/cdot_iwf' stop || true
        # keep operator-edited config: back it up, restore after extract
        cp -a '$PARENT/CDOT-iwf/etc' /tmp/cdot-etc-backup 2>/dev/null || true
    fi
    tar xzf /tmp/CDOT-iwf.tgz -C '$PARENT'
    rm -f /tmp/CDOT-iwf.tgz
    echo 'installed:'
    ls -R '$PARENT/CDOT-iwf' | sed 's/^/  /'
"
echo "[deploy] done. Start with:  ssh $TARGET '$PARENT/CDOT-iwf/bin/cdot_iwf start'"
