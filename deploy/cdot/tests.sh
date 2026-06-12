#!/usr/bin/env bash
# tests.sh — functional test cases for a deployed CDOT-iwf against Open5GS.
#
# Run on the running-environment host (192.168.179.39):
#     /opt/CDOT-iwf/bin/tests.sh
#
# Each test case is a function test_NN_name. The runner executes them in
# order, prints PASS/FAIL per case, and exits non-zero if any failed.
#
# Explicitly requested cases:
#   TEST 01  — IWF registers with the NRF.
#   TEST 02  — generate exactly ONE call and verify it reaches the UDM.
# Plus supporting functional cases (health, readiness, metrics, restart, stop).
set -u

ROOT="${CDOT_IWF_ROOT:-/opt/CDOT-iwf}"
CI="$ROOT/bin/cdot_iwf"
LOADGEN="$ROOT/bin/loadgen"
LOG="$ROOT/log/cdot_iwf.log"

DIAM="127.0.0.99:3868"            # IWF Diameter listener
METRICS="http://127.0.0.1:9090"   # IWF Prometheus
ADMIN="http://127.0.0.1:8080"     # IWF admin (health/ready)

PASS=0
FAIL=0

ok()   { echo "  [PASS] $1"; PASS=$((PASS + 1)); }
bad()  { echo "  [FAIL] $1"; FAIL=$((FAIL + 1)); }
info() { echo "         $1"; }

# NOTE: a metric's value is always the LAST whitespace-separated field
# ($NF), because Prometheus label *values* may contain spaces (the SBA
# `operation` label is e.g. "Get /nudm-sdm/v2/{id}/am-data"). Using $2 would
# read the middle of such a label, not the count.

# Sum of all UDM SBA calls that returned HTTP 200.
udm_200() {
    curl -s "$METRICS/metrics" 2>/dev/null \
        | grep '^iwf_sba_requests_total{' | grep 'nf_type="UDM"' | grep 'http_status="200"' \
        | awk '{s+=$NF} END{print s+0}'
}

# Sum of Cx UAR answers with the given result_code.
uar_rc() {
    curl -s "$METRICS/metrics" 2>/dev/null \
        | grep '^iwf_diameter_requests_total{' | grep 'command="UAR"' \
        | grep "result_code=\"$1\"" | awk '{s+=$NF} END{print s+0}'
}

ensure_running() {
    if ! "$CI" status >/dev/null 2>&1; then
        "$CI" start >/dev/null 2>&1
        sleep 3
    fi
}

# ---------------------------------------------------------------------------
# TEST 01 — IWF registers with the NRF.
# ---------------------------------------------------------------------------
test_01_nrf_registration() {
    echo "TEST 01: IWF registers with NRF"
    # Fresh start so the registration event is current in the log.
    "$CI" restart >/dev/null 2>&1
    sleep 3
    if "$CI" status >/dev/null 2>&1; then
        ok "process is running"
    else
        bad "process did not start"
        return
    fi
    if grep -q "registered with NRF" "$LOG"; then
        ok "log shows 'registered with NRF' (NRF returned 2xx to the registration)"
    else
        bad "no 'registered with NRF' in $LOG"
        tail -n 5 "$LOG" | sed 's/^/         /'
    fi
    # No registration/heartbeat errors lingering.
    if [ "$(grep -c 'heartbeat failed' "$LOG")" = "0" ]; then
        ok "no heartbeat failures"
    else
        info "heartbeat failures present (non-fatal): $(grep -c 'heartbeat failed' "$LOG")"
    fi
}

# ---------------------------------------------------------------------------
# TEST 02 — generate exactly ONE call; verify it reaches the Open5GS UDM
#           and is answered SUCCESS (2001).
# ---------------------------------------------------------------------------
test_02_single_call() {
    echo "TEST 02: single Cx call -> Open5GS UDM"
    ensure_running
    before_udm="$(udm_200)"
    before_ok="$(uar_rc 2001)"

    out="$("$LOADGEN" "$DIAM" --connections 1 --count 1 --seconds 5 2>&1)"
    info "loadgen: $(echo "$out" | grep -E '^sent=' || echo "$out" | tail -1)"

    sleep 1
    after_udm="$(udm_200)"
    after_ok="$(uar_rc 2001)"
    d_udm=$((after_udm - before_udm))
    d_ok=$((after_ok - before_ok))

    if echo "$out" | grep -q "sent=1 answered=1 errors=0"; then
        ok "exactly 1 request sent and answered, 0 errors"
    else
        bad "expected sent=1 answered=1 errors=0"
    fi
    if [ "$d_udm" -eq 1 ]; then
        ok "exactly 1 SBA call to UDM returned HTTP 200 (delta=$d_udm)"
    else
        bad "expected 1 UDM HTTP-200 call, got delta=$d_udm"
    fi
    if [ "$d_ok" -eq 1 ]; then
        ok "exactly 1 Cx UAR answered 2001 SUCCESS (delta=$d_ok)"
    else
        bad "expected 1 UAR=2001, got delta=$d_ok"
    fi
}

# ---------------------------------------------------------------------------
# TEST 03 — liveness endpoint.
# ---------------------------------------------------------------------------
test_03_health_liveness() {
    echo "TEST 03: /healthz liveness"
    ensure_running
    code="$(curl -s -o /dev/null -w '%{http_code}' "$ADMIN/healthz")"
    [ "$code" = "200" ] && ok "/healthz -> 200" || bad "/healthz -> $code"
}

# ---------------------------------------------------------------------------
# TEST 04 — readiness endpoint (ready after a peer/call).
# ---------------------------------------------------------------------------
test_04_readiness() {
    echo "TEST 04: /readyz readiness"
    ensure_running
    # A call connects a Diameter peer, which flips readiness on.
    "$LOADGEN" "$DIAM" --connections 1 --count 1 --seconds 5 >/dev/null 2>&1
    sleep 1
    code="$(curl -s -o /dev/null -w '%{http_code}' "$ADMIN/readyz")"
    [ "$code" = "200" ] && ok "/readyz -> 200 (NRF-registered + peer connected)" \
                        || bad "/readyz -> $code"
}

# ---------------------------------------------------------------------------
# TEST 05 — metrics exposition.
# ---------------------------------------------------------------------------
test_05_metrics_exposed() {
    echo "TEST 05: /metrics exposition"
    ensure_running
    body="$(curl -s "$METRICS/metrics")"
    for fam in iwf_diameter_requests_total iwf_sba_requests_total iwf_active_sessions_total; do
        if echo "$body" | grep -q "$fam"; then ok "exposes $fam"; else bad "missing $fam"; fi
    done
}

# ---------------------------------------------------------------------------
# TEST 06 — restart works.
# ---------------------------------------------------------------------------
test_06_restart() {
    echo "TEST 06: restart"
    "$CI" restart >/dev/null 2>&1
    sleep 3
    "$CI" status >/dev/null 2>&1 && ok "RUNNING after restart" || bad "not running after restart"
}

# ---------------------------------------------------------------------------
# TEST 07 — graceful stop.
# ---------------------------------------------------------------------------
test_07_graceful_stop() {
    echo "TEST 07: graceful stop"
    "$CI" stop >/dev/null 2>&1
    if "$CI" status >/dev/null 2>&1; then
        bad "still running after stop"
    else
        ok "STOPPED after stop"
    fi
    if grep -q "drain complete; exiting" "$LOG"; then
        ok "log shows clean drain ('drain complete; exiting')"
    else
        info "no 'drain complete' line (check $LOG)"
    fi
}

# --------------------------------- runner ----------------------------------
echo "==================================================================="
echo " CDOT-iwf functional test cases   (install: $ROOT)"
echo "==================================================================="
[ -x "$CI" ]      || { echo "FATAL: $CI not found"; exit 1; }
[ -x "$LOADGEN" ] || { echo "FATAL: $LOADGEN not found"; exit 1; }

test_01_nrf_registration
test_02_single_call
test_03_health_liveness
test_04_readiness
test_05_metrics_exposed
test_06_restart
test_07_graceful_stop

echo "-------------------------------------------------------------------"
echo " RESULT: PASS=$PASS  FAIL=$FAIL"
echo "-------------------------------------------------------------------"
[ "$FAIL" -eq 0 ] || exit 1
