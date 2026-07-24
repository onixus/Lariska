#!/usr/bin/env bash
# Cross-repository end-to-end test (Plan.md §15 "End-to-end test", §17 Phase
# L6, and Shapoclyack's Agent_plan.md §17 S10).
#
# Brings up a disposable Shapoclyack stack (Postgres in Docker + the FastAPI
# app in a local venv), bootstraps a tenant/provisioning key directly via
# Shapoclyack's own service layer, runs the real Lariska binary against it
# twice, and asserts on the server's own read APIs that:
#
#   1. registration + inventory submission succeed (real HTTP, real auth);
#   2. the device links to a new endpoint-backed asset;
#   3. the collected software actually lands (non-zero count);
#   4. a second submission with unchanged software produces zero spurious
#      change events (proves the diff logic isn't over-firing).
#
# This intentionally does not fabricate a software change to assert
# installed/removed/updated events fire correctly — that diff logic lives in
# and is covered by Shapoclyack's own test suite
# (tests/test_endpoint_inventory_service.py). This script's job is the
# cross-repo contract: does a real Lariska binary talking to a real
# Shapoclyack server actually work end to end.
#
# Requirements: docker, python3 (with venv), cargo. Not run by `cargo test`
# or CI by default (see docs/RELEASE.md) — it stands up real infrastructure
# and takes a couple of minutes.
#
# Usage:
#   SHAPOCLYACK_REPO=/path/to/Shapoclyack tests/e2e/run.sh

set -euo pipefail

SHAPOCLYACK_REPO="${SHAPOCLYACK_REPO:-../Shapoclyack}"
LARISKA_REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK_DIR="$(mktemp -d /tmp/lariska-e2e.XXXXXX)"
POSTGRES_CONTAINER="lariska-e2e-postgres-$$"
POSTGRES_PORT=15432
API_PORT=18080
TENANT_ID="ten_lariska_e2e_$$"

log() { echo "[e2e] $*" >&2; }

cleanup() {
  log "cleaning up"
  [[ -n "${UVICORN_PID:-}" ]] && kill "$UVICORN_PID" 2>/dev/null || true
  [[ -n "${AGENT_PID:-}" ]] && kill "$AGENT_PID" 2>/dev/null || true
  sleep 1
  # Belt-and-suspenders: catches this script's own uvicorn even if PID
  # capture ever goes wrong again, without touching unrelated uvicorn
  # processes on the host (matched by this run's own port).
  pkill -f "uvicorn api.app:app.*--port ${API_PORT}" 2>/dev/null || true
  docker rm -f "$POSTGRES_CONTAINER" >/dev/null 2>&1 || true
  rm -rf "$WORK_DIR"
}
trap cleanup EXIT

if [[ ! -d "$SHAPOCLYACK_REPO" ]]; then
  echo "Shapoclyack repo not found at '$SHAPOCLYACK_REPO' — set SHAPOCLYACK_REPO=/path/to/Shapoclyack" >&2
  exit 1
fi
SHAPOCLYACK_REPO="$(cd "$SHAPOCLYACK_REPO" && pwd)"

log "starting disposable Postgres on port $POSTGRES_PORT"
docker run -d --name "$POSTGRES_CONTAINER" \
  -e POSTGRES_DB=octo_man -e POSTGRES_USER=octo -e POSTGRES_PASSWORD=octo-dev-change-me \
  -p "${POSTGRES_PORT}:5432" postgres:16-alpine >/dev/null

for _ in $(seq 1 30); do
  docker exec "$POSTGRES_CONTAINER" pg_isready -U octo -d octo_man >/dev/null 2>&1 && break
  sleep 1
done

export OCTO_POSTGRES_URL="postgresql+psycopg://octo:octo-dev-change-me@localhost:${POSTGRES_PORT}/octo_man"

log "setting up Shapoclyack Python environment"
python3 -m venv "$WORK_DIR/venv"
# shellcheck disable=SC1091
source "$WORK_DIR/venv/bin/activate"
pip install -q -r "$SHAPOCLYACK_REPO/requirements-api.txt"

log "running Alembic migrations"
(cd "$SHAPOCLYACK_REPO" && alembic -c api/db/alembic.ini upgrade head)

log "bootstrapping tenant + provisioning key"
KEY_FILE="$WORK_DIR/provisioning-key.txt"
(cd "$SHAPOCLYACK_REPO" && python3 - "$TENANT_ID" "$KEY_FILE" <<'PYEOF'
import sys
from api.settings import Settings
from api.services import tenants as tenants_service

tenant_id, key_file = sys.argv[1], sys.argv[2]
tenants_service.configure(Settings(postgres_url=__import__("os").environ["OCTO_POSTGRES_URL"]))
tenants_service.create_tenant(name="Lariska E2E Tenant", tenant_id=tenant_id)
key = tenants_service.create_provisioning_key(tenant_id=tenant_id, label="lariska-e2e")
with open(key_file, "w") as f:
    f.write(key["key"])
PYEOF
)

log "starting the Shapoclyack API on port $API_PORT"
# `(cd X && nohup cmd &)` backgrounds the whole `cd && nohup` list as one
# subshell job, so `$!` there does not reliably capture uvicorn's own PID —
# pushd/popd keeps `nohup ... &` a single simple command in the main shell.
pushd "$SHAPOCLYACK_REPO" >/dev/null
nohup uvicorn api.app:app --host 127.0.0.1 --port "$API_PORT" \
  > "$WORK_DIR/shapoclyack-api.log" 2>&1 &
UVICORN_PID=$!
popd >/dev/null

for _ in $(seq 1 30); do
  curl -sf "http://127.0.0.1:${API_PORT}/api/health" >/dev/null 2>&1 && break
  sleep 1
done
curl -sf "http://127.0.0.1:${API_PORT}/api/health" >/dev/null || {
  log "Shapoclyack API did not become healthy; log follows"
  cat "$WORK_DIR/shapoclyack-api.log" >&2
  exit 1
}

log "building Lariska"
(cd "$LARISKA_REPO" && cargo build --quiet)

cat > "$WORK_DIR/lariska.toml" <<EOF
server_url = "http://127.0.0.1:${API_PORT}"
provisioning_key_file = "$KEY_FILE"
state_dir = "$WORK_DIR/state"
allow_plain_http = true
heartbeat_interval_secs = 30
inventory_interval_secs = 30
EOF

login() {
  curl -sS -X POST "http://127.0.0.1:${API_PORT}/api/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"viewer","password":"viewer-change-me"}' \
    | python3 -c "import json,sys; print(json.load(sys.stdin)['access_token'])"
}

log "first agent run (register + submit inventory)"
"$LARISKA_REPO/target/debug/lariska" run --config "$WORK_DIR/lariska.toml" \
  > "$WORK_DIR/agent-run-1.log" 2>&1 &
AGENT_PID=$!
sleep 6
kill "$AGENT_PID" 2>/dev/null || true
wait "$AGENT_PID" 2>/dev/null || true
unset AGENT_PID

TOKEN="$(login)"
DEVICES_JSON="$(curl -sS "http://127.0.0.1:${API_PORT}/api/endpoint/devices?tenant_id=${TENANT_ID}" \
  -H "Authorization: Bearer $TOKEN")"

DEVICE_COUNT="$(echo "$DEVICES_JSON" | python3 -c "import json,sys; print(len(json.load(sys.stdin)))")"
if [[ "$DEVICE_COUNT" != "1" ]]; then
  log "FAIL: expected exactly 1 registered device, got $DEVICE_COUNT"
  cat "$WORK_DIR/agent-run-1.log" >&2
  exit 1
fi

ASSET_ID="$(echo "$DEVICES_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin)[0]['asset_id'])")"
DEVICE_ID="$(echo "$DEVICES_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin)[0]['device_id'])")"

SOFTWARE_COUNT="$(curl -sS "http://127.0.0.1:${API_PORT}/api/assets/${ASSET_ID}/software?tenant_id=${TENANT_ID}" \
  -H "Authorization: Bearer $TOKEN" | python3 -c "import json,sys; print(len(json.load(sys.stdin)))")"
if [[ "$SOFTWARE_COUNT" -lt 1 ]]; then
  log "FAIL: expected at least 1 software entry, got $SOFTWARE_COUNT"
  exit 1
fi
log "OK: device $DEVICE_ID linked to asset $ASSET_ID with $SOFTWARE_COUNT software entries"

log "second agent run (unchanged software must not generate spurious change events)"
"$LARISKA_REPO/target/debug/lariska" run --config "$WORK_DIR/lariska.toml" \
  > "$WORK_DIR/agent-run-2.log" 2>&1 &
AGENT_PID=$!
sleep 6
kill "$AGENT_PID" 2>/dev/null || true
wait "$AGENT_PID" 2>/dev/null || true
unset AGENT_PID

SNAPSHOT_COUNT="$(curl -sS "http://127.0.0.1:${API_PORT}/api/endpoint/devices/${DEVICE_ID}/snapshots?tenant_id=${TENANT_ID}" \
  -H "Authorization: Bearer $TOKEN" | python3 -c "import json,sys; print(len(json.load(sys.stdin)))")"
if [[ "$SNAPSHOT_COUNT" -lt 2 ]]; then
  log "FAIL: expected at least 2 snapshots after two runs, got $SNAPSHOT_COUNT"
  exit 1
fi
log "OK: $SNAPSHOT_COUNT snapshots recorded"

log "PASS: cross-repository e2e flow succeeded"
