#!/usr/bin/env bash
set -euo pipefail

if [ "${EUID}" -ne 0 ]; then
    echo "[ERROR] Please run with sudo: sudo ./apply_log_retention_fix.sh" >&2
    exit 1
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLIENT_DIR="$REPO_ROOT/client"
RUNTIME_ROOT="$CLIENT_DIR/runtime/node-1"
SOCKET_SRC="$REPO_ROOT/server/service_templates/smart-streetlight-stack/packages/socket-server/socket_server.py"
SOCKET_DST="$RUNTIME_ROOT/streetlight-socket-server-b10e4bb6/package/socket-server/socket_server.py"
SOCKET_ENV="$RUNTIME_ROOT/streetlight-socket-server-b10e4bb6/package/socket-server/socket_server.env"
SUBSCRIBER_SRC="$REPO_ROOT/server/service_templates/smart-streetlight-stack/packages/subscriber/app.py"
SUBSCRIBER_DST="$RUNTIME_ROOT/streetlight-subscriber-b10e4bb6/package/subscriber/app.py"
SUBSCRIBER_ENV="$RUNTIME_ROOT/streetlight-subscriber-b10e4bb6/package/subscriber/subscriber.env"
MONGO_CONTAINER="honeypot-node-1-streetlight-mongodb-b10e4bb6-mongo"
SOCKET_CONTAINER="honeypot-node-1-streetlight-socket-server-b10e4bb6-socket-server"
SUBSCRIBER_CONTAINER="honeypot-node-1-streetlight-subscriber-b10e4bb6-subscriber"

for path in "$SOCKET_SRC" "$SOCKET_DST" "$SOCKET_ENV" "$SUBSCRIBER_SRC" "$SUBSCRIBER_DST" "$SUBSCRIBER_ENV"; do
    if [ ! -f "$path" ]; then
        echo "[ERROR] Missing required file: $path" >&2
        exit 1
    fi
done

needs_apply=false
if ! cmp -s "$SOCKET_SRC" "$SOCKET_DST" || ! cmp -s "$SUBSCRIBER_SRC" "$SUBSCRIBER_DST"; then
    needs_apply=true
fi
for env_file in "$SOCKET_ENV" "$SUBSCRIBER_ENV"; do
    if ! grep -q '^MONGO_LOG_RETENTION_DAYS=30$' "$env_file"; then
        needs_apply=true
    fi
done

restart_pending=false
restart_agent_if_needed() {
    if [ "$restart_pending" = true ]; then
        echo "[INFO] Recovering Agent after an interrupted update..." >&2
        "$CLIENT_DIR/start_agent.sh" -d || true
    fi
}
trap restart_agent_if_needed EXIT

if [ "$needs_apply" = true ]; then
    BACKUP_ROOT="$CLIENT_DIR/retention-backups/$(date -u +%Y%m%dT%H%M%SZ)"
    mkdir -p "$BACKUP_ROOT"
    cp -a "$SOCKET_DST" "$SOCKET_ENV" "$SUBSCRIBER_DST" "$SUBSCRIBER_ENV" "$BACKUP_ROOT/"

    "$CLIENT_DIR/start_agent.sh" stop
    restart_pending=true

    install -m 0644 "$SOCKET_SRC" "$SOCKET_DST"
    install -m 0644 "$SUBSCRIBER_SRC" "$SUBSCRIBER_DST"
    for env_file in "$SOCKET_ENV" "$SUBSCRIBER_ENV"; do
        if ! grep -q '^MONGO_LOG_RETENTION_DAYS=' "$env_file"; then
            printf '\nMONGO_LOG_RETENTION_DAYS=30\n' >> "$env_file"
        else
            sed -i 's/^MONGO_LOG_RETENTION_DAYS=.*/MONGO_LOG_RETENTION_DAYS=30/' "$env_file"
        fi
    done

    echo "[OK] Runtime files updated; backup: $BACKUP_ROOT"
    "$CLIENT_DIR/start_agent.sh" -d
    restart_pending=false
else
    echo "[OK] Runtime files already contain the retention fix; rebuild skipped"
fi

for attempt in $(seq 1 90); do
    state_mongo="$(docker inspect -f '{{.State.Status}}' "$MONGO_CONTAINER" 2>/dev/null || true)"
    state_socket="$(docker inspect -f '{{.State.Status}}' "$SOCKET_CONTAINER" 2>/dev/null || true)"
    state_subscriber="$(docker inspect -f '{{.State.Status}}' "$SUBSCRIBER_CONTAINER" 2>/dev/null || true)"
    if [ "$state_mongo" = "running" ] && [ "$state_socket" = "running" ] && [ "$state_subscriber" = "running" ]; then
        break
    fi
    sleep 2
done

state_mongo="$(docker inspect -f '{{.State.Status}}' "$MONGO_CONTAINER" 2>/dev/null || true)"
state_socket="$(docker inspect -f '{{.State.Status}}' "$SOCKET_CONTAINER" 2>/dev/null || true)"
state_subscriber="$(docker inspect -f '{{.State.Status}}' "$SUBSCRIBER_CONTAINER" 2>/dev/null || true)"
if [ "$state_mongo" != "running" ] || [ "$state_socket" != "running" ] || [ "$state_subscriber" != "running" ]; then
    echo "[ERROR] Containers not running: mongo=$state_mongo socket=$state_socket subscriber=$state_subscriber" >&2
    exit 1
fi

mongo_result="$(docker exec "$MONGO_CONTAINER" sh -lc 'mongosh --quiet --username "$MONGO_INITDB_ROOT_USERNAME" --password "$MONGO_INITDB_ROOT_PASSWORD" --authenticationDatabase admin streetlight --eval '\''const idx=db.command_logs.getIndexes().find(x=>x.name==="created_at_ttl"); const cutoff=new Date(Date.now()-30*86400*1000); print(JSON.stringify({ttl_seconds:idx?idx.expireAfterSeconds:null, expired_rows:db.command_logs.countDocuments({created_at:{$lt:cutoff}}), total_rows:db.command_logs.countDocuments({})}));'\''' 2>/dev/null)"
echo "[OK] MongoDB retention: $mongo_result"

if ! printf '%s' "$mongo_result" | grep -q '"ttl_seconds":2592000'; then
    echo "[ERROR] MongoDB TTL index is missing or has the wrong duration" >&2
    exit 1
fi

echo "[OK] Service states: mongo=$state_mongo socket=$state_socket subscriber=$state_subscriber"
curl -k -sS --max-time 8 -o /dev/null -w '[OK] HTTPS 443 status: %{http_code}\n' https://127.0.0.1:443/
df -h /
