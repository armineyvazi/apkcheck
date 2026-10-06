#!/usr/bin/env bash
# Ensure apkcheck Lab UI is up and reachable on the LAN (tool laptop).
#
#   ./scripts/ensure-lab-lan.sh                 # via DOCKER_CONTEXT=mdc-lab
#   ./scripts/ensure-lab-lan.sh armin@13.0.0.216
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
HOST="${1:-armin@13.0.0.216}"
IP="${HOST#*@}"
REMOTE_DIR="${REMOTE_DIR:-/home/armin/Dropbox/coding/sec/apkcheck}"

echo "== target $HOST =="
ssh -o BatchMode=yes -o ConnectTimeout=10 "$HOST" 'bash -lc "uname -n; docker compose version"'

echo "== sync compose =="
ssh "$HOST" "bash -lc \"mkdir -p '$REMOTE_DIR'\""
rsync -az --delete \
  --exclude '.git' \
  --exclude 'web/node_modules' \
  --exclude 'bin' \
  --exclude '.DS_Store' \
  "$ROOT/docker-compose.yml" "$ROOT/Dockerfile" "$HOST:$REMOTE_DIR/" 2>/dev/null || true
rsync -az "$ROOT/docker-compose.yml" "$HOST:$REMOTE_DIR/docker-compose.yml"

echo "== compose up lab + open firewall :8787 =="
ssh "$HOST" "bash -lc \"
set -e
cd '$REMOTE_DIR'
# Prefer image already on host
docker compose up -d lab
sleep 2
# Arch / ufw / firewalld best-effort
if command -v ufw >/dev/null 2>&1; then
  sudo ufw allow 8787/tcp || true
elif command -v firewall-cmd >/dev/null 2>&1; then
  sudo firewall-cmd --add-port=8787/tcp --permanent || true
  sudo firewall-cmd --reload || true
elif command -v nft >/dev/null 2>&1; then
  # Ensure Docker-published ports are not blocked by a host DROP policy on INPUT
  sudo nft list ruleset 2>/dev/null | head -5 || true
fi
# Also allow common tool ports if ufw active
if command -v ufw >/dev/null 2>&1 && sudo ufw status 2>/dev/null | grep -qi active; then
  for p in 7420 7480 8080 8081 8088 8089 8090 8787; do sudo ufw allow \${p}/tcp || true; done
fi
docker compose ps
curl -sf http://127.0.0.1:8787/api/health && echo local_ok || (docker logs --tail 40 apkcheck-lab-1; exit 1)
\""

echo "== LAN probe =="
ok=0
for _ in $(seq 1 20); do
  if curl -sf --max-time 2 "http://${IP}:8787/api/health" >/dev/null \
    || curl -sf --max-time 2 "http://${IP}:8787/" >/dev/null; then
    ok=1
    break
  fi
  sleep 1
done
if [[ "$ok" != "1" ]]; then
  echo "LAN :8787 unreachable from this Mac — laptop firewall or host down" >&2
  exit 1
fi
echo "OK  http://${IP}:8787"
