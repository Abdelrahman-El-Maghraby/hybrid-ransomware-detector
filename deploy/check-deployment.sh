#!/usr/bin/env bash
# Build the images, start the deployment with throw-away secrets and a
# self-signed certificate, prove the isolation from inside the containers, run
# one scan through TLS, and tear everything down (volumes included).
#
#   deploy/check-deployment.sh          # needs docker compose v2, openssl, curl
#   KEEP=1 deploy/check-deployment.sh   # leave it running afterwards
set -euo pipefail
cd "$(dirname "$0")/.."

export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-aegis-check}"
work="$(mktemp -d)"
export AEGIS_SECRETS_DIR="$work/secrets" AEGIS_TLS_DIR="$work/tls"
export AEGIS_HTTPS_PORT="${AEGIS_HTTPS_PORT:-18443}"
mkdir -p "$AEGIS_SECRETS_DIR" "$AEGIS_TLS_DIR"

cleanup() {
  status=$?
  if [ "$status" -ne 0 ]; then docker compose logs --no-color --tail 80 || true; fi
  if [ -z "${KEEP:-}" ]; then docker compose down -v --remove-orphans >/dev/null 2>&1 || true; fi
  rm -rf "$work"
  exit "$status"
}
trap cleanup EXIT

token() { python3 -c 'import secrets; print(secrets.token_urlsafe(40))'; }
token > "$AEGIS_SECRETS_DIR/api_token"
token > "$AEGIS_SECRETS_DIR/intel_token"
: > "$AEGIS_SECRETS_DIR/virustotal_api_key"      # external services stay off
: > "$AEGIS_SECRETS_DIR/openai_api_key"
: > "$AEGIS_SECRETS_DIR/sandbox_token"
chmod 0644 "$AEGIS_SECRETS_DIR"/*                  # read by uid 10001 / 10002 in the containers
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=localhost" \
  -keyout "$AEGIS_TLS_DIR/key.pem" -out "$AEGIS_TLS_DIR/cert.pem" 2>/dev/null
chmod 0644 "$AEGIS_TLS_DIR"/*.pem

docker compose build
docker compose up -d --wait

echo "== isolation (inside the containers)"
docker compose exec -T analysis python - analysis < deploy/isolation_check.py
docker compose exec -T intel python - intel < deploy/isolation_check.py

echo "== through the TLS proxy"
api="https://localhost:$AEGIS_HTTPS_PORT"
auth="Authorization: Bearer $(cat "$AEGIS_SECRETS_DIR/api_token")"
curl -fsS --cacert "$AEGIS_TLS_DIR/cert.pem" "$api/health"; echo
ready="$(curl -sS --cacert "$AEGIS_TLS_DIR/cert.pem" -H "$auth" -o /dev/stderr -w '%{http_code}' "$api/ready")"
echo; echo "GET /ready -> $ready"
test "$ready" = "200"
printf 'Quarterly figures attached.\n' > "$work/note.txt"
curl -fsS --cacert "$AEGIS_TLS_DIR/cert.pem" -H "$auth" -F "file=@$work/note.txt" "$api/scan" \
  | python3 -c 'import json,sys; r=json.load(sys.stdin); print("POST /scan ->", r["verdict"], r["scan_status"], r["provenance"]["external_services"]); assert r["verdict"] == "Clean"'
code="$(curl -sS --cacert "$AEGIS_TLS_DIR/cert.pem" -o /dev/null -w '%{http_code}' "$api/version")"
echo "GET /version without a token -> $code"; test "$code" = "401"
echo "== deployment check passed"
