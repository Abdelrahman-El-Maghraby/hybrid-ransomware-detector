#!/usr/bin/env bash
# Restore a backup made by deploy/backup.sh and start the deployment.
#   deploy/restore.sh BACKUP_DIR         (run next to docker-compose.yml)
# Existing volumes of the project are REPLACED. Config files are restored only when
# they are missing here (an existing .env / secrets folder is kept).
set -euo pipefail
cd "$(dirname "$0")/.."
src="$(cd "${1:?usage: deploy/restore.sh BACKUP_DIR}" && pwd)"
project="${COMPOSE_PROJECT_NAME:-aegis}"
image="aegis-sentinel:${AEGIS_VERSION:-4.7.0}"

if [ -f "$src/config.tar.gz" ]; then
  unpacked="$(mktemp -d)"
  tar -xzf "$src/config.tar.gz" -C "$unpacked"
  # back to where this deployment keeps them; -n never overwrites what is here
  [ -f "$unpacked/.env" ] && [ ! -e .env ] && cp -p "$unpacked/.env" .env
  for part in secrets:"${AEGIS_SECRETS_DIR:-deploy/secrets}" tls:"${AEGIS_TLS_DIR:-deploy/tls}"; do
    name="${part%%:*}"; target="${part#*:}"
    [ -d "$unpacked/$name" ] || continue
    # copy only what is missing (cp -n exits non-zero on macOS when it skips a file)
    (cd "$unpacked/$name" && find . -type f) | while read -r f; do
      if [ ! -e "$target/$f" ]; then
        mkdir -p "$target/$(dirname "$f")"
        cp -p "$unpacked/$name/$f" "$target/$f"
      fi
    done
  done
  rm -rf "$unpacked"
  echo "config restored where missing"
fi
docker compose down --remove-orphans >/dev/null 2>&1 || true
docker compose up --no-start                       # creates the project's volumes
for vol in content analysis-state intel-state; do
  [ -f "$src/volumes/$vol.tar.gz" ] || continue
  name="$(docker volume ls -q --filter "label=com.docker.compose.project=$project" \
                              --filter "label=com.docker.compose.volume=$vol")"
  docker run --rm --network none --user 0 --entrypoint sh -v "$name:/v" -v "$src/volumes:/b:ro" \
    "$image" -c "find /v -mindepth 1 -delete && tar -xzf /b/$vol.tar.gz --numeric-owner -C /v"
  echo "volume $vol restored"
done
docker compose up -d --wait
echo "restored and running"
