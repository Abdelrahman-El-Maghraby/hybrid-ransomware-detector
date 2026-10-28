#!/usr/bin/env bash
# Restore a backup made by deploy/backup.sh and start the deployment.
#   deploy/restore.sh BACKUP_DIR         (run next to docker-compose.yml)
# Existing volumes of the project are REPLACED. Config files are restored only when
# they are missing here (an existing .env / secrets folder is kept).
set -euo pipefail
cd "$(dirname "$0")/.."
src="$(cd "${1:?usage: deploy/restore.sh BACKUP_DIR}" && pwd)"
project="${COMPOSE_PROJECT_NAME:-aegis}"
image="aegis-sentinel:${AEGIS_VERSION:-4.7.0-rc1}"

if [ -f "$src/config.tar.gz" ]; then
  unpacked="$(mktemp -d)"
  tar -xzf "$src/config.tar.gz" -C "$unpacked"
  cp -Rn "$unpacked"/. .                           # -n: never overwrite what is here
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
