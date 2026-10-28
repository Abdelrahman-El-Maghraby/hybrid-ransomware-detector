#!/usr/bin/env bash
# Back up an Aegis Sentinel Docker deployment into one folder:
#   volumes/<name>.tar.gz   content (rule packs, allowlist, hash and fuzzy DBs),
#                           analysis-state (reports, logs), intel-state (answer cache)
#   config.tar.gz           .env, the secrets folder and the TLS folder
# The archive holds the API, intel and service keys: keep it encrypted and offline.
#
#   deploy/backup.sh BACKUP_DIR          (run next to docker-compose.yml; the stack may run)
set -euo pipefail
cd "$(dirname "$0")/.."
dest="${1:?usage: deploy/backup.sh BACKUP_DIR}"
project="${COMPOSE_PROJECT_NAME:-aegis}"
image="aegis-sentinel:${AEGIS_VERSION:-4.7.0-rc1}"
mkdir -p "$dest/volumes"
dest="$(cd "$dest" && pwd)"

for vol in content analysis-state intel-state; do
  name="$(docker volume ls -q --filter "label=com.docker.compose.project=$project" \
                              --filter "label=com.docker.compose.volume=$vol")"
  if [ -z "$name" ]; then echo "skip $vol (no such volume in project $project)"; continue; fi
  docker run --rm --network none --user 0 --entrypoint tar -v "$name:/v:ro" -v "$dest/volumes:/b" \
    "$image" -czf "/b/$vol.tar.gz" --numeric-owner -C /v .
  echo "volume $vol -> volumes/$vol.tar.gz"
done

files=()
for f in .env "${AEGIS_SECRETS_DIR:-deploy/secrets}" "${AEGIS_TLS_DIR:-deploy/tls}"; do
  [ -e "$f" ] && files+=("$f")
done
if [ "${#files[@]}" -gt 0 ]; then
  tar -czf "$dest/config.tar.gz" "${files[@]}"
  chmod 0600 "$dest/config.tar.gz"
  echo "config ${files[*]} -> config.tar.gz (contains secrets)"
fi
date -u +"%Y-%m-%dT%H:%M:%SZ project=$project image=$image" > "$dest/BACKUP_INFO"
echo "backup written to $dest"
