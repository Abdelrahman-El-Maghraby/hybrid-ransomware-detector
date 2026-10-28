# Operating Aegis Sentinel (Docker deployment)

Install, configure, start, stop, upgrade, roll back, back up, restore and
uninstall. The design and the hardening are in `docs/DEPLOYMENT.md`; what to do
when something goes wrong is in `docs/RUNBOOKS.md`.

Requirements: a Linux host with a current Docker Engine and the Compose v2 plugin
(tested with Docker 29.9 and on GitHub's ubuntu-latest runners),
4 CPU cores and 8 GB of memory for the default limits (analysis 2 CPUs / 6 GB,
intel 1 CPU / 1 GB), `openssl` and `curl` for the checks below.

## 1. Install

From a release (offline-capable):

```bash
mkdir /opt/aegis && cd /opt/aegis
# copy in: docker-compose.yml, deploy/Caddyfile, and the release archive
sha256sum -c SHA256SUMS --ignore-missing          # verify first (docs/RELEASING.md)
docker load -i aegis-sentinel-server-4.7.0-linux-amd64.tar.gz
echo "AEGIS_VERSION=4.7.0" > .env
```

From source (builds the images on this host, needs internet):

```bash
git clone https://github.com/Abdelrahman-El-Maghraby/hybrid-ransomware-detector /opt/aegis
cd /opt/aegis && git checkout v4.7.0
```

Then, either way, secrets and the TLS certificate:

```bash
install -d -m 0700 deploy/secrets
python3 -c 'import secrets; print(secrets.token_urlsafe(40))' > deploy/secrets/api_token
python3 -c 'import secrets; print(secrets.token_urlsafe(40))' > deploy/secrets/intel_token
: > deploy/secrets/virustotal_api_key     # empty = off (the default)
: > deploy/secrets/openai_api_key
: > deploy/secrets/sandbox_token
chmod 0644 deploy/secrets/*               # read inside the containers; the folder is 0700

install -d deploy/tls
cp /path/to/server.crt deploy/tls/cert.pem && cp /path/to/server.key deploy/tls/key.pem
chmod 0644 deploy/tls/*.pem
```

Give the API token to the systems that will call the API (mail gateway, SOAR);
they send it as `Authorization: Bearer <token>`.

## 2. Configure

Settings go in `.env` next to `docker-compose.yml` (Compose reads it). The ones
you are likely to change:

| Setting | Default | Meaning |
|---|---|---|
| `AEGIS_HTTPS_PORT` | 8443 | the published HTTPS port |
| `AEGIS_ANALYSIS_MEMORY`, `AEGIS_ANALYSIS_CPUS` | 6g, 2 | limits of the analysis service |
| `AEGIS_TMP_SIZE` | 2g | extraction sandbox (tmpfs; counts against the memory limit) |
| `AEGIS_API_MAX_CONCURRENT_SCANS`, `AEGIS_API_SPARE_WORKERS` | 2, 2 | parallel scans; workers started ahead |
| `AEGIS_API_MAX_UPLOAD_MB`, `SCAN_TIMEOUT_SECONDS`, `WORKER_MEMORY_MB` | 50, 300, 2048 | per-upload limits |
| `VT_UPLOAD_UNKNOWN`, `LLM_PROVIDER`, `OLLAMA_HOST`, `SANDBOX_URL` | false, none, -, - | external services (intel only; `docs/DATA_POLICY.md`) |
| `LOG_FORMAT` | text | `json` for one JSON object per log line |

A bad value stops the service at start with one line per problem
(`docker compose logs analysis intel`). In the production profile a required
layer that is switched off, `LLM_PROVIDER=auto`, an external-service key on the
analysis side or `CANARY_RESPONSE` are refused.

## 3. Start, check, stop

```bash
docker compose up -d --wait                       # returns when every health check passes
curl --cacert deploy/tls/cert.pem https://aegis.example.internal:8443/health
curl --cacert deploy/tls/cert.pem -H "Authorization: Bearer $(cat deploy/secrets/api_token)" \
     https://aegis.example.internal:8443/ready    # 200 + every layer's state, or 503 + why
curl --cacert deploy/tls/cert.pem -H "Authorization: Bearer $(cat deploy/secrets/api_token)" \
     -F file=@invoice.pdf https://aegis.example.internal:8443/scan

docker compose stop                               # scans in progress may finish (120 s)
docker compose start
```

To prove the isolation on this host: `deploy/check-deployment.sh` (it starts a
separate throw-away deployment on port 18443 and removes it afterwards).

## 4. Upgrade

**From a 4.7.x release to a newer one** (configuration, secrets, rule packs and the
cache are in volumes and files and are kept):

```bash
deploy/backup.sh /var/backups/aegis-$(date +%F)   # always first
docker load -i aegis-sentinel-server-<new>-linux-amd64.tar.gz     # or: git pull + build
sed -i 's/^AEGIS_VERSION=.*/AEGIS_VERSION=<new>/' .env
docker compose up -d --wait
```

**From 4.6.0.** 4.6.0 had no Docker deployment; it ran as the desktop app, the CLI or
`aegis-api` under systemd.

* *Desktop / CLI:* install the 4.7.0 build over it. The per-user folder
  (`~/RansomwareScanner`: reports, quarantine vault, keystore, rule packs) is kept.
  On first start, API keys in `.env` move to the OS keyring - after each one reads
  back identical, otherwise `.env` is left as it was. Export the quarantine key
  before upgrading (section 6).
* *systemd API → Docker:* install as in section 1, carry the settings from
  `/etc/aegis/aegis.env` into `.env` (external-service keys go into
  `deploy/secrets/`, not `.env`), and copy installed rule packs into the content
  volume:
  `docker compose run --rm -v /var/lib/aegis/RansomwareScanner/data/rulepacks:/import:ro content --update-rules /import/<pack>`
  (or simply install the current pack). Keep the old service stopped but installed
  until the new one has passed `/ready` and a test scan. The result schema is
  backward compatible (4.6.0's 1.1 → 1.3, fields only added), so API clients need no change.

## 5. Roll back

To the previous image (4.7.x → earlier 4.7.x): set `AEGIS_VERSION` back and
`docker compose up -d --wait`; the volumes are compatible within 4.7. If a
backup was taken before the upgrade, `deploy/restore.sh <backup>` puts the
volumes back exactly. Back to a 4.6.0 systemd install: stop the Docker
deployment (`docker compose down`) and start the old service again.

A bad *rule pack* is rolled back with a signed rollback pack, not by downgrading
(`docs/RULE_PACKS.md`).

## 6. Back up and restore

```bash
deploy/backup.sh /var/backups/aegis-2026-11-02     # volumes + .env + secrets + TLS
deploy/restore.sh /var/backups/aegis-2026-11-02    # replaces the volumes, starts it
```

The backup holds the API and intel tokens and any service keys: store it
encrypted and offline. Restore keeps an existing `.env` and secrets folder and
fills in only what is missing. Tested end to end: data written to the content
volume survived backup, `docker compose down -v` and restore, with its owner,
and `/ready` answered 200 afterwards.

**Quarantine key (desktop app / CLI).** The server deployment does not quarantine
files. On a desktop, back up the vault key with a passphrase and keep it apart
from the vault:

```bash
hrd-scanner --export-key /media/usb/aegis-key.backup     # asks for a passphrase twice
                                                          # (or HRD_KEY_PASSPHRASE)
hrd-scanner --import-key /media/usb/aegis-key.backup     # on the new machine
```

Items quarantined on one machine restore on another with the imported key; a
wrong passphrase or a modified backup is refused, and a different existing key is
never replaced silently (`tests/test_key_backup.py`).

## 7. Uninstall

```bash
deploy/backup.sh /var/backups/aegis-final          # if anything should be kept
docker compose down -v --remove-orphans            # containers, networks, volumes
docker image rm aegis-sentinel:<version> aegis-sentinel-proxy:<version>
rm -rf /opt/aegis                                  # compose file, .env, secrets, TLS
```
