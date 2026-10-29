# Operating Aegis Sentinel

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
docker load -i aegis-sentinel-server-4.8.0-linux-amd64.tar.gz
echo "AEGIS_VERSION=4.8.0" > .env
```

From source (builds the images on this host, needs internet):

```bash
git clone https://github.com/Abdelrahman-El-Maghraby/hybrid-ransomware-detector /opt/aegis
cd /opt/aegis && git checkout v4.8.0
```

Then, either way, secrets and the TLS certificate:

```bash
install -d -m 0700 deploy/secrets
python3 -c 'import secrets; print(secrets.token_urlsafe(40))' > deploy/secrets/api_token
python3 -c 'import secrets; print(secrets.token_urlsafe(40))' > deploy/secrets/intel_token
: > deploy/secrets/virustotal_api_key     # empty = off (the default)
: > deploy/secrets/openai_api_key
: > deploy/secrets/sandbox_token
: > deploy/secrets/smtp_password         # empty when e-mail is not configured
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

### E-mail in Docker

Set `SMTP_HOST`, `SMTP_PORT` (465), `SMTP_SECURITY` (`tls`, or required
`starttls` on port 587), `SMTP_USER`, `ALERT_EMAIL_FROM` and comma-separated
`ALERT_EMAIL_TO` in `.env`. Put the password in `deploy/secrets/smtp_password`.
Compose passes connection settings and the password only to intel; analysis
queues fixed metadata through the intel socket and retains no network access.
`ALERT_EMAIL_MIN_VERDICT` defaults to `High`; intel limits delivery to
`ALERT_EMAIL_PER_HOUR=20` and `ALERT_EMAIL_PER_DAY=100`. TLS certificate
verification is mandatory. Leave the host and recipients unset to disable mail.

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

**4.7.x → 4.8.0:** before starting the new Compose file, create
`deploy/secrets/smtp_password` (empty when mail is off) and make it readable
inside intel, as in section 1. Schema 1.4 adds `provenance.isolation`;
consumers should accept the additive field. `ISOLATE_SCANS=0` is refused in
production. Worker-start failure now returns `/scan` 503, `/ready` 503 and
CLI exit code 3; clients must retry after the service recovers, rather than
interpret an unscanned file as clean. Rule-pack version strings must be numeric
components separated by dots. Back up before upgrading; a real-installation
upgrade remains tracked under U1.

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

* *Desktop / CLI:* install the 4.8.0 build over it. The per-user folder
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
  backward compatible (4.6.0's 1.1 → 1.4, fields only added), so API clients need no change.

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

## 8. Desktop monitoring, alerts and cloud

These features run in the desktop GUI or CLI background service; Docker and
the REST API have no folder watcher or cloud uploader.

**Monitoring:** select roots on the **Monitoring** page and start monitoring,
or set `WATCH_DIRS` (semicolon-separated paths) for `hrd-scanner --background`.
New, modified and renamed files are queued, deduplicated and scanned after
`WATCH_SETTLE_SECONDS=2`. `WATCH_MAX_QUEUE=1000` bounds pending files.
Worker-start failure pauses scanning and retries after `WATCH_RETRY_MINUTES=5`.
Own output folders, canaries and links are excluded. Results feed the dashboard,
reports and configured outputs. `AUTO_QUARANTINE` is opt-in; a changed file is
refused by quarantine. This is inspection after an event, not guaranteed prevention.

**Alerts:** the **Alerts & cloud** page saves SMTP/webhook settings and offers
**Send test e-mail**. Desktop mail goes directly to SMTP over verified TLS.
Passwords are saved to the OS keyring. Delivery status shows pending and expired
alerts. Failed channels retry from `OUTBOX_DIR`; the default lifetime is
`OUTBOX_MAX_AGE_HOURS=24`. A receiver should deduplicate by alert id: delivery
cannot guarantee exactly once if the receiver accepts a message but its reply
is lost.

**Quarantine keys:** use the key export/import controls on **Protection**, or
the CLI commands in section 6. Keep the encrypted backup apart from the vault;
verify recovery before removing the old installation.

**Cloud:** install the optional dependency with `pip install ".[cloud]"` when
running from source. In **Alerts & cloud**, set an HTTPS endpoint, region,
bucket, prefix, access key id and secret key, then save and use **Test upload**.
Uploads are off by default (`CLOUD_UPLOAD=false`). Leave `CLOUD_UPLOAD_FULL=false`
for an allowlisted, pseudonymised report and structured log events; raw rotated
log files are not uploaded. Read [DATA_POLICY.md](DATA_POLICY.md) before enabling
full detail. `CLOUD_CA_BUNDLE` can trust a private CA; verification stays enabled.

The local `CLOUD_SPOOL_DIR` defaults to the app's `cloud_spool` folder. Confirmed
uploads are removed; failures retry with capped exponential backoff. Cleanup
runs at service start and daily: `CLOUD_SPOOL_DAYS=30`, `CLOUD_SPOOL_MAX_MB=1024`
(oldest first). Expiry is logged and counted in delivery status. Turning uploads
off keeps pending items until cleanup expires them; it deletes nothing remotely.

### Bucket policy and remote retention

Create the bucket and configure retention with a separate administrator account.
The app never lists, reads, deletes or configures remote objects. Replace
`example-bucket`, `aegis` and `INSTALLATION_ID` below; the installation id is in
the app data folder's `installation_id` file. Give the upload identity only this
permission, without broader grants elsewhere:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": "s3:PutObject",
    "Resource": "arn:aws:s3:::example-bucket/aegis/INSTALLATION_ID/*"
  }]
}
```

Example bucket lifecycle configuration (operator applies it, not the app):

```json
{
  "Rules": [{
    "ID": "aegis-90-days",
    "Status": "Enabled",
    "Filter": {"Prefix": "aegis/INSTALLATION_ID/"},
    "Expiration": {"Days": 90},
    "NoncurrentVersionExpiration": {"NoncurrentDays": 90}
  }]
}
```

Check your endpoint's lifecycle semantics, including noncurrent versions and
delete markers. The client cannot check or enforce remote retention. Use an
administrator to delete remote data. The 90-day remote rule is independent of
the 30-day local spool. Versioning or object lock/WORM (lock period no greater
than 90 days) are recommended operator controls; account for lock expiry when
planning deletion.

Keys contain the prefix, installation id, reports/logs, date, UTC time, a random
128-bit id and a SHA-256 prefix. `CLOUD_CONDITIONAL_WRITES=true` sends
`If-None-Match: *`; use an endpoint that supports it. If explicitly disabled for
an incompatible endpoint, accidental collision remains unlikely but overwrite
protection is lost. The client sends SHA-256 and rejects a mismatching returned
checksum; an endpoint that omits the checksum supplies no independent read-back
verification. Write-only permissions do not prevent forged uploads or deliberate
overwrite. Versioning preserves history; object lock protects retained versions.
Reports and logs are only as trustworthy as their source host, and are not
tamper-evident.
