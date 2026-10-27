# Deploying Aegis Sentinel

This guide covers running the scanner as a service: the supported Docker
deployment (section 0), a plain install with systemd (sections 1-3), logs and
metrics. Everything here is optional; the desktop app and the CLI need none of it.

## 0. Docker: the supported deployment

One deployment per customer, on a Linux host with Docker Engine and Compose v2.
Docker Desktop (macOS, Windows) runs the same files and is fine for evaluation;
for production use a Linux host, where the isolation below is enforced by the
host kernel you control.

```
 clients --TLS--> proxy (Caddy) --unix socket--> analysis (aegis-api) --unix socket--> intel (aegis-intel) --HTTPS--> VirusTotal / LLM / CAPE
                  port 8443                      network_mode: none                     the only egress
```

| Service | Does | Network | Holds |
|---|---|---|---|
| `proxy` | TLS with your certificate; the only published port | `edge` | the certificate |
| `analysis` | opens and scans the files (isolated workers) | **none** (loopback only) | API token, intel token |
| `intel` | fixed operations to VirusTotal, the LLM, the sandbox (`api/intel.py`) | `egress` | the external-service secrets, the cache of their answers |
| `content` (tool) | installs signed rule packs into the read-only content volume | none | - |

**Why no network for analysis.** The analysis service runs the parsers on hostile
input, and the worker pool limits crashes but is not a security boundary: a parser
exploit runs with the service's rights. With `network_mode: none` that code finds no
interface but loopback - no route to the internet, the LAN, the cloud metadata
address, the proxy or Docker's DNS. It can reach intel only through intel's Unix
socket. An internal Docker network shared with intel (the other option) would
leave Docker's resolver and every container on that network reachable, and one
compose edit could attach a route; with no interface there is nothing to
misconfigure.

**What intel accepts.** Fixed operations only - hash look-up, upload (only when
`VT_UPLOAD_UNKNOWN=true`), LLM analysis of at most 8,000 characters, sandbox submit
and poll of tasks it submitted - never a URL. Each service gets its own HTTP session
that refuses every origin outside intel's configuration, redirects included, so a
compromised analysis service cannot use intel as a proxy. Every request needs
`AEGIS_INTEL_TOKEN`; each operation is rate-limited (`AEGIS_INTEL_RATE_PER_MINUTE`,
`AEGIS_INTEL_BURST`) and bodies are capped (`AEGIS_INTEL_MAX_UPLOAD_MB`).

### Start it

```bash
# 1. secrets: one file each, read by the containers (uid 10001 / 10002)
install -d -m 0700 deploy/secrets
python3 -c 'import secrets; print(secrets.token_urlsafe(40))' > deploy/secrets/api_token
python3 -c 'import secrets; print(secrets.token_urlsafe(40))' > deploy/secrets/intel_token
: > deploy/secrets/virustotal_api_key      # empty = off (decision D4: off by default)
: > deploy/secrets/openai_api_key
: > deploy/secrets/sandbox_token
chmod 0644 deploy/secrets/*                # the 0700 folder keeps other host users out

# 2. TLS: your certificate and key (PEM) for the name clients use
install -d deploy/tls && cp server.crt deploy/tls/cert.pem && cp server.key deploy/tls/key.pem
chmod 0644 deploy/tls/*.pem

# 3. build and start; --wait returns when every health check passes
docker compose up -d --build --wait
curl --cacert deploy/tls/cert.pem -H "Authorization: Bearer $(cat deploy/secrets/api_token)" \
     https://aegis.example.internal:8443/ready
```

Settings go in a `.env` file next to `docker-compose.yml` (Compose reads it):
`AEGIS_HTTPS_PORT` (8443), `AEGIS_TLS_DIR`, `AEGIS_SECRETS_DIR`, resource sizes
(`AEGIS_ANALYSIS_MEMORY` 6g, `AEGIS_ANALYSIS_CPUS` 2, `AEGIS_TMP_SIZE` 2g,
`AEGIS_INTEL_MEMORY`, `AEGIS_INTEL_CPUS`), scan limits (`SCAN_TIMEOUT_SECONDS`,
`WORKER_MEMORY_MB`, `AEGIS_API_MAX_CONCURRENT_SCANS`, `AEGIS_API_MAX_UPLOAD_MB`) and
the external services, which are configured on **intel only**: `VT_UPLOAD_UNKNOWN`,
`LLM_PROVIDER`, `OLLAMA_HOST`, `SANDBOX_URL`. Putting an external-service key on the
analysis side is a start-up error in the production profile.

**Check it.** `deploy/check-deployment.sh` builds the images, starts a throw-away
deployment, runs `deploy/isolation_check.py` inside both containers (no interface
up but loopback, no route, outbound TCP/UDP/DNS refused, intel reachable only with
the token and with no generic operation, content read-only, containment code absent,
not root, no capabilities, no-new-privileges, seccomp on, read-only root, `/tmp`
noexec), scans a file through TLS and removes everything. CI runs it on every pull
request (`.github/workflows/docker.yml`).

### Hardening in docker-compose.yml

| Control | Setting | Why |
|---|---|---|
| Non-root | `user: 10001` (analysis), `10002` (intel), `10003` (proxy) | separate users; files of one are not the other's |
| Read-only root | `read_only: true` | a compromised process cannot change the program or plant files |
| Extraction sandbox | `/tmp` tmpfs, `size=2g,noexec,nosuid,nodev` | unpacked members never hit disk, cannot be executed, and cannot exceed the size; each worker's folder is removed when the worker is killed |
| Capabilities | `cap_drop: [ALL]` | no raw sockets, no chown, no ptrace; Caddy's file capability is removed in the image so it starts without any |
| Privilege escalation | `no-new-privileges:true` | setuid binaries cannot raise privileges |
| System calls | Docker's default seccomp profile (never `unconfined`) | blocks mount, kernel module, keyring and similar calls |
| Resources | `mem_limit`, `cpus`, `pids_limit` per service | a hostile file cannot starve the host; tmpfs usage counts against the memory limit |
| Detection content | the `content` volume is mounted `:ro` in analysis | a compromised parser cannot edit rules, the allowlist, the hash or fuzzy databases |
| Result cache | in intel's volume only; analysis keeps none | a compromised parser cannot plant a clean VirusTotal / LLM / sandbox answer for another file |
| Secrets | Docker secrets via `NAME_FILE`, never environment values | `docker inspect` and child processes do not see them |
| Sockets | `/run/aegis/intel` (group 10010: analysis), `/run/aegis/api` (group 10020: proxy), mode 0750 | only the intended client can connect |
| Containment | not in the image (`.dockerignore`), refused by the production profile | the server cannot suspend, kill or lock anything (decision D3) |
| TLS | Caddy with your certificate, HSTS, admin API off | the API itself speaks plain HTTP on a socket only |
| Client address | Caddy replaces `X-Forwarded-For`; the API uses its last entry | rate limits and the token lockout apply to the real client |
| Images | base images pinned by digest; Python packages from `requirements.lock` | rebuilds are reproducible |

### Rule-pack updates

The content volume is written only by the `content` tool service, which has no
network either:

```bash
docker compose run --rm -v "$PWD/packs:/import:ro" content --update-rules /import/aegis-rules-2026.11.zip
```

The pack's Ed25519 signature, manifest hashes and version are checked before
anything is installed (`core/rulepack.py`); the running analysis service notices
the change on disk and reloads before its next scan, and every result records the
rule-pack version and hash in `provenance`.

### Operations

* Logs: `docker compose logs analysis` (JSON lines with `LOG_FORMAT=json`); the log
  file is also in the `analysis-state` volume.
* Back up the `analysis-state` volume (reports, logs), `content` and `intel-state`
  (the cache of external answers); all can be rebuilt, the secrets folder cannot.
* Offline install from a release: `docker load -i aegis-sentinel-server-<version>-linux-amd64.tar.gz`,
  then `AEGIS_VERSION=<version> docker compose up -d --no-build --wait` (verify the
  file first: `docs/RELEASING.md`).
* Upgrade: `docker compose build --pull && docker compose up -d --wait`, or load the
  new release archive and run the same `up` with the new `AEGIS_VERSION`.
* Reset completely: `docker compose down -v` (deletes every volume).

## 1. Install (without Docker)

```bash
python -m venv /opt/aegis/venv
/opt/aegis/venv/bin/pip install -r requirements.lock
/opt/aegis/venv/bin/pip install -e ".[api]" --no-deps
```

Create a dedicated, unprivileged user (`aegis`) and keep the configuration in
`/etc/aegis/aegis.env` (owner `root`, mode `0640`, group `aegis`). The settings
are the ones in `.env.example`. The service checks them at start-up and stops
with one line per problem, so a typo does not quietly switch a protection off.

Secrets on a server come from the environment. Either set `NAME=value` in that
protected file, or point `NAME_FILE` at a file only the service can read (for
example a Docker secret under `/run/secrets/`): `OPENAI_API_KEY`,
`VIRUSTOTAL_API_KEY`, `SANDBOX_TOKEN`, `WEBHOOK_SECRET`, `IMAP_PASSWORD`,
`AEGIS_API_TOKEN`, `AEGIS_INTEL_TOKEN`. A server
has no OS keyring, so nothing is migrated there and the start-up log line
`Secrets -> NAME:source` shows where each one came from (never its value).

## 2. The REST API behind a TLS reverse proxy

`aegis-api` speaks plain HTTP on `127.0.0.1:8765` and must not be exposed
directly. Put a reverse proxy in front of it to terminate TLS.

```ini
# /etc/aegis/aegis.env (excerpt)
AEGIS_API_TOKEN=<python -c "import secrets;print(secrets.token_urlsafe(32))">
AEGIS_API_HOST=127.0.0.1
AEGIS_API_PORT=8765
AEGIS_API_TRUST_PROXY=1          # the client address comes from X-Forwarded-For
AEGIS_API_MAX_UPLOAD_MB=50
AEGIS_API_RATE_PER_MINUTE=60
AEGIS_API_BURST=10
AEGIS_API_MAX_CONCURRENT_SCANS=2
LOG_FORMAT=json
```

Set `AEGIS_API_TRUST_PROXY=1` only when the proxy is the only way in. With it
on, a client that reaches the API directly could send a fake
`X-Forwarded-For` header and slip past the per-client rate limit.

### nginx

```nginx
server {
    listen 443 ssl http2;
    server_name aegis.example.internal;

    ssl_certificate     /etc/ssl/aegis/fullchain.pem;
    ssl_certificate_key /etc/ssl/aegis/privkey.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;
    add_header Strict-Transport-Security "max-age=31536000" always;

    client_max_body_size 51m;          # a little over AEGIS_API_MAX_UPLOAD_MB
    proxy_request_buffering off;       # let the API count and cut oversize bodies
    proxy_read_timeout 360s;           # above SCAN_TIMEOUT_SECONDS

    location / {
        proxy_pass http://127.0.0.1:8765;
        proxy_set_header X-Forwarded-For $remote_addr;   # replace, never append
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header Host $host;
    }
}
```

`X-Forwarded-For $remote_addr` overwrites whatever the client sent. The API uses
the last X-Forwarded-For entry (the one your proxy added), so a proxy that appends
instead is safe too: addresses a client puts in the header are ignored. Exactly
one trusted proxy is supported. Without `AEGIS_API_TRUST_PROXY=1`
behind a proxy, every client shares the proxy's address: one client's wrong
tokens would then lock everyone out.

### Caddy

```caddyfile
aegis.example.internal {
    request_body {
        max_size 51MB
    }
    reverse_proxy 127.0.0.1:8765 {
        header_up X-Forwarded-For {remote_host}
        transport http {
            read_timeout 360s
        }
    }
}
```

Caddy obtains and renews the certificate itself. For an internal name, use
`tls internal` or your own CA.

### Liveness and readiness

| Endpoint | Answers | Token |
|---|---|---|
| `GET /health` | 200 while the process runs | not needed |
| `GET /ready` | 200 when a scan would be correct and complete, else 503 | without it only `{"ready": true/false}`; with it, every check and layer state |

`/ready` checks that the YARA rules compiled, the indicator registry is valid, the
report, data and temporary folders are writable, and isolated workers start (proved
once by a warm-up scan at start-up). With `AEGIS_PROFILE=production` it also needs
every layer the production profile requires (docs/RELEASE_SCOPE.md) to be up: route
traffic to an instance only when `/ready` says so. `hrd-scanner --capabilities`
prints the same layer states on the command line.

### Limits the API enforces

| Limit | Setting | Answer |
|---|---|---|
| Upload size: the declared `Content-Length` is checked before reading, then the body is counted as it streams | `AEGIS_API_MAX_UPLOAD_MB` | 413 |
| Requests per IP address, before authentication | `AEGIS_API_IP_RATE_PER_MINUTE` (120), `AEGIS_API_IP_BURST` (30) | 429 + `Retry-After` |
| Failed bearer tokens per IP address: N failures within the window lock the address out, checked before the token is compared | `AEGIS_API_AUTH_FAILURES` (5), `AEGIS_API_AUTH_WINDOW_SECONDS` (300), `AEGIS_API_AUTH_LOCKOUT_SECONDS` (900) | 401, then 429 + `Retry-After` |
| Requests per authenticated client (IP and valid token) | `AEGIS_API_RATE_PER_MINUTE`, `AEGIS_API_BURST` | 429 + `Retry-After` |
| Scans running at once | `AEGIS_API_MAX_CONCURRENT_SCANS` | 503 + `Retry-After` |
| Time and memory per scan, in an isolated worker | `SCAN_TIMEOUT_SECONDS`, `WORKER_MEMORY_MB` | result with `scan_failed` |

## 3. systemd

```ini
# /etc/systemd/system/aegis-api.service
[Unit]
Description=Aegis Sentinel REST API
After=network-online.target

[Service]
User=aegis
EnvironmentFile=/etc/aegis/aegis.env
ExecStart=/opt/aegis/venv/bin/aegis-api
Restart=on-failure
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/home/aegis/RansomwareScanner /tmp
PrivateTmp=yes
CapabilityBoundingSet=
MemoryMax=4G

[Install]
WantedBy=multi-user.target
```

The background scanner (`RansomwareScanner.py --background`) runs the same
way. If you use the `stop_writers` or `network_off` canary responses, they
need the rights to signal other processes or to change network settings. Give
the service only those rights (for example `CAP_KILL`, `CAP_NET_ADMIN`), not
root.

## 4. Logs and metrics

* `LOG_FORMAT=json` writes one JSON object per line to
  `~/RansomwareScanner/ransomware_scanner.log` and to stdout, so journald,
  Filebeat, Fluent Bit or Vector can ingest it without parsing rules.
* Events and their fields:
  * `scan_started`
  * `scan_completed` (`path`, `sha256`, `verdict`, `risk_score`, `duration_ms`)
  * `layer_error` (`layer`, `error`)
  * `scan_batch` (`files`, `files_per_sec`, `duration_ms`)
* `GET /metrics` (bearer token) returns the counters as JSON:
  * files and bytes scanned, files per second, average scan time
  * verdicts by band
  * errors per layer
  * time-outs and worker crashes
  * rejected requests

  `GET /metrics?format=prometheus` returns the same counters in the Prometheus
  text format:

```yaml
# prometheus.yml
scrape_configs:
  - job_name: aegis
    scheme: https
    metrics_path: /metrics
    params: {format: [prometheus]}
    authorization: {credentials_file: /etc/prometheus/aegis.token}
    static_configs: [{targets: ["aegis.example.internal"]}]
```

## 5. Before you call it production

* The detection rate on real malware has to be measured on your own samples,
  in an isolated VM, with `tools/evaluate.py`. The test suite only proves the
  logic.
* Read `docs/THREAT_MODEL.md`: what the scanner does not cover is listed there.
