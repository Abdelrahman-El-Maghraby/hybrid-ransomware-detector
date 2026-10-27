# Deploying Aegis Sentinel

This guide covers running the scanner as a service: the background scanner,
the REST API behind TLS, logs and metrics. Everything here is optional; the
desktop app and the CLI need none of it.

## 1. Install

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
`VIRUSTOTAL_API_KEY`, `SANDBOX_TOKEN`, `WEBHOOK_SECRET`, `IMAP_PASSWORD`. A server
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

`X-Forwarded-For $remote_addr` overwrites whatever the client sent, so the
first address the API sees is the real peer. Without `AEGIS_API_TRUST_PROXY=1`
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
