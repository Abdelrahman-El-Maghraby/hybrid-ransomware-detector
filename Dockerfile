# syntax=docker/dockerfile:1
# Aegis Sentinel server image. One image, two services with different users:
#   analysis  python -m api.server   opens the files; no network (docker-compose.yml)
#   intel     python -m api.intel    the only service that reaches VirusTotal / LLM / sandbox
# plus the `proxy` target: Caddy for TLS in front of the analysis socket.
# Hardening notes: docs/DEPLOYMENT.md.
ARG PYTHON=python:3.12-slim-trixie@sha256:12316debbfb86890f6b2d825820612741ba527ad5a44e3902759141d572bfe8f
ARG CADDY=caddy:2.10.2-alpine@sha256:4c6e91c6ed0e2fa03efd5b44747b625fec79bc9cd06ac5235a779726618e530d

# ---------------------------------------------------------------- dependencies
FROM ${PYTHON} AS build
RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
# The server's layers at the versions pinned in requirements.lock (no GUI, no ML
# training: without scikit-learn no pickled model is ever loaded).
RUN python -m venv /opt/aegis \
 && /opt/aegis/bin/pip install --no-cache-dir -c requirements.lock \
        ".[fuzzy,macro,yara,archives,office,qr,api]" \
 && /opt/aegis/bin/pip uninstall -y hybrid-ransomware-detector

# ---------------------------------------------------------------- TLS proxy
FROM ${CADDY} AS proxy
# The binary carries cap_net_bind_service, which makes exec fail once every
# capability is dropped. It listens on 8443 and needs none.
RUN setcap -r /usr/bin/caddy
COPY deploy/Caddyfile /etc/caddy/Caddyfile

# ---------------------------------------------------------------- the services
FROM ${PYTHON} AS server
# libzbar0: the QR layer; unar: RAR archives
RUN apt-get update \
 && apt-get install -y --no-install-recommends libzbar0 unar \
 && rm -rf /var/lib/apt/lists/*
# analysis 10001 and intel 10002 have their own groups. 10010 may connect to the
# intel socket (analysis only), 10020 to the API socket (the proxy only).
RUN groupadd -g 10001 analysis && groupadd -g 10002 intel \
 && groupadd -g 10010 intel-clients && groupadd -g 10020 api-clients \
 && useradd -r -M -u 10001 -g analysis -G intel-clients -d /var/lib/aegis -s /usr/sbin/nologin analysis \
 && useradd -r -M -u 10002 -g intel -d /var/lib/aegis-intel -s /usr/sbin/nologin intel \
 && mkdir -p /var/lib/aegis/RansomwareScanner/data /var/lib/aegis/cache /var/lib/aegis-intel \
             /run/aegis/intel /run/aegis/api \
 && chown -R analysis:analysis /var/lib/aegis \
 && chown intel:intel /var/lib/aegis-intel && chmod 0700 /var/lib/aegis-intel \
 && chown intel:intel-clients /run/aegis/intel && chmod 0750 /run/aegis/intel \
 && chown analysis:api-clients /run/aegis/api && chmod 0750 /run/aegis/api
COPY --from=build /opt/aegis /opt/aegis
COPY . /app
RUN test ! -e /app/core/containment.py && test ! -e /app/core/response.py \
 && /opt/aegis/bin/python -m compileall -q /app
ENV PATH=/opt/aegis/bin:$PATH \
    PYTHONPATH=/app \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHON_KEYRING_BACKEND=keyring.backends.null.Keyring \
    AEGIS_PROFILE=production
WORKDIR /app
USER 10001:10001
CMD ["python", "-m", "api.server"]
