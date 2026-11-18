# Kubernetes deployment (optional)

Aegis Sentinel can run on Kubernetes from the manifests in `deploy/kubernetes/`.
This is an **optional** alternative to the Docker Compose deployment
([DEPLOYMENT](DEPLOYMENT.md), section 0), which remains supported and is still the
reference deployment. Kubernetes does not change what the scanner detects, and
nothing about detection quality depends on it.

**Status.** The manifests render and pass the static checks in this repository.
They have **not yet been run on a cluster**: admission, the network plugin, the
storage driver, the probes and shutdown are unverified until an operator runs
`deploy/kubernetes/verify-cluster.sh` on a test cluster (see "Verify"). Do not
describe this deployment as production ready before that.

Contents: [Architecture](#architecture) ·
[Cluster requirements](#cluster-requirements) · [Images](#images) ·
[Secrets and TLS](#secrets-and-tls) · [Configure and render](#configure-and-render) ·
[Deploy](#deploy) · [Access](#access) · [Verify](#verify) ·
[Rule packs](#rule-packs) · [Storage](#storage) ·
[Backup and restore](#backup-and-restore) · [Upgrade and rollback](#upgrade-and-rollback) ·
[Rotation](#rotation) · [Remove](#remove) · [Resources and shutdown](#resources-and-shutdown) ·
[Scaling](#scaling) · [Differences from Docker Compose](#differences-from-docker-compose) ·
[Intel](#intel-external-services) · [Troubleshooting](#troubleshooting) ·
[Checks](#checks)

## Architecture

```
 clients --TLS--> Service aegis-sentinel:8443
                    |
   Pod aegis-analysis (namespace aegis-sentinel, Pod Security "restricted")
   +-----------------------------------------------------------------------+
   | init: prepare-state    creates the state folders as uid 10001          |
   | init: isolation-gate   fails while any outside destination answers    |
   | proxy (Caddy, 10003)  --unix socket (emptyDir)-->  analysis (10001)   |
   |   TLS Secret aegis-tls                              API token Secret  |
   |                                                    content claim: ro |
   +-----------------------------------------------------------------------+
   NetworkPolicy: ingress TCP 8443 only; no egress at all
   Job aegis-content-update (on demand): the only writer of the content claim
```

Read from the code (`docker-compose.yml`, `api/server.py`, `api/intel.py`,
`core/intel_client.py`, `engine/validation.py`):

- The proxy reaches the API over the Unix socket `api.sock`; the analysis service
  listens on nothing else. Analysis reaches intel only over `intel.sock`
  (`core/intel_client.py` speaks HTTP over a Unix socket and nothing else).
- The analysis service runs correctly without intel: with `AEGIS_INTEL_SOCKET`
  unset and `LLM_PROVIDER=none`, the production profile's configuration check
  passes and the external layers are simply off. E-mail alerts need intel
  (`_Alerts` in `api/server.py` is off without `AEGIS_INTEL_SOCKET` or SMTP
  settings).

**Decision.** One Pod holds the analysis service and the TLS proxy, joined by
the Unix socket in a Pod-local emptyDir, as in Docker. The Pod has no egress:
a default-deny NetworkPolicy, with one rule that admits TCP 8443. The intel
service is **not deployed** on Kubernetes yet, so VirusTotal, the LLM, CAPE and
e-mail alerts are unavailable there (see [Intel](#intel-external-services)).
Detection content lives on its own claim, mounted read-only in analysis and
written only by a Job while analysis is stopped.

Alternatives considered and rejected:

| Alternative | Why not |
|---|---|
| analysis and intel in one Pod (Unix socket in an emptyDir) | Containers in a Pod share one network namespace and NetworkPolicy applies to Pods, not containers: giving intel egress gives the hostile-file parser the same egress |
| intel in its own Pod, socket on a shared volume | A Unix socket works only on one node's file system; a shared claim does not carry it between nodes, and a `hostPath` socket is refused by the restricted Pod Security Standard and ties both Pods to one node |
| intel over TCP within the cluster | Changes the application's transport and gives the analysis Pod a network path; a trust-boundary change that needs the owner's decision first (proposal below) |
| proxy in its own Pod, analysis on TCP (`AEGIS_API_HOST`/`AEGIS_API_PORT`, already supported) | Analysis would accept connections from the network, and `AEGIS_API_TRUST_PROXY=1` would then rely on a NetworkPolicy alone to stop clients from forging `X-Forwarded-For` |
| TLS at an Ingress controller | A second proxy: the API trusts exactly one (the last `X-Forwarded-For` entry), and the Ingress controller would hold the certificate outside this namespace |
| Helm chart | The configuration has few variables; one Kustomize base and an overlay keep one format with no templating |

## Cluster requirements

| Requirement | Why | If absent |
|---|---|---|
| Kubernetes 1.29 or later | `ReadWriteOncePod` is stable from 1.29 | Claims are refused or stay Pending |
| A network plugin that **enforces NetworkPolicy** (Calico, Cilium, Antrea, ...) | Without it the policies "have no effect" (Kubernetes documentation) and the analysis Pod has full network access | The isolation-gate init container fails and the Pod never starts; the readiness probe takes a running Pod out of service if enforcement stops |
| A CSI storage class that supports `ReadWriteOncePod` | One Pod at a time per claim: no concurrent writer of content or state | Claims stay Pending (or set `ReadWriteOnce` deliberately: [Storage](#storage)) |
| Pod Security Admission (built in since 1.25) | The namespace enforces `restricted` | Without admission the labels do nothing; `check_manifests.py` still checks every field |
| Kubelet `podPidsLimit` (for example 512) | Kubernetes has no per-Pod or per-container process limit in the Pod spec; Docker's `pids_limit` has no Pod-spec equivalent | A fork bomb in a parser is bounded only by the node's settings |
| Secret encryption at rest, and RBAC that limits who can read Secrets or create Pods in the namespace | Secrets are stored unencrypted in etcd by default; anyone who can create a Pod in the namespace can read its Secrets | The API token and TLS key are readable by more people than intended |
| A container runtime with a default seccomp profile (containerd, CRI-O) | `seccompProfile: RuntimeDefault` | Admission refuses the Pod under `restricted` |
| About 1.2 CPU and 6.5 GiB memory free on one node, plus 3 GiB of claims | [Resources](#resources-and-shutdown) | The Pod stays Pending |

Optional, stronger isolation for the analysis Pod: a sandboxed runtime through a
`RuntimeClass` (gVisor, Kata Containers) and user namespaces (`hostUsers: false`)
where the cluster supports them. Add them in the overlay; a `runtimeClassName` the
cluster does not know makes the Pod fail to start, which is the safe failure.
They are not in the base because they are not available everywhere, and a
cluster that silently ignores a field is worse than one that refuses it.

## Images

The manifests use the two images the Dockerfile already builds; nothing new:

```bash
VERSION=4.8.0                      # the version you are deploying
REGISTRY=registry.example.internal # your registry; the repository names none
docker build --target server -t "$REGISTRY/aegis-sentinel:$VERSION" .
docker build --target proxy  -t "$REGISTRY/aegis-sentinel-proxy:$VERSION" .
docker push "$REGISTRY/aegis-sentinel:$VERSION"
docker push "$REGISTRY/aegis-sentinel-proxy:$VERSION"
# the digests to put in the overlay:
docker buildx imagetools inspect "$REGISTRY/aegis-sentinel:$VERSION" --format '{{.Manifest.Digest}}'
```

A release archive (`docs/RELEASING.md`) can be loaded with `docker load` and
retagged the same way. On a single-node test cluster without a registry, load the
images into the node instead (`kind load docker-image ...`,
`minikube image load ...`); `imagePullPolicy: IfNotPresent` then uses them.

The base's image tags are `SET-VERSION-IN-OVERLAY`: an overlay that forgets to set
them renders images the kubelet cannot pull, and `check_manifests.py` refuses them.
Use a digest (`digest: sha256:...` in the overlay's `images:`) rather than a tag,
and never `latest`.

The isolation gate is not in the image (`.dockerignore` keeps `deploy/` out); it
reaches the Pod as the ConfigMap `aegis-isolation-gate`, generated from
`deploy/kubernetes/base/isolation_gate.py`.

## Secrets and TLS

Nothing in the repository creates a Secret, and `check_manifests.py` fails if a
rendered manifest contains one. Create two before the first deployment; the Pod
does not start without them:

```bash
NS=aegis-sentinel CTX=your-test-context
install -d -m 0700 ~/aegis-k8s-secrets
python3 -c 'import secrets; print(secrets.token_urlsafe(40))' > ~/aegis-k8s-secrets/api_token
chmod 0600 ~/aegis-k8s-secrets/api_token
# the namespace comes from the manifests (with its Pod Security labels): apply it first
kubectl kustomize ~/aegis-overlay | python3 -c 'import sys,yaml; print(yaml.safe_dump(next(d for d in yaml.safe_load_all(sys.stdin) if d and d["kind"] == "Namespace")))' \
  | kubectl --context "$CTX" apply -f -
kubectl --context "$CTX" -n "$NS" create secret generic aegis-api-token \
    --from-file=api_token="$HOME/aegis-k8s-secrets/api_token"
kubectl --context "$CTX" -n "$NS" create secret tls aegis-tls \
    --cert=server.crt --key=server.key
```

The token must be at least 16 characters (`api/server.py`). The certificate must
name the address clients use. Keep the token file and the key outside the
repository.

| Secret | Mounted in | As |
|---|---|---|
| `aegis-api-token` (key `api_token`) | `analysis` only | `/run/secrets/aegis/api_token`, mode 0440, read through `AEGIS_API_TOKEN_FILE` |
| `aegis-tls` (`tls.crt`, `tls.key`) | `proxy` only | `/etc/caddy/tls/cert.pem` and `key.pem` (the paths in `deploy/Caddyfile`), mode 0440 |

No external-service credential exists in this deployment. Secrets are files,
never environment variables, so child processes and `kubectl describe` do not
show them. The service account mounts no token (no workload uses the Kubernetes
API) and no Role is bound.

Cluster-level protection is the operator's: enable encryption at rest for
Secrets, restrict `get`/`list`/`watch` on Secrets and `create` on Pods in this
namespace to the people who run it, and back the secret files up outside the
cluster. A tool such as cert-manager may manage `aegis-tls`, as long as it writes
a Secret of that name with `tls.crt` and `tls.key`.

## Configure and render

```bash
cp -r deploy/kubernetes/overlays/example ~/aegis-overlay   # outside the repository
# edit ~/aegis-overlay/kustomization.yaml: every REPLACE value
sed -i.bak 's|\.\./\.\./base|'"$PWD"'/deploy/kubernetes/base|' ~/aegis-overlay/kustomization.yaml
kubectl kustomize ~/aegis-overlay > aegis.yaml
python3 deploy/kubernetes/check_manifests.py aegis.yaml   # needs PyYAML
```

The overlay sets: the image references; `RULEPACK_PUBLIC_KEYS` (public keys of
the rule-pack signers); the storage class; how clients reach the Service; and the
client networks allowed to reach port 8443. Settings of the analysis service go in
the `aegis-analysis-config` ConfigMap (`configMapGenerator`, `behavior: merge`):
`AEGIS_API_MAX_UPLOAD_MB`, `AEGIS_API_MAX_CONCURRENT_SCANS`,
`AEGIS_API_SPARE_WORKERS`, `SCAN_TIMEOUT_SECONDS`, `WORKER_MEMORY_MB`,
`LOG_FORMAT`, and the API limits in [DEPLOYMENT](DEPLOYMENT.md) section 2. A changed
ConfigMap gets a new name, so the Pod restarts with it.

`AEGIS_PROFILE=production`, `LLM_PROVIDER=none`, the socket paths and
`AEGIS_API_TRUST_PROXY=1` are set in the Deployment, not in the ConfigMap: they
define the isolation. When you raise `AEGIS_API_MAX_UPLOAD_MB` past 50, the proxy
still stops bodies at 52 MB (`deploy/Caddyfile`, baked into the proxy image):
change both and rebuild the proxy image. When you raise `SCAN_TIMEOUT_SECONDS`,
raise `terminationGracePeriodSeconds` with it (the checker assumes 300 s).

## Deploy

```bash
# first time only: the namespace and the two Secrets (above)
kubectl --context "$CTX" apply -f aegis.yaml
kubectl --context "$CTX" -n aegis-sentinel rollout status deployment/aegis-analysis --timeout=15m
```

Always pass `--context`; nothing here changes the current context. Start-up takes
a while: the init containers create the state folders and run the isolation gate
(about 8 s), then the API
compiles the YARA rules and warms up its workers before `/health` answers.

## Access

The base Service is `ClusterIP`. Choose how clients reach it in the overlay; the
choice decides whether the API's per-client limits see real clients
(`api/limits.py`: per-address rate limits and the failed-token lockout):

| Path | Client address the API sees | Use |
|---|---|---|
| `type: LoadBalancer` with `externalTrafficPolicy: Local` (the example overlay) | the real client | recommended; `Local` also lets the NetworkPolicy's `ipBlock` match client networks. Traffic spreads only to nodes that run the Pod |
| `type: NodePort` with `externalTrafficPolicy: Local` | the real client | clusters without a load balancer |
| TLS passthrough at an Ingress or Gateway (SNI routing, no TLS termination) | the controller's address: every client shares one rate limit and one lockout | only with an access path that has its own per-client limits |
| `kubectl port-forward service/aegis-sentinel 8443:8443` | 127.0.0.1 for everyone | evaluation and `verify-cluster.sh` only |

Do not terminate TLS before the proxy: the analysis service trusts exactly one
proxy, the Caddy container in its own Pod. Narrow the `aegis-allow-https` policy
to your client networks (the example overlay shows how). Traffic from the node the
Pod runs on is always allowed by NetworkPolicy, whatever the rule says.

## Verify

`deploy/kubernetes/verify-cluster.sh` is for a **dedicated test cluster**, run by
the operator with the owner's approval; nobody has run it yet.

```bash
deploy/kubernetes/verify-cluster.sh --context "$CTX" --namespace aegis-sentinel \
    --token-file ~/aegis-k8s-secrets/api_token --ca-file ca.pem --server-name aegis.test \
    --probe 10.0.0.5:443 --restart-test
```

It needs `kubectl`, `curl` and `python3` with PyYAML on the operator's machine. It
checks:

- the deployed objects with `check_manifests.py`, and that no Role, RoleBinding or
  autoscaler exists in the namespace;
- that the rollout completes and the Pod is Ready;
- inside the analysis container (`isolation_gate.py verify`): not root, no
  capabilities, no-new-privileges, seccomp filtering, read-only root, no
  service-account token, no external-service setting, the content read-only and
  not writable, and that the internet (IPv4 and IPv6), public DNS, the cluster DNS,
  the Kubernetes API, the metadata address and every `--probe` target do not
  answer; the `/tmp` mount options and `pids.max` are printed for the record;
- that the analysis container holds only the API token, and the proxy container's
  capabilities, no-new-privileges, seccomp and user;
- through TLS (a port-forward): `/health` 200, `/version` 401 without and with a
  wrong token, `/ready` 200 with the token, and an inert text file scanned as Clean;
- with `--restart-test`: deletes the Pod once, prints how long shutdown took, and
  checks that a marker in the state claim survived, `/tmp` is new, and the
  rule-pack version is unchanged.

The token goes to curl in a header file and is never printed. The script creates
nothing in the cluster; `--restart-test` deletes one Pod (the Deployment replaces
it) and removes the marker it wrote. Intel checks are reported as not applicable:
intel is not deployed. Add `--probe` targets for anything else the analysis Pod
must not reach (another Service, a node address, a database); traffic to the
Pod's own node cannot be blocked by NetworkPolicy at all.

## Rule packs

The content claim is written only by `jobs/content-update.yaml`, which runs
`RansomwareScanner.py --update-rules` with no network, as Docker's `content`
service does. The pack's signature, manifest hashes and version are checked before
anything is installed (`core/rulepack.py`, [RULE_PACKS](RULE_PACKS.md)); older or
unsigned packs are refused.

```bash
deploy/kubernetes/content-update.sh --context "$CTX" --namespace aegis-sentinel \
    --pack aegis-rules-2026.11.02.tar.gz           # PACK.tar.gz.sig next to it
```

The script scales the analysis Deployment to zero and waits for the Pod to end
(both claims are `ReadWriteOncePod`, so the Job could not mount the content
otherwise, and no scan reads half-installed content), creates the ConfigMap
`aegis-rulepack-import` from the pack and its signature, runs the Job with the
Deployment's own image and `RULEPACK_PUBLIC_KEYS`, prints the log, deletes the Job
and the ConfigMap, and scales the Deployment back, also when the install failed.
Scans are refused while it runs (usually under a minute).

A ConfigMap holds less than 1 MiB, so the script refuses larger packs. For those,
fill a separate claim with the pack and mount it at `/import` instead of the
ConfigMap. Rollback is a signed pack with a newer version (`rollback_pack`); there
is no way to install an older one, by design.

## Storage

| Data | Where | Kept across | Notes |
|---|---|---|---|
| Detection content (rule packs, `active.json`, allowlist, hash and fuzzy databases) | claim `aegis-content` (1 GiB), read-only in analysis | restarts, upgrades | Written only by the content Job |
| Service state: the log file (`RansomwareScanner/ransomware_scanner.log`, also on stdout) | claim `aegis-analysis-state` (2 GiB) | restarts, upgrades | The API writes no report files, no quarantine and, without intel, no alert outbox |
| Uploads, extracted members, worker folders | emptyDir `/tmp`, memory-backed, 2 GiB | nothing: cleared at every container start | Counted in the analysis memory limit |
| The API socket | emptyDir, memory-backed | nothing | Shared by proxy and analysis only |
| Caddy's `/data` and `/config` | emptyDirs | nothing | Caddy obtains no certificates here (`auto_https off`) |

Both claims are `ReadWriteOncePod`: one Pod in the cluster may use each. That
makes two analysis Pods, or analysis and the content Job together, impossible
rather than merely discouraged. It needs a CSI driver. `ReadWriteOnce` would let
several Pods on the same node mount the claim at once; if your storage offers only
that, set it in the overlay, render with `check_manifests.py --allow-rwo`, and rely
on `content-update.sh` (which always scales analysis to zero first) and
`replicas: 1` to keep a single writer. Claims are scheduled with the Pod: on
zonal storage, the Pod can only run in the claim's zone.

Ownership: a new claim is owned by root. `fsGroup: 10001` lets the kubelet give
its root folder to the image's `analysis` group (10001) for drivers that support
it (`fsGroupChangePolicy: OnRootMismatch`); the image's own ownership of
`/var/lib/aegis` does not carry over, as it does for a Docker named volume. The
content claim is mounted inside the state claim (at `RansomwareScanner/data`), and
the container runtime would create those mount-point folders as root with mode
0755, leaving uid 10001 unable to write its log file. So the first init container,
`prepare-state`, runs as uid 10001 with only the state claim mounted, creates
`RansomwareScanner/data`, and checks that it can write there; it stops with
"is not writable by uid 10001" when the driver ignores `fsGroup` (then fix the
volume's ownership with the storage provider's tools). The content Job does the
same for its home emptyDir. Nothing runs as root to chown.

## Backup and restore

What needs a backup: the **secret files** (API token, TLS key and certificate:
keep them outside the cluster, encrypted), the **overlay** and the rendered
manifests (in a private repository), and the **content** claim. The content can
always be rebuilt by installing the newest signed pack again; the state claim
holds only the log file, which is also on stdout.

With CSI snapshots (`VolumeSnapshotClass` available):

```bash
kubectl --context "$CTX" -n aegis-sentinel scale deployment/aegis-analysis --replicas=0
kubectl --context "$CTX" -n aegis-sentinel apply -f - <<'EOF'
apiVersion: snapshot.storage.k8s.io/v1
kind: VolumeSnapshot
metadata: {name: aegis-content-2026-11-18}
spec:
  volumeSnapshotClassName: REPLACE-snapshot-class
  source: {persistentVolumeClaimName: aegis-content}
EOF
kubectl --context "$CTX" -n aegis-sentinel scale deployment/aegis-analysis --replicas=1
```

Restore: with analysis scaled to zero, delete the claim and create one with the
same name and `dataSource: {kind: VolumeSnapshot, apiGroup:
snapshot.storage.k8s.io, name: ...}`, then scale back. Without snapshots, restore
by installing the newest signed pack into an empty claim (`content-update.sh`).
The Docker scripts `deploy/backup.sh` and `deploy/restore.sh` are for Compose
volumes and do not apply here.

## Upgrade and rollback

1. Build and push the new images; set their digests in the overlay.
2. Render, run `check_manifests.py`, and keep the rendered file with its version.
3. `kubectl --context "$CTX" apply -f aegis.yaml`.

The Deployment uses `Recreate`: the old Pod receives SIGTERM, stops accepting
uploads, finishes the ones in progress (up to the 330 s grace period), and only
then does the new Pod start. Expect an outage of the shutdown plus the start-up.
A scan cut by the grace period gives the client a connection error and must be
sent again; the API keeps no scan state between Pods. Whether in-progress scans
complete during an update has not been measured on a cluster
(`verify-cluster.sh --restart-test` prints the shutdown time).

Rollback: apply the previous rendered file. `kubectl rollout undo` also works as
long as the previous generated ConfigMap still exists (`kubectl apply` keeps old
ones unless you prune them). Neither rolls back detection content.

## Rotation

- **API token:** write a new token file, replace the Secret
  (`kubectl --context "$CTX" -n aegis-sentinel create secret generic aegis-api-token
  --from-file=api_token=NEW_FILE --dry-run=client -o yaml | kubectl --context "$CTX" apply -f -`),
  then `kubectl --context "$CTX" -n aegis-sentinel rollout restart deployment/aegis-analysis`: the API reads the token
  once at start-up. Give clients the new token.
- **TLS certificate:** replace `aegis-tls` the same way (or let cert-manager
  renew it), then restart the Deployment: Caddy runs with its admin API off and
  does not reload the files by itself. Renew well before expiry; the restart is an
  outage (see Upgrade).
- **Rule-pack signing keys:** change `RULEPACK_PUBLIC_KEYS` in the overlay and
  apply; procedure and key-compromise recovery in [RULE_PACKS](RULE_PACKS.md).

## Remove

```bash
kubectl --context "$CTX" delete -f aegis.yaml
```

This deletes the Deployment, Service, policies, ConfigMaps, claims and the
namespace. Whether the volumes behind the claims are deleted depends on the
storage class's `reclaimPolicy` (`Delete` erases the data; `Retain` keeps the
PersistentVolumes, which you then delete yourself). The Secrets you created are
deleted with the namespace. Snapshots and images in your registry stay.

## Resources and shutdown

| Container | Requests | Limits | Basis |
|---|---|---|---|
| `analysis` | 1 CPU, 6 GiB | 2 CPU, 6 GiB | the Docker deployment: main process + 2 concurrent scans x `WORKER_MEMORY_MB` 2,048 + 2 spares x about 200 MB + the 2 GiB `/tmp` |
| `proxy` | 50m, 64 MiB | 500m, 256 MiB | the Docker deployment |
| `prepare-state`, `isolation-gate` (init) | 50m, 64 MiB each | 250m, 128 MiB each | standard library only |
| content Job | 250m, 512 MiB | 1 CPU, 1 GiB | YARA compile of the pack |

Memory request equals the limit for analysis, so it is not the first Pod evicted
under node memory pressure. Do not lower `WORKER_MEMORY_MB` or the concurrency to
fit a smaller node: they set how much of a hostile file a worker may use before it
is stopped; give the Pod the memory instead.

Probes: the **startup** probe allows 10 minutes for the YARA compile and the
warm-up scan; **readiness** runs the isolation gate and then the API's `/ready`
(every 30 s); **liveness** asks only `/health` on the socket, so an unavailable
external service, a busy scanner or a failed isolation check never restarts the
container. The proxy's probes open TCP 8443.

Shutdown: `terminationGracePeriodSeconds: 330` (the 300 s scan limit plus the
reply). Both containers receive SIGTERM together; uvicorn stops accepting and
finishes requests in progress, and Caddy's default grace period waits for active
connections. Worker processes are stopped by the API on exit. Unverified on a
cluster.

## Scaling

One replica only. Horizontal scaling is not supported because the rate limits,
the failed-token lockout and the scan slots are in-process (`api/limits.py`), so
replicas would multiply every limit; the state and content claims are single-Pod
by design; and rule-pack installation assumes a stopped reader. Before adding
replicas or an autoscaler, these would need a shared store for limits and lockout,
a read-only content distribution that several Pods can mount, and a tested
content-update procedure for running replicas. `check_manifests.py` refuses
`replicas` other than 1 and any HorizontalPodAutoscaler. More throughput on one
Pod: raise `AEGIS_API_MAX_CONCURRENT_SCANS` and the memory limit together.

## Differences from Docker Compose

| Property | Docker Compose | Kubernetes (these manifests) |
|---|---|---|
| Analysis network | `network_mode: none`: no interface but loopback | A Pod interface always exists; egress is blocked only by NetworkPolicy, which needs an enforcing plugin. The init gate and readiness probe check the effect. Traffic to and from the Pod's own node is always allowed by NetworkPolicy, and the policy may apply only after the Pod starts (hence the gate) |
| DNS | none | The Pod has the cluster DNS server in `/etc/resolv.conf`; the policy blocks it and the gate checks it |
| Proxy and analysis | separate containers with separate networks | one Pod, one network namespace: the proxy shares analysis's interface. Neither has egress, and analysis listens on no port |
| Socket access | group-restricted directories (10010, 10020) | the socket's emptyDir is visible to the two containers of this Pod only |
| Process limit | `pids_limit` per container | none in the Pod spec; the kubelet's `podPidsLimit` per Pod |
| `/tmp` | tmpfs `noexec,nosuid,nodev`, new at every container start | memory-backed emptyDir, size-limited, **without** `noexec`, `nosuid` or `nodev` (Kubernetes has no generally available way to set them); cleared by the container's start command because it outlives a container restart. With every capability dropped and no-new-privileges, setuid files gain nothing; a file written there can still be executed |
| Seccomp | Docker's default profile | the runtime's default (`RuntimeDefault`) |
| No new privileges | `no-new-privileges:true` | `allowPrivilegeEscalation: false` |
| Worker clean-up | the API kills workers and their helpers on exit | the same code; at Pod deletion the container's processes are killed after the grace period |
| Secrets | files on the Docker host | API objects in etcd: encryption at rest and RBAC are the cluster's |
| Admission | none | the namespace enforces Pod Security `restricted` |
| External services and e-mail alerts | through intel | not available yet |

## Intel: external services

**Not available on Kubernetes in this version.** VirusTotal, the LLM, the CAPE
sandbox and e-mail alerts all go through the intel service, which reaches analysis
only over a Unix socket. No Kubernetes arrangement keeps that socket and keeps
analysis without a network path (see Architecture). The settings that switch them
on (`VIRUSTOTAL_API_KEY`, `LLM_PROVIDER`, `OLLAMA_HOST`, `OPENAI_API_KEY`,
`SANDBOX_URL`, `SANDBOX_TOKEN`, `SMTP_*`, `ALERT_EMAIL_*`) must not be added to the
analysis container: `check_manifests.py` and the isolation gate fail when they
are. The production profile never sends anything outside when they are absent.

**Proposal for an owner decision** (not implemented):

1. Intel in its own Deployment and namespace-local Service, listening on TCP with
   TLS, holding the external-service Secrets and its cache claim; egress allowed
   only to the operator's destinations (CIDR rules: NetworkPolicy cannot filter by
   domain name, so intel's own origin allowlist, `core/http.py`, stays the real
   filter).
2. An application change: `AEGIS_INTEL_URL` (an `https://` address with a fixed
   IP, so analysis needs no DNS) and a CA file beside the existing token, in
   `core/intel_client.py`, `api/intel.py` and `engine/validation.py`, with tests;
   the Unix-socket path stays the default for Docker.
3. The analysis Pod gets exactly one egress rule: TCP to the intel Pods' port.
   Intel accepts only that Pod. Because the proxy shares the analysis Pod's
   network, the proxy could also open connections to intel (it holds no intel
   token, so it gets 401); separating the proxy would need analysis to listen on
   TCP, which the Architecture table rejects.
4. The isolation gate learns the one allowed destination and keeps failing on
   everything else.

What this changes: analysis gains a network path to one internal service
(today: none in Docker, a socket only). The token and TLS keep it authenticated;
NetworkPolicy keeps it narrow. Approve, reject or amend before any of it is
built; until then Kubernetes runs without external services.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| Pod stuck in `Init:CrashLoopBackOff`; the `isolation-gate` log shows `FAIL blocked: ...` | NetworkPolicy is not enforced, not yet programmed, or something allows that destination. Check the plugin; a delay clears after a restart or two. Some managed clusters answer `169.254.169.254` from a node-local metadata server, which NetworkPolicy cannot block (node traffic): disable or block it at the cluster level |
| `prepare-state` fails with "is not writable by uid 10001" | The storage driver does not apply `fsGroup` (Storage) |
| `CreateContainerConfigError` or `ContainerCreating` for a long time | A Secret is missing (`aegis-api-token`, `aegis-tls`) or a claim is not bound |
| Claims `Pending` | No CSI class with `ReadWriteOncePod`, or no default class; set `storageClassName` |
| Admission error naming `restricted` | A patch removed a hardening field; render and run `check_manifests.py` |
| `ErrImagePull` with `SET-VERSION-IN-OVERLAY` or `REPLACE` | The overlay's `images:` are not filled in |
| Ready flips to false; `kubectl describe pod` shows the readiness probe output with `FAIL blocked:` | Isolation stopped holding (policy deleted or plugin changed); the Pod is out of service until it holds again |
| Ready false, gate lines pass | `/ready` is 503: `kubectl exec ... -c analysis -- python -m api.probe /run/aegis/api/api.sock /ready`, or `curl /ready` with the token for every check |
| Every client gets 429 after a few wrong tokens | The API sees one address for everyone (port-forward, TLS passthrough, `externalTrafficPolicy: Cluster`); see Access |
| 413 on uploads under `AEGIS_API_MAX_UPLOAD_MB` | The proxy's 52 MB cap in `deploy/Caddyfile` |
| Permission denied under `/var/lib/aegis` | The storage driver ignores `fsGroup` (Storage) |
| Content Job stays Pending | The analysis Pod still holds the claim: use `content-update.sh`, which scales it down |

Logs: `kubectl logs deployment/aegis-analysis -c analysis` (JSON lines,
`LOG_FORMAT=json`), `-c proxy`, `-c prepare-state`, `-c isolation-gate`.

## Checks

| Check | Where | Proves |
|---|---|---|
| `check_manifests.py` | operator, before every apply; `tests/test_kubernetes.py` | every invariant in this guide that the YAML can show: hardening fields, users, secrets per container, no external settings, read-only content, probes, grace period, one replica, `Recreate`, `ReadWriteOncePod`, default-deny and no egress, one HTTPS port, no Secret, Role or autoscaler, no placeholders |
| `tests/test_kubernetes.py` | `pytest` (renders with `kubectl kustomize` when kubectl is installed) | the base and the example overlay render; the checker rejects each of a list of weakened manifests (privileged, egress allowed, content writable, a second replica, a Secret in the output, ...); the gate's classification (connected, refused, silent, DNS answer, broken probe); the scripts refuse to run without an explicit context and namespace |
| `isolation_gate.py` | in the Pod: init, readiness, `verify` | the network isolation as the Pod experiences it |
| `verify-cluster.sh` | operator, test cluster | everything above, on a running deployment |

Not covered without a cluster: server-side admission, schema validation against
the cluster's API version, whether the network plugin really enforces the
policies, storage permissions, probe timing, shutdown behaviour and resource use.
