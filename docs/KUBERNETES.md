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
[Isolation contract](#isolation-contract-and-its-limits) · [Intel](#intel-external-services) · [Troubleshooting](#troubleshooting) ·
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
| A network plugin that **enforces NetworkPolicy** (Calico, Cilium, Antrea, ...) | Without it the policies "have no effect" (Kubernetes documentation) and the analysis Pod has full network access | The isolation-gate init container fails, because the cluster DNS and the API server answer, and the Pod never starts; the readiness probe takes a running Pod out of service if enforcement stops. The probes are a sample, not a proof ([Isolation contract](#isolation-contract-and-its-limits)) |
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
still stops bodies at 51 MiB (`deploy/Caddyfile`, baked into the proxy image):
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

Two kinds of evidence, kept apart:

- **Static** (this repository, no cluster): `check_manifests.py`, the rendered
  base and overlay, and `tests/test_kubernetes.py`. They show what the YAML
  requests, not what a cluster does with it. None of them opens a network
  connection: `isolation_gate.py` probes only when `AEGIS_GATE_LIVE=1` and an
  explicit `AEGIS_GATE_TARGETS` list are set (the manifests set both for the init
  container and the analysis container); anywhere else its network modes refuse
  with exit 2 before opening a socket. `isolation_gate.py posture` checks a
  container's hardening without any network, and the test suite fails any test
  that reaches beyond this machine.
- **Runtime** (an approved, dedicated test cluster): `verify-cluster.sh`.
  **Nobody has run it yet**; every runtime property below is unverified until
  someone does.

### Runtime procedure (operator-run, disposable namespaces, inert files only)

1. Choose a test cluster and the context name explicitly. The script never reads
   or changes the current context; every call names `--context`.
2. Create two empty namespaces and mark them disposable. The script refuses
   `default` and `kube-*`, and runs no changing check without this label:

   ```bash
   kubectl --context "$CTX" create namespace aegis-verify
   kubectl --context "$CTX" create namespace aegis-verify-control
   kubectl --context "$CTX" label namespace aegis-verify aegis-verify-control \
       aegis-sentinel.io/verification=disposable \
       pod-security.kubernetes.io/enforce=restricted
   ```

3. Deploy into `aegis-verify` with an overlay that sets `namespace: aegis-verify`
   (Secrets as in [Secrets and TLS](#secrets-and-tls), with a test token and a
   test CA). This is the **fresh-volume** start: `prepare-state` creates the
   state folders on new claims.
4. Run the checks:

   ```bash
   deploy/kubernetes/verify-cluster.sh --context "$CTX" --namespace aegis-verify \
       --token-file ~/aegis-test/api_token --ca-file ~/aegis-test/ca.pem \
       --server-name aegis.test --control-namespace aegis-verify-control \
       --drift-test --restart-test
   ```

5. For content maintenance, install a **test-signed** pack with
   `content-update.sh` (it scales analysis to zero, runs the Job, scales back),
   then run step 4 again without `--drift-test`: the rule-pack version must be
   the new one, and a pack with a bad signature must leave the old content.
6. Delete both namespaces. The script removes only what it created; the claims
   and Secrets belong to the operator's deployment.

Before changing anything, the script checks that the server is 1.29 or later,
that the namespaces exist (and carry the label when a changing check was asked
for), and that the operator may do what the selected checks need
(`kubectl auth can-i`). It then checks:

| Area | Check | Kind |
|---|---|---|
| Objects | the live objects pass `check_manifests.py`; no Role, RoleBinding or autoscaler | read |
| Start | rollout completes, Pod Ready, `prepare-state` ran; the state folder belongs to uid 10001 (fresh volume); the socket's mode and owner are printed | read |
| Isolation | `isolation_gate.py verify` inside analysis: not root, no capabilities, no-new-privileges, seccomp, read-only root, no service-account token, no external setting, content read-only and not writable, and the internet, DNS, the API server, the metadata address and every `--probe` do not answer | read |
| Secrets | analysis sees its token and not the TLS key; the proxy sees its certificate (positive control) and not the token | read |
| API over TLS | `/health` 200; `/version` 401 without and with a wrong token; `/ready` 200; an inert text file scanned Clean; one byte over `AEGIS_API_MAX_UPLOAD_MB` gets the **API's** JSON 413 (so the proxy's cap is above it) | read |
| Controlled network (`--control-namespace`) | a listener and a client Pod in the control namespace: the client reaches the listener and resolves cluster DNS (**positive controls**), and only then does "analysis cannot reach the listener" count; if the positive control fails the result is *inconclusive*, not a pass | creates 2 Pods, 1 Service |
| After start-up (`--drift-test`) | a NetworkPolicy that allows DNS egress is added: readiness must take the Pod out of service (within 180 s), and it must return when the policy is removed | creates 1 NetworkPolicy |
| Restart (`--restart-test`) | the Pod is deleted once: shutdown time printed (grace 330 s), a marker in the state claim survives, `/tmp` is new, the rule-pack version is unchanged (**existing-volume** restart) | deletes 1 Pod |

Not covered by the script, and still to be checked by hand on that cluster:
shutdown while a scan is in progress (start a large inert upload, delete the
Pod, expect the reply before the grace period ends); resource use under two
concurrent scans; behaviour when the storage class ignores `fsGroup` (expect the
`prepare-state` error). Traffic to the Pod's own node cannot be blocked by
NetworkPolicy at all, so no probe of the node proves anything about it.

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
same for its home emptyDir. Nothing runs as root to chown, and nothing changes a
mode: on an existing or restored claim the folders and files are left exactly as
they are. A claim whose `RansomwareScanner` folder already belongs to root (one
started without this step) stops `prepare-state` with the same message; give that
folder to uid 10001 with the storage provider's tools, or start from a new claim
and reinstall the rule pack.

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

## Isolation contract and its limits

What these manifests promise for the analysis Pod, and where each promise ends.
"Holds" below means *requested by the manifests and checked statically*; none of
it has been observed on a cluster yet ([Verify](#verify)).

| Property | Mechanism | Limit |
|---|---|---|
| No egress from the Pod | default-deny NetworkPolicy, no egress rule | Enforced only by a network plugin that implements NetworkPolicy. A policy applies to the **Pod**, not to a container: the proxy and analysis share one network namespace and one set of rules. Traffic to and from the Pod's own node is always allowed |
| The policy is in effect before analysis starts | the `isolation-gate` init container must see every probe fail | The probes are a **finite sample**, not proof of isolation. A time-out or refusal counts as blocked, so in a cluster without internet access the internet probes pass whether or not the policy is enforced. The gate is meaningful because two destinations always exist in a working cluster: the cluster DNS server (from `/etc/resolv.conf`) and the API server (`KUBERNETES_SERVICE_HOST`). If either answers, the gate fails. `verify-cluster.sh --control-namespace` adds a destination proven reachable by a positive control |
| It stays in effect | the readiness probe reruns the gate every 30 s | Detection, not prevention: between probes, and while a probe fails, the process keeps running and in-flight scans continue; the Pod only stops receiving new requests through the Service. Nothing restarts it, by design (liveness asks only `/health`). `--drift-test` checks this behaviour |
| Ingress only to the proxy | NetworkPolicy: TCP 8443 only | Analysis listens on no TCP port, only `api.sock`. Code running in analysis shares the Pod's loopback: it can open connections to the proxy's 8443, which gives it nothing it does not already hold (the API token is in its own container). If the proxy is not running, such code could bind 8443 itself and receive client connections; it holds no TLS key, so a client that verifies the certificate refuses it. **Clients must verify the server certificate** |
| Secrets per container | the token is mounted only in analysis, the TLS key only in the proxy; no service-account token | `fsGroup` gives every container in the Pod the supplementary group 10001; the proxy uses it to open `api.sock`. Secrets in etcd are protected by the cluster's RBAC and encryption at rest, not by these manifests |
| Detection content read-only | the content claim is mounted `readOnly` in analysis and written only by the content Job while analysis is scaled to zero | The gate's `verify` mode tries a write and must fail; that probe file is removed if the write succeeds |
| Restart semantics | state and content: claims (persist); `/tmp`, the socket folder and the proxy's folders: emptyDirs (persist across a **container** restart, removed with the **Pod**) | The analysis start command clears `/tmp`; a stale `api.sock` is replaced when the server binds again. A Pod replaced by the Deployment starts with new emptyDirs and the same claims |
| Volume ownership | `prepare-state` (uid 10001, no `chmod`/`chown`) creates the state folders on a new claim | Relies on the storage driver applying `fsGroup`; if it does not, `prepare-state` fails with a clear message instead of running with wrong permissions |
| Execution and processes | read-only root, every capability dropped, no-new-privileges, seccomp `RuntimeDefault` | `/tmp` (memory-backed emptyDir) is **not** `noexec`: a file written there can be run. No per-Pod process limit in the spec: only the kubelet's `podPidsLimit` |
| Probes and shutdown | startup and liveness: `/health` over the socket; readiness: the gate, then `/ready`; grace period 330 s | Shutdown within the grace period is unverified; SIGTERM reaches `python` as PID 1 (the start command `exec`s it), and uvicorn handles it |

A sandboxed runtime (gVisor, Kata) and user namespaces strengthen the first and
the last rows where the cluster offers them ([Cluster requirements](#cluster-requirements)).

## Intel: external services

**Not available on Kubernetes in this version.** VirusTotal lookups and
uploads, the LLM (Ollama or OpenAI), the CAPE sandbox and e-mail alerts all go
through the intel service. Without it, the production profile sends nothing
outside, and the API's alert outbox stays disabled (`_Alerts` in `api/server.py`
is off without `AEGIS_INTEL_SOCKET` or SMTP settings), so nothing is queued
without a receiver. Webhooks are not configured in these manifests either. The
settings that would switch these on must not be added to the analysis container:
`check_manifests.py` and the isolation gate fail when they are.

### Decision record K8S-1: how analysis could reach intel (proposed, not approved)

**Context.** In Docker, intel is a separate container with an allowlisted egress
network; analysis has no network and reaches intel only over `intel.sock`,
a Unix socket in a volume shared by group (`core/intel_client.py` speaks HTTP
over a Unix socket and nothing else; `api/intel.py` listens only on a socket).
Intel authenticates analysis with `AEGIS_INTEL_TOKEN`, holds every external
credential, and filters destinations by origin (`core/http.py`).

**Constraints.** Kubernetes applies NetworkPolicy per Pod, and containers in a
Pod share one network namespace. A Unix socket works only within one node's
kernel: a shared ReadWriteMany claim (NFS, CephFS) carries files between nodes,
not socket connections, and a `hostPath` socket is refused by the restricted Pod
Security Standard and ties both Pods to one node.

| Option | Analysis network | Application change | Verdict |
|---|---|---|---|
| A. No intel (today) | none | none | Safe default; no external services or e-mail alerts |
| B. Intel and analysis in one Pod, socket in an emptyDir | the Pod gets intel's egress | none | **Rejected**: the hostile-file parser would share intel's egress, which no enforceable mechanism separates |
| C. Socket on a shared claim or `hostPath` | none | none | **Rejected**: does not work across nodes; `hostPath` breaks the restricted standard |
| D. Exchange files through a shared ReadWriteMany claim (queue folders) | none | large: every intel call is synchronous today (lookups, LLM, sandbox wait) and would become an asynchronous queue with its own timeouts; adds RWX storage and its locking semantics | Keeps "no network" but costs a redesign and a storage dependency; reconsider only if B and E are refused |
| **E. Intel in its own Deployment; analysis reaches it over TLS on one port** | exactly one destination: the intel Pods' TLS port | client HTTPS transport (below); no server change if intel keeps its socket behind a TLS proxy in its own Pod | **Recommended** |

**Recommended design (E).**

- *Intel Pod*: the `intel` container (uid 10002, unchanged: `python -m api.intel`
  on `intel.sock` in a Pod-local emptyDir) and a TLS proxy container (the same
  hardened Caddy image) that terminates TLS on 9443 and forwards to the socket,
  with its own request-size cap above `AEGIS_INTEL_MAX_UPLOAD_MB`. Same hardening
  as analysis; its own ServiceAccount without a token; a ReadWriteOncePod claim
  for its cache; one replica (its rate limits and e-mail caps are in-process).
- *Network*: analysis gets **one** egress rule: TCP 9443 to Pods labelled as
  intel (podSelector), nothing else; no DNS (the client uses the Service's
  ClusterIP, fixed in the overlay, with the certificate's name for SNI). Intel
  accepts ingress only from the analysis Pods on 9443 and has egress to the
  operator's destinations; NetworkPolicy cannot filter by name, so its egress is
  a CIDR rule (excluding the cluster ranges and `169.254.169.254`) and intel's
  origin allowlist remains the real filter. An egress gateway or a plugin with
  name-based policies (Cilium, Calico Enterprise) narrows it further.
- *Credentials*: the external keys, SMTP password and intel TLS key exist only in
  the intel Pod. Analysis holds the intel token (as in Docker) and the CA that
  signed intel's certificate. The analysis proxy shares analysis's network and
  can reach 9443 too, but holds no intel token and gets 401.
- *Application change*: an `AEGIS_INTEL_URL=https://CLUSTER-IP:9443` (the intel
  **Service's** ClusterIP, never a Pod IP) alternative to
  `AEGIS_INTEL_SOCKET` with `AEGIS_INTEL_CA_FILE` and `AEGIS_INTEL_SERVER_NAME`
  in `core/intel_client.py` (TLS 1.2+, certificate and name verified, no proxy
  environment variables honoured, the same reply-size limits), and the matching
  checks in `engine/validation.py`. The socket stays the default; Docker is
  unchanged.
- *Deployment changes*: intel manifests; `check_manifests.py` learns the one
  allowed analysis egress rule and the intel invariants (no external setting in
  analysis except the URL, token and CA; intel ingress only from analysis);
  `isolation_gate.py` gets the intel address as the one destination that
  **must** answer (a positive control inside every gate run) while every other
  probe must still fail.
- *Scheduling and runtime*: no co-location needed; about the Docker intel
  service's resources (`AEGIS_INTEL_MEMORY`, `AEGIS_INTEL_CPUS`); readiness of
  analysis stays independent of intel (an intel outage degrades to "external
  layers unavailable", as in Docker).
- *Operational cost*: a second Deployment, an intel TLS certificate to rotate,
  the egress CIDR list to maintain, and a cluster whose plugin enforces both
  ingress and egress rules.

**What changes in the trust boundary.** Analysis gains a network path to one
internal TLS port, where Docker gives it a socket. Authentication (token) and
what intel will do for analysis are the same as in Docker; reachability now
also depends on NetworkPolicy enforcement, which the existing gate already
requires. **Kubernetes analysis then has a restricted, authenticated network path
to one internal port; it does not have Docker's `network_mode: none` isolation.**

**Transport contract for option E** (resolved here; option E is still not approved
and nothing of it is built):

| Concern | Decision |
|---|---|
| Endpoint | The intel Service's ClusterIP and port 9443, set by the operator in the analysis Deployment's fixed `env` (not the ConfigMap, never from a scan or an API caller). The ClusterIP is stable for the Service's lifetime; intel Pods are replaced behind it (kube-proxy or the plugin maps it to the current endpoints). Pod IPs are never configured. Pinning `spec.clusterIP` in the overlay keeps it stable across a re-created Service |
| No DNS for analysis | The client connects to the IP literal and verifies the certificate against `AEGIS_INTEL_SERVER_NAME` (for example `aegis-intel.aegis-sentinel.svc`), passed as the TLS server name: Python's `ssl` checks the name from that parameter, not from the address, so hostname verification stays on without a lookup. The certificate carries that DNS name (an IP SAN would break when the Service is re-created) |
| Identity | TLS 1.2 or later, `CERT_REQUIRED`, hostname checked, trust only `AEGIS_INTEL_CA_FILE` (a private CA; not the system store). Any failure is an `IntelError`; there is no plaintext or unverified fallback, and an `http://` URL or a host name is refused by the configuration check |
| Token | Sent only on the connection to the configured address. Redirects are not followed (`http.client` does not, and a 3xx is an error), and proxy variables (`HTTPS_PROXY`, `NO_PROXY`) are ignored, so the token cannot reach another origin |
| Bounds | The socket client's limits apply unchanged: per-call time-outs, reply-size cap, `AEGIS_INTEL_MAX_UPLOAD_MB`, intel's own destination allowlist and rate limits |
| Retries | No hidden retries: lookups, uploads, sandbox submissions and e-mail are each attempted once per call; the outbox retries e-mail with the same alert id, and intel de-duplicates by it (in memory) |
| NetworkPolicy and the Service | Policies match Pods, so the analysis egress rule names the intel Pods (`podSelector`) and the target port 9443, not the Service. Calico, Cilium and Antrea evaluate ClusterIP traffic after it is translated to the Pod address; this must be shown on the chosen plugin (cluster test 4 below), because a plugin that evaluates the pre-translation address would block the path (safe failure) or need a different rule |
| Intel Pod topology | Intel's TLS proxy and intel share the intel Pod's network; intel's ingress rule admits only the analysis Pods on 9443, and its egress rule applies to both containers. The proxy holds only intel's TLS key |
| Start-up and restarts | Analysis readiness does not depend on intel. While intel starts or restarts, calls fail fast with `IntelError`: layers report "unreachable" and the scan is partial, the outbox keeps e-mail queued. A call in flight when intel restarts fails and is not retried |
| Certificate rotation | The CA file is read when a client is created (per scan configuration), so a new intel leaf certificate from the same CA needs no analysis restart. A CA change needs both CAs in the file for the overlap |
| Docker | Unchanged: `AEGIS_INTEL_SOCKET` stays the default and the only transport there |

**Tests required before it can be called isolated.**

1. Unit (local TLS server on loopback with a test CA): the HTTPS client refuses a
   wrong CA, a wrong server name, an expired certificate, a plain-HTTP URL, a host
   name that needs DNS, a 3xx reply (and does not send the token to its
   `Location`), and ignores proxy variables; a wrong token gives 401 as an
   `IntelError`; a server that stalls hits the call's time-out; a refused
   connection is "unreachable"; uploads are sent once; the same reply limits as
   the socket client; with only `AEGIS_INTEL_SOCKET` set, behaviour is identical
   to today (the existing socket tests).
2. Static: `check_manifests.py` rejects a second analysis egress rule, a wider
   port or selector, intel ingress from anything but analysis, intel egress to
   cluster ranges or the metadata address, and any external setting in analysis;
   tests with weakened copies, as today.
3. Gate: fails when intel does not answer (positive control) and when anything
   else does, including another port of the intel Pod.
4. Cluster (`verify-cluster.sh`, extended): analysis reaches intel 9443 with the
   token (200) and without it (401); the analysis proxy gets 401; analysis cannot
   reach the control listener, DNS, the API server, the internet or intel's other
   ports; a Pod in the control namespace cannot reach intel; intel cannot reach
   analysis; with a stand-in external service in the control namespace,
   allowlisted by CIDR, intel reaches it and analysis does not; the drift test
   with intel deployed.

Until the owner approves option E (or chooses A or D), Kubernetes runs without
external services.

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
| 413 on uploads under `AEGIS_API_MAX_UPLOAD_MB` | The proxy's 51 MiB cap in `deploy/Caddyfile` (raised past 50 MiB) |
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
| `verify-cluster.sh` | operator, approved test cluster, disposable namespaces | everything above on a running deployment, with positive controls for the network and secret checks, the readiness reaction to isolation drift, the API's upload limit, and a restart ([Verify](#verify)) |

Not covered without a cluster: server-side admission, schema validation against
the cluster's API version, whether the network plugin really enforces the
policies, storage permissions, probe timing, shutdown behaviour and resource use.
