# Task brief: optional Kubernetes deployment (2026-11-18)

Sanitised technical brief; no private context. Branch
`review/production-hardening` (local only), started at `b93f287`.

## 1. Request

Add an optional, secure, single-instance Kubernetes deployment that reuses the
existing images, with manifests, supporting tools, tests, an operator guide and a
Kubernetes trust-boundary view. Docker Compose and the desktop/CLI stay as they
are and remain supported.

Authorised: Kubernetes manifests and tooling, documentation, meaningful tests,
minimal application changes only if deployment compatibility requires them,
static checks and safe local tests, local commits, the handoff.

Not authorised: push, merge, image publication, release, deployment to any
cluster, changing a Kubernetes context or cluster settings, cloud resources,
installing software or starting a local cluster, malware or restricted
artifacts, fuzz campaigns, OOM reproduction, detection weight / threshold /
coverage / result-schema changes, weaker isolation, touching unrelated work.
Security-sensitive transport or trust-boundary changes need a proposal and an
owner decision first.

## 2. Decision

Read from the code: the proxy reaches the API over `api.sock`; analysis reaches
intel only over `intel.sock` (`core/intel_client.py` speaks HTTP over a Unix
socket only); the analysis service passes the production-profile configuration
check without intel and with `LLM_PROVIDER=none`.

Chosen: one Pod with the analysis and proxy containers joined by the socket in an
emptyDir; default-deny NetworkPolicy, ingress TCP 8443 only, no egress; an
isolation-gate init container and readiness probe that fail while outside
destinations answer; ReadWriteOncePod claims; content written only by a Job while
analysis is scaled to zero; no intel. Rejected alternatives and reasons:
`docs/KUBERNETES.md`, "Architecture".

Owner decision required (K8S-1): the intel transport on Kubernetes. Proposal in
`docs/KUBERNETES.md`, "Intel". Until decided, external services and e-mail
alerts are unavailable on Kubernetes. Nothing of the proposal is implemented.

## 3. Deliverables

| Deliverable | Where |
|---|---|
| Kustomize base, example overlay, content Job | `deploy/kubernetes/base/`, `overlays/example/`, `jobs/` |
| In-Pod isolation gate | `deploy/kubernetes/base/isolation_gate.py` (ConfigMap) |
| Static manifest checker | `deploy/kubernetes/check_manifests.py` |
| Operator scripts (not run) | `deploy/kubernetes/verify-cluster.sh`, `content-update.sh` |
| Tests | `tests/test_kubernetes.py` |
| Guide | `docs/KUBERNETES.md`, linked from `docs/DEPLOYMENT.md` and `README.md` |
| Threat model | `docs/THREAT_MODEL.md` section 14 |
| Diagram 6 | `docs/architecture/uml-diagram-sources/d6_kubernetes_trust_boundaries.py` and the SVG and page |

No application code changed. Two deployment-level problems were found while
building and fixed in the manifests: an emptyDir outlives a container restart
(Docker's tmpfs does not) and the worker sweep skips its own PID, so the analysis
container empties its private `/tmp` before it starts; and on a new claim the
runtime would create the nested content mount point as root 0755, so an init
container (`prepare-state`) creates the state folders as uid 10001 first.

Commits: `a139fa3` (manifests, checker, scripts, tests), `00c0639` (guide,
`/tmp` clearing), `7ae85eb` (diagram 6, threat model 14), `817d3b9`
(`prepare-state`), then a commit with the fresh- and existing-volume tests and
these documents. Checks and their results: [VERIFICATION_MATRIX](../VERIFICATION_MATRIX.md)
section 4.

## 4. Remaining steps (need approval or infrastructure)

1. Owner: decide K8S-1 (intel transport).
2. Owner: approve a dedicated test cluster (Kubernetes 1.29+, an enforcing
   network plugin, a CSI class with ReadWriteOncePod), then the operator builds
   and loads the images, creates the two Secrets, applies a filled-in overlay and
   runs `deploy/kubernetes/verify-cluster.sh --restart-test`, plus
   `content-update.sh` with a test-signed pack.
3. Not checked here: the image contains `sh` and `find` (Debian essential
   packages; Docker was not running), server-side admission and schema
   validation, NetworkPolicy enforcement, fsGroup handling by the storage
   driver, probe timing, shutdown within the grace period, resource use.
