# Deployment and trust boundaries

Three kinds of separation appear below. Keep them apart:

- **Reliability isolation**: worker processes under the same user. It contains hangs,
  crashes and memory blow-ups. It is **not** a security boundary: a parser exploit in a
  worker runs with the scanner's user, files and (on the desktop) configuration.
- **Security boundaries**: Docker containers (distinct users, no capabilities, read-only
  root, `network_mode: none` for the scanning side), Kubernetes Pods with NetworkPolicy, and
  the operator's separately isolated CAPE environment.
- **Static checks versus runtime enforcement**: `check_manifests.py` proves what the YAML
  says; only a running cluster with an enforcing network plugin makes it true.

## Desktop and CLI

One parent process (GUI, CLI or `--background`) and its scan workers, all as the signed-in
user. Workers receive the full configuration, API keys included, and make the VirusTotal,
LLM and CAPE requests themselves; the parent sends webhooks and e-mail, uploads to S3 and
fetches IMAP. The parent reads files only to walk, hash and quarantine them; only workers
parse them. Secrets are in the OS keyring; state (reports, quarantine, outbox, cache, canary
registry) is in the user's application folder. Containment actions run with the user's
rights (administrator rights for network and Controlled Folder Access). Status: [[impl]];
macOS [[local]]; Windows and Linux [[pending]] at this baseline.

## Docker Compose (the supported server edition)

| Container | Runs | User | Network | Holds | Mounts |
|---|---|---|---|---|---|
| `proxy` | Caddy, TLS on 8443 (the only published port), body cap 51 MiB, HSTS | 10003 | `edge` | TLS certificate (read-only) | `api-socket` |
| `analysis` | `python -m api.server` and its scan workers | 10001 | **none** (`network_mode: none`) | `api_token`, `intel_token` only | `analysis-state` (rw), `content` (**read-only**), both sockets, `/tmp` tmpfs 2 GiB `noexec,nosuid,nodev` |
| `intel` | `python -m api.intel`: the only component that reaches VirusTotal, the LLM, CAPE and SMTP | 10002 | `egress` | intel token, VirusTotal, OpenAI, sandbox and SMTP secrets | `intel-socket`, `intel-state`, `/tmp` tmpfs 256 MiB |
| `content` | rule-pack installs on demand (`tools` profile) | 10001 | none | — | `content` (rw) |

Every service: read-only root file system, `cap_drop: [ALL]`, `no-new-privileges`, memory,
CPU and process limits (analysis 6 GiB, 2 CPUs, 256 processes). The proxy reaches analysis
only through the `api.sock` Unix socket (directory group-restricted); analysis reaches intel
only through `intel.sock`. Intel accepts a fixed set of operations, authenticates a token of
at least 32 characters, rate-limits per operation, and its HTTP sessions refuse any origin
not configured (redirects included). Images are pinned by digest and dependencies installed
with `--require-hashes`; the build fails if containment code is present in the image.
`deploy/isolation_check.py` (run by `deploy/check-deployment.sh`) checks inside the running
containers that analysis has only loopback, no route and no outbound connection, that content
is read-only and `/tmp` is `noexec`, and that intel has no TCP or UDP listener.
Status: [[impl]]; [[ci]] on `3e5a3f2`; [[pending]] at this baseline (Docker was not running
on the review host). Not available in this edition: webhooks, JSON Lines, S3 upload,
automatic quarantine, canaries, IMAP.



## Kubernetes without intel (the base)

`deploy/kubernetes/base/`: one Namespace with Pod Security `restricted` enforced; one
Deployment `aegis-analysis` (one replica, `Recreate`) whose Pod holds `analysis` (uid 10001)
and `proxy` (uid 10003) joined by `api.sock` in a memory-backed `emptyDir`; a ClusterIP
Service on 8443; two `ReadWriteOncePod` claims (state 2 GiB, content 1 GiB, mounted
read-only in analysis and written only by the `aegis-content-update` Job while analysis is
scaled to zero); a ServiceAccount that mounts no token and has no Role.

**Network.** Containers in a Pod share one network namespace, so Docker's `network_mode:
none` has no equivalent. Isolation is a default-deny NetworkPolicy plus ingress to TCP 8443
only. This **needs a network plugin that enforces NetworkPolicy** and cannot block traffic
from the Pod's own node. Two runtime guards compensate: the `isolation-gate` init container
and the readiness probe run `isolation_gate.py`, which fails the Pod while the internet, the
cluster DNS, the Kubernetes API or the cloud metadata address answers. The gate is a sample
of destinations, not a proof of isolation.

**Other differences from Docker:** `/tmp` is a 2 GiB memory `emptyDir` **without** `noexec`
(cleared at container start); no per-Pod process limit exists in the Pod spec (use the
kubelet's `podPidsLimit`); Secrets are unencrypted in etcd unless the cluster encrypts them.
Probes: start-up `/health` (up to 10 minutes), readiness = gate + `/ready`, liveness
`/health`; termination grace 330 s, longer than a scan. Status: [[impl]]; rendered and
checked offline ([[local]], 139 Kubernetes tests); [[pending]] on any cluster.



## Kubernetes with option E (intel over TLS)

`components/intel` adds an `aegis-intel` Pod: the unchanged intel container on a Pod-local
socket, and an `intel-proxy` Caddy container terminating TLS 1.2/1.3 on 9443 with its own
101 MiB body cap. Analysis reaches it as follows:

- **Addressing.** `AEGIS_INTEL_URL` must be `https://<IP>:<port>`, the Service's fixed
  ClusterIP set in the overlay. Analysis makes **no DNS lookup**, so it needs no DNS egress.
- **Identity.** `AEGIS_INTEL_SERVER_NAME` (`aegis-intel.<namespace>.svc`) is used for SNI and
  host-name verification; only the private CA in ConfigMap `aegis-intel-ca` is trusted (no
  system store), and the CA file is re-read on every connection so CA rotation needs no
  analysis restart. TLS 1.2 minimum, certificate required.
- **Authentication.** A bearer token of 32+ characters from Secret `aegis-intel-token`,
  mounted in both Pods; compared in constant time by intel. Intel has no failed-token lockout
  (the REST API has one) and rate-limits per operation.
- **Transport restrictions.** Plain `http.client`: no redirects (anything but 200 is an
  error), proxy variables ignored, no retries; replies at most {{fact:intel_reply_mib}} MiB,
  identity encoding only, a declared length checked before and after reading, a JSON object
  required; a refused reply closes its connection at once.
- **NetworkPolicy.** Analysis egress: only TCP 9443 to Pods labelled as intel. Intel ingress:
  only 9443 from analysis. Intel egress: kube-dns on 53, and 443/465/587 to public addresses
  (private, loopback and link-local ranges excluded); an internal CAPE or Ollama needs its own
  narrow rule in the overlay. The plugin must enforce ingress *and* egress and evaluate policy
  after ClusterIP translation (Calico, Cilium and Antrea do).
- **Lifecycle.** Analysis readiness does not depend on intel; while intel is down, external
  layers report it unreachable and scans are `partial`. A new leaf certificate from the same
  CA needs an intel restart; a CA change uses both CAs in `aegis-intel-ca` during the
  overlap; a new token needs both Deployments restarted.

Status: [[impl]]; client transport [[local]] against a real TLS server on 127.0.0.1 with
throwaway certificates; manifests checked statically; [[pending]] on a cluster:
NetworkPolicy on ClusterIP traffic, the TLS proxy in the intel Pod, certificate rotation and
`verify-cluster.sh`'s intel checks. Corrected in this review: the guide said intel had its
own ServiceAccount; it shares `aegis-sentinel`, which mounts no token and has no Role.



## CAPE and other external systems

CAPE executes submitted files. It is the operator's own server and must be isolated by the
operator (its own network segment or VM, no route back into production). Aegis Sentinel only
submits files to it and reads reports. VirusTotal, OpenAI, the SMTP provider and S3 storage
are third parties governed by their own terms (`docs/THIRD_PARTY.md`).

## What is checked where

| Check | Static (offline) | Runtime |
|---|---|---|
| Container hardening, users, secrets per container, no service-account token, single replica, `ReadWriteOncePod`, probe wiring, intel URL and server name | `check_manifests.py` ([[local]]) | `verify-cluster.sh` on a disposable labelled namespace ([[pending]]) |
| Analysis cannot reach the network | — | Docker: `isolation_check.py` ([[pending]] here); Kubernetes: `isolation_gate.py` in the Pod ([[pending]]) |
| NetworkPolicy enforced by the plugin | — | only on a cluster ([[pending]]) |
| Image matches the revision under test | — | `verify-cluster.sh --image-digest` ([[pending]]) |

@diagram 5-deployment-trust-boundaries.svg | Diagram 5 - desktop and Docker deployments and their trust boundaries. A dashed frame is process separation (not a security boundary); a thick red frame is a container. | landscape

@diagram 6-kubernetes-trust-boundaries.svg | Diagram 6 - the Kubernetes base: one Pod, two containers, the isolation gate, two claims and a content Job. | landscape

@diagram 11-option-e-intel.svg | Diagram 11 - option E: the analysis Pod reaches intel only by a fixed ClusterIP on 9443, with a private CA, server-name check and token. | landscape
