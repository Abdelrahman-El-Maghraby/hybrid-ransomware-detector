# Task brief: review of option E (2026-11-19)

Sanitised technical brief. Branch `review/production-hardening` (local only),
started at `0898a8a`. Scope: review and verify the completed option E
implementation ([brief](kubernetes-intel-option-e-2026-11-19.md)), fix confirmed
defects with regression tests, make the cluster verification ready for an
operator, prepare Windows and Linux verification. No new features. Not
authorised: push, workflow dispatch, pull request, image publication, cluster
creation, deployment, malware, restricted fuzzing, OOM reproduction, detection
or result-schema changes.

## 1. The request path, end to end

Traced in the code and the rendered `overlays/example-intel`:

1. Analysis (`core/intel_client.py`): `client_from_config` builds a
   `TlsEndpoint` from `AEGIS_INTEL_URL` (an IP literal and port only),
   `AEGIS_INTEL_CA_FILE` and `AEGIS_INTEL_SERVER_NAME`. `_TlsConnection` connects
   to the IP (no DNS: a numeric address) and wraps the socket with
   `server_hostname` = the configured name, in a context that trusts only the CA
   file (read for every connection), TLS 1.2+, `CERT_REQUIRED`,
   `check_hostname`. `http.client` reads no proxy variables and follows no
   redirect; any status but 200 is an `IntelError`; a failed connect or
   handshake is `NotConnected` (nothing was sent), so sandbox submissions are
   reported `not_attempted`. One attempt per call; the outbox retries e-mail
   with a stable id.
2. Network: one analysis egress rule (TCP 9443 to the intel Pods); the
   ClusterIP is translated to an intel Pod by the cluster (an assumption, below).
3. Intel Pod: Caddy (`intel-proxy`, uid 10003) terminates TLS on 9443 with
   `aegis-intel-tls`, caps bodies at 101 MiB and forwards to
   `unix//run/aegis/intel/intel.sock` in a Pod-local emptyDir; uvicorn creates
   the socket mode 0666 (only the two containers of this Pod mount it).
4. Intel (`api/intel.py`, uid 10002): bearer token in constant time, then per-
   operation rate limit, body limit, exact input checks; the answer returns the
   same way. Probes use `/health` on the socket (no token).

Rendered references checked: generated ConfigMap names (`aegis-intel-config-*`,
`aegis-intel-proxy-*`) resolve in the Deployment; Secret names and items;
labels and selectors of the Deployment, Service and three policies; port names
(`intel-tls`); namespace on every object; `fsGroup` 10002 for the claim.

## 2. Confirmed issues, fixed

Register rows K8S-R1 to K8S-R5:

- **K8S-R1** (checker): a split default route (`0.0.0.0/1` + `128.0.0.0/1`,
  `8000::/1`) passed the intel egress check while covering every private range.
- **K8S-R2** (script): nothing tied the running images to the revision under
  test; `--image-digest` is now required and checked on every container.
- **K8S-R3** (script): intel negatives without positive controls; now gated,
  with `INCONCLUSIVE` and exit 3. Added the wrong-name, per-container secrets
  and intel restart checks.
- **K8S-R4** (records): a "reply-size cap" claimed for the intel client does not
  exist in either transport; the CA was said to be read per client (it is per
  connection). Corrected in the decision record.
- **K8S-R5** (records): stale "no intel" statements, unstated cluster
  assumptions, and the certificate name that must change with the namespace
  (now set in the example overlay; the checker already refuses a mismatch).

## 3. Reviewed and found correct (no change)

TLS identity and private-CA trust (and the 25 loopback TLS tests behind them);
no DNS, proxy, redirect, plaintext or retry; token only to the configured
address; secret separation per container (checker and rendered output);
Docker's socket path untouched (`AEGIS_INTEL_SOCKET` stays the default; no code
path changed); probes and grace periods; Recreate and `ReadWriteOncePod` for
the intel claim; the analysis readiness independent of intel; the gate's
positive control only in `verify`.

## 4. Open, recorded for the owner (not changed)

- ~~No reply-size cap in the intel client~~: approved by the owner and added
  the same day (section 9).
- Intel has no isolation gate of its own; its policies are checked statically
  and by `verify-cluster.sh` only.
- The analysis proxy's 401 against intel, analysis to intel's other ports and a
  stand-in external service allowlisted by CIDR are not automated (the decision
  record says why).
- No `.gitattributes`: a Windows checkout gets CRLF shell scripts. Tests skip
  them on Windows; an operator running the scripts from such a checkout needs LF
  files (WSL or `git config core.autocrlf input`).

## 5. Evidence of the earlier run

The 2,112-test result in VERIFICATION_MATRIX section 7 matches its log: 2,112
passed, 8 skipped, 4 deselected, 0 failed, 0 errors, exit 0, 581 s, plus one
warning not mentioned in the record (Starlette's deprecation of `httpx` in its
test client). The log does not print the revision; the record's `706ea8a` comes
from the worktree it ran in. Limits as recorded: macOS only, Python 3.14,
`tests/test_fuzz_parsers.py` excluded, the memory-limit test (OOM) and three
intel-socket tests deselected, and no network beyond loopback.

## 6. Checks of this review

[VERIFICATION_MATRIX](../VERIFICATION_MATRIX.md) section 8.

## 7. Runtime verification plan (needs owner approval and a chosen cluster)

Not selected yet: **which test cluster.** Requirements:

- Kubernetes 1.29+; a network plugin that enforces NetworkPolicy ingress **and**
  egress and applies it after Service address translation (Calico, Cilium or
  Antrea); a CSI storage class with `ReadWriteOncePod` that applies `fsGroup`;
  Pod Security admission; Pod, Service and node ranges inside intel's excluded
  private ranges (or the overlay extended); about 2 CPU and 8 GiB free on one
  node.
- A local kind cluster with its default plugin disabled and Calico installed
  meets these at no cost (whether kind's own plugin enforces NetworkPolicy
  depends on its version, so it is not relied on), but needs `kind` installed
  (an installation, so an approval) and Docker resources on this Mac. A managed
  test cluster costs money and must be created by the owner.

Resources and images: both images built locally from the revision under test
(`docker build --target server`, `--target proxy`), loaded into the cluster or
pushed to a **private test** registry (not a publication); their digests passed
to the script. Operator-made test material only: a test API token and CA, a
test intel CA and leaf for `aegis-intel.aegis-verify.svc`, an intel token, an
empty credentials Secret (no external service is contacted).

Created or changed: two namespaces labelled
`aegis-sentinel.io/verification=disposable`; the deployment from a copy of
`overlays/example-intel` (namespace `aegis-verify`, a free Service address, the
certificate name, and the same label on the Deployments and Pod templates, which
the restart test requires before it deletes a Pod); during the run, two control Pods and one Service in the
control namespace, one drift NetworkPolicy, and one deletion each of the
analysis and intel Pods. Inputs are inert: a one-line text file and a zero-filled
file one byte over the upload limit.

Clean-up and data: the script deletes only what it created and its two marker
files; the operator deletes both namespaces at the end (claims and their volumes
follow the storage class's reclaim policy: use `Delete` on a test cluster). No
existing cluster resource or data is touched; the current kube context is never
read or changed.

Then by hand, as listed in the guide's "Expected results": certificate rotation
(same CA, CA change with overlap, an untrusted CA must fail) and shutdown during
a scan.

## 8. Windows and Linux (needs owner approval to push)

No workflow starts on a push of this branch: `tests.yml` and `quality.yml` run
on pushes to `main` and on pull requests, `docker.yml` on `main`,
`integration/**`, `fix/**` and `area/**`, `parser-fuzz` only on pull requests
and dispatch. So: push the branch, then dispatch `tests.yml` (Ubuntu, Windows,
macOS; Python 3.9 and 3.12), `quality.yml` and `docker.yml` (the Docker socket
deployment, built and checked in the runner; nothing published) with
`--ref review/production-hardening`. Do **not** open a pull request (it would
start `parser-fuzz`, a restricted campaign). The one workflow change prepared:
the Linux test jobs fail when the Kubernetes render tests are skipped
(`ef3a5c4`).

## 9. Follow-up (2026-11-19): reply limit, restart scope, this Mac, publication

Owner request: add an intel reply-size limit; restrict restart-test deletions to
the test deployment; assess this Mac for the cluster run (read-only); recheck
the workflow triggers before a push. Not authorised: installing tools, starting
Docker or a cluster, changing settings, pushing, dispatching.

**Reply limit** (K8S-R4, `f8a10a3`, `7f95021`, `d45715a`). Replies inspected: capabilities,
the VirusTotal summary (`engine/external.py`), the normalised LLM analysis
(`detectors/llm_backends._parse_analysis`: 20 elements, the explanation bounded
only by the model's output, about 0.5 MB at most for a 128k-token context), the
sandbox summary (`core/sandbox.SandboxResult.as_dict`: 30 signatures with
200-character descriptions, 20 hosts), the e-mail receipt and HTTP error details:
a few kilobytes in practice. `MAX_REPLY_BYTES` = 1 MiB on both transports
(`read_reply`): a declared length over it is refused before reading; a body
without one or chunked is read to limit + 1 and refused; a body shorter than its
declared length is refused; any `Content-Encoding` but identity is refused (the
client sends `Accept-Encoding: identity`; nothing is decompressed). With a 200
that is not JSON, these are `IntelError` carrying the status, so the existing
paths apply: VirusTotal errors are not cached, the LLM layer fails (partial), a
sandbox submission stays `possible`, capabilities read as unreachable (not
cached), e-mail stays queued. Findings already collected by other layers are
untouched. No change for replies within the limit. A refused reply's
connection is closed at once (`d45715a`; before it, garbage collection closed
it, which the safe suite showed as ResourceWarnings).

**Restart scope** (K8S-R6, `a1c752e`). Pod deletion needs the test label on the
Deployment and its Pod template, and the Pod's ReplicaSet owner checked just
before deletion.

**This Mac** (read-only checks): Apple M1, 8 cores (4 performance), **8 GiB
RAM** (about 44 % free during the check), 44 GiB free disk, macOS 27.2.1.
Docker Desktop 4.97.0 installed, its engine **not running** (no CPU or memory
setting stored, so its defaults apply); `kubectl` 1.36.1 installed; kind,
minikube, k3d, colima, helm and the Calico and Cilium CLIs not installed.
Assessment: **not suitable for the representative run.** The analysis Pod
requests 6 GiB of memory (request equals limit, matching Docker's 6 GiB), intel
512 MiB to 1 GiB, plus the kind control plane and Calico, inside a Docker VM
that must leave macOS memory: more than 8 GiB of RAM allows. A reduced
functional run would need a test-only overlay lowering the analysis memory
(with `WORKER_MEMORY_MB` and the scan concurrency) to fit a VM of about 5-6 GiB;
it would exercise isolation, TLS, intel, restarts and clean-up but not the
production sizing or behaviour under memory pressure, and it would make this
Mac swap. Recommended instead: a machine or a small test cluster with at least
16 GiB (for example one node of 4 vCPU and 16 GiB), chosen and paid for by the
owner.

**Publication** (read-only checks; nothing pushed). The remote has `main`
(`bd46fff`) and `validation/v4.8-remaining` (`3e5a3f2`, PR #46); it has no
`review/production-hardening`. Pushing it would publish every local commit
since `3e5a3f2`: 163 commits at this follow-up's last code commit, about 260
files (tests, docs, deploy, detectors, engine, core, GUI, tools, rules,
`.github`), all authored as the owner. Triggers in the branch's own workflow
files: `tests.yml` and `quality.yml` run on pushes to `main` and on pull
requests; `docker.yml` on pushes to `main`, `integration/**`, `fix/**`,
`area/**` and on pull requests; `parser-fuzz` on pull requests touching `fuzz/`,
`detectors/`, `core/`, `engine/` or `requirements.lock`; `release.yml` on `v*`
tags; `dependency-audit.yml` on a schedule; all can be dispatched. None uses
`workflow_run`, `repository_dispatch` or `workflow_call`. So pushing
`review/production-hardening` alone (no tags; `push.followTags` is not set)
starts no workflow; opening a pull request would start `tests`, `quality`,
`docker` and `parser-fuzz`. Repository-side settings (for example a code
scanning default setup) cannot be seen from here. Before publishing: two
earlier commits (`a11b37c`, `74b6aef`) carry a `Co-Authored-By` trailer that
AGENTS.md does not allow; removing it would rewrite every later commit and the
hashes the records cite, so it needs the owner's decision. The diff contains no
private key, cloud key or token pattern, and `.env.example` has no values.
