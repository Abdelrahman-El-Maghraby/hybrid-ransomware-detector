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

- No reply-size cap in the intel client (both transports). A cap would also
  change the Docker client; the reply comes from the authenticated intel
  service. Owner decision.
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
certificate name); during the run, two control Pods and one Service in the
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
