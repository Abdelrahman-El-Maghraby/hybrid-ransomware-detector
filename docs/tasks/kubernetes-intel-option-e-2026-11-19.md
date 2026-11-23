# Task brief: intel on Kubernetes, option E (2026-11-19)

Sanitised technical brief. Branch `review/production-hardening` (local only),
started at `c3dc658`. The owner approved option E of the K8S-1 decision record
([KUBERNETES](../KUBERNETES.md#decision-record-k8s-1-how-analysis-reaches-intel-option-e-approved-and-implemented)),
including the restricted, authenticated network path from analysis to intel.
Not authorised: push, image publication, deployment, cluster creation, restricted
fuzzing, detection changes.

## What was built

- `core/intel_client.py`: `TlsEndpoint` and an HTTPS transport beside the Unix
  socket. `AEGIS_INTEL_URL` must be `https://IP:PORT` (the intel Service's
  ClusterIP); the certificate is verified against `AEGIS_INTEL_SERVER_NAME`
  without DNS, trusting only `AEGIS_INTEL_CA_FILE` (read per connection); TLS
  1.2+; no redirects, proxies, plaintext or retries. `intel_configured()` replaces
  the socket-only checks in validation, outputs, the outbox and the API's alerts.
  `engine/validation.py` refuses a bad URL, a missing or unreadable CA, a missing
  name and both transports at once. Docker's socket is unchanged and the default.
- `deploy/kubernetes/components/intel`: intel Deployment (intel, uid 10002, on a
  socket in a Pod-local emptyDir; `intel-proxy`, the hardened Caddy image with
  its own Caddyfile, TLS on 9443), fixed-ClusterIP Service, cache claim, three
  NetworkPolicies, the analysis patch; `overlays/example-intel`.
- `check_manifests.py`, `isolation_gate.py`, `verify-cluster.sh` extended (see the
  register row K8S-1). The base stays without intel.

## Decisions taken while implementing

- A Kustomize **component**, not a base change: no intel unless an overlay opts in.
- The component sets its own namespace and image placeholders (the base's do not
  reach a component's objects; found by the checker).
- The gate requires intel to answer only in `verify` (positive control); the init
  gate and readiness do not, so analysis readiness stays independent of intel. The
  decision record's earlier wording ("every gate run") was corrected.
- The checker now also refuses external settings in a ConfigMap that analysis
  loads through `envFrom` (a gap found while extending it).

## Checks

[VERIFICATION_MATRIX](../VERIFICATION_MATRIX.md) section 7. Runtime on a cluster
is pending and needs separate authorisation.

Reviewed on 2026-11-19: [review brief](kubernetes-option-e-review-2026-11-19.md) (findings K8S-R1 to K8S-R5).
