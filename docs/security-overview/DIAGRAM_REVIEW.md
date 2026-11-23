# Architecture diagram review (2026-11-19)

Every diagram in `docs/architecture/uml-diagram-sources/` was reviewed against the code at
`e012d3f` (application code last changed in `d45715a`; `deploy/kubernetes/` in `a1c752e`).
Before this review the diagrams described `b6966f8` (diagrams 1 to 5) and `706ea8a`
(diagram 6). The 44 commits since changed `engine/workers.py`, `api/server.py`,
`api/intel.py`, `core/intel_client.py`, `core/outbox.py`, `core/outputs.py`,
`core/mailer.py`, `detectors/web_content.py`, `engine/completeness.py`, `engine/config.py`,
`engine/metrics.py`, `engine/validation.py` and the Kubernetes manifests.

## Method

1. Every identifier in the six definitions (class, method, attribute and message names) was
   extracted and searched for in `engine/`, `detectors/`, `core/`, `api/`, `aegis_gui/` and the
   entry points: all of them exist (the only misses were local variables of the drawing code
   and Kubernetes object kinds).
2. Counts and structure were read from the code by `docs/security-overview/facts.py`: 22
   layer objects from 19 `Layer` subclasses, 4 `ContainerLayer` instances, 5 heavy layers, 19
   typed signals, 23 scorer functions, the 12 worker message kinds, the mixin order, 16
   detection engines.
3. Behaviour shown in the drawings (layer order and parallel execution, context and signal
   flow, container recursion, worker messages and failure outcomes, interface outputs,
   deployment boundaries) was compared with `engine/staging.py`, `engine/layers.py`,
   `engine/containers.py`, `engine/workers.py`, `engine/scanner.py`, `core/outbox.py`,
   `api/server.py`, `docker-compose.yml` and `deploy/kubernetes/`.
4. `build_diagrams.py` was run: no label wider than its box, no overlapping nodes, no
   connector through an unrelated node, for all eleven diagrams.

## Results per diagram

| # | Diagram | Finding | Change |
|---|---|---|---|
| 1 | Class | Accurate. A note said the intel client is used "(Docker)" only; option E adds a TLS transport (`TlsEndpoint`) | note updated |
| 2 | Use cases | Accurate: three primary actors, interfaces as tags, seven external systems | none |
| 3 | Activity | Missing RV-S2 (`e849f3b`): an `ok` result or a snapshot whose `file_path` is not the dispatched file is refused and the file gets `failure_result()`. The intel note named only the Unix socket | guard on the failure branch and a checked note added; intel note mentions TLS on Kubernetes |
| 4 | System flowchart | Said services are reached "through the intel service over a Unix socket (Docker)" only | now "a Unix socket (Docker) or TLS (Kubernetes, option E)" |
| 5 | Desktop and Docker | Accurate against `docker-compose.yml` (users 10001/10002/10003, `network_mode: none`, secrets per container, read-only content) | none |
| 6 | Kubernetes base | Drawing accurate. The page text in `build_diagrams.py` still said "There is no intel service on Kubernetes yet" | text corrected; option E drawn separately as diagram 11 |
| 7 | One file across processes (sequence) | new | added |
| 8 | Layers, context and evidence flow | new | added |
| 9 | Nested containers | new | added |
| 10 | Scoring versus completeness | new | added |
| 11 | Option E communication | new | added |

The baseline in `build_diagrams.py` (`META`) now names `e012d3f` / `d45715a` / `a1c752e`.
The proposed multi-tenant architecture is **not** drawn here; implemented-system diagrams and
proposals are kept apart.

## Related documentation corrections

- `docs/KUBERNETES.md`: the K8S-1 decision record said the intel Pod has "its own
  ServiceAccount without a token"; `components/intel/intel.yaml` uses the shared
  `aegis-sentinel` account (which mounts no token and has no Role). The cluster-requirements
  row and the "Secrets and TLS" section described the base only without saying so; both now
  name what the optional intel component adds.
- `docs/architecture/README.md`: baseline, eleven diagrams, text summaries of diagrams 7 to 11,
  and the Graphify snapshot status.

## Graphify

The committed `docs/architecture/graphify-code-graph.html` is a snapshot of an earlier commit
and was not replaced. For this review a code-only Graphify build (no LLM) was run on a clean
`git archive` of `e012d3f` in a temporary folder: 8,038 nodes, 18,823 edges, 407 communities
over 334 files, including tests, documentation and manifests (the committed snapshot covered
253 Python files, so the counts are not comparable). Its hubs (`RansomwareScanner`,
`ContainerExtractor`, `ScoringMatrix`, `ScanContext`, `_IsolatedScan`) agree with the
diagrams. The refreshed page was not committed because its communities are unlabelled without
the LLM step; the graph was used for navigation only.

## Not verified

The diagrams describe code and manifests. Drawing a Kubernetes or Docker boundary does not
show that it holds at run time: see `docs/VERIFICATION_MATRIX.md` for what has been run.
