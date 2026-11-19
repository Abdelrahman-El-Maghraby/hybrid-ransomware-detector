# Appendix A: Glossary

| Term | Meaning in this project |
|---|---|
| Allowlist | SHA-256 hashes an operator marked as known-good; the score becomes 0 unless the MD5 is in the malware database |
| Analysis (container or Pod) | the server-side component that runs the REST API and scan workers; it parses files and has no network in Docker |
| Capability state | `up`, `down` or `disabled` for each layer, computed at start-up (`engine/capabilities.py`) |
| Category | `technical`, `reputation`, `semantic`, `statistical` or `dynamic`; each has a cap |
| Container (file) | a file that holds other files: archive, disc image, package, message, web page with payloads, OneNote/CHM/MSI, encrypted Office |
| Contribution | one indicator's points with its category and a human-readable detail |
| Fail closed | if isolated workers cannot start, files are reported unscanned instead of being parsed in the main process |
| Heavy layer | emulation, ML, LLM, VirusTotal, sandbox: run last, concurrently, and skipped when they cannot change the verdict |
| Indicator | a named finding in `detectors/indicators.yaml` with a weight and a category |
| Intel (service) | `api/intel.py`: the only component holding external-service credentials in Docker and Kubernetes; fixed operations only |
| Isolation gate | `isolation_gate.py`: Kubernetes init container and readiness check that fails the Pod when the network answers |
| Layer | one step of the pipeline (`Layer` subclass) that adds one kind of evidence |
| Option E | the approved design for intel on Kubernetes: TLS on one port to a fixed ClusterIP with a private CA (decision K8S-1) |
| Outbox | the persistent alert queue (`core/outbox.py`) |
| Partial evidence | findings a worker reported before it failed, kept in `scan_results.partial_evidence` |
| Production profile | `AEGIS_PROFILE=production`: required layers on, emulation, containment and isolation opt-outs refused |
| Provenance | per-result record of what ran, what was unavailable, and what was sent outside |
| Provisional, settled, completed | snapshots a worker sends so the parent can keep findings if it must stop the worker during a slow wait |
| Registry | `detectors/indicators.yaml`, versioned weights, caps and labels |
| Risk score | 0-100 weighted, capped total; not a probability |
| Rule pack | a signed bundle of YARA rules and fuzzy signatures (`core/rulepack.py`) |
| Scan status | `complete`, `unsupported`, `partial`, `locked`, `failed`: how much was inspected |
| Signals | the typed per-layer evidence the scorer reads (`detectors/signals.py`) |
| Verdict / verdict label | the score band; the label adds the scan status when it is not complete |
| Worker | a spawned process that parses and scans one file at a time under time and memory limits |
| Worst member | a container's highest-scoring member, whose contributions are added to the container with a prefix |

# Appendix B: Code-reading guide

In priority order; each step builds on the previous one.

| # | Read | To understand |
|---|---|---|
| 1 | `docs/architecture/README.md`, then diagrams 7, 8 and 10 | the shape of the system in text and pictures |
| 2 | `engine/layers.py` (`ScanContext`, `default_pipeline`, `ORDER_RULES`) | what a layer is and the order |
| 3 | `engine/staging.py` (`scan_file`, `_run_heavy`, `_run_together`, `_assemble`) | the coordinator and the merge |
| 4 | `detectors/signals.py`, `detectors/scoring.py`, `detectors/indicators.yaml` | how evidence becomes points |
| 5 | `engine/completeness.py`, `engine/provenance.py` | scan status and what is recorded |
| 6 | `engine/workers.py` (module docstring, `check_reply`, `_IsolatedScan._step`, `failure_result`, `stopped_result`) | isolation and every failure path |
| 7 | `engine/containers.py`, `detectors/container_extractor.py` | recursion and archive safety |
| 8 | the detectors you will touch (`detectors/*.py`), with their tests | detection logic |
| 9 | `engine/external.py`, `detectors/llm_backends.py`, `detectors/prompt_guard.py`, `core/sandbox.py` | external services and the untrusted-text handling |
| 10 | `api/server.py`, `api/limits.py`, `api/intel.py`, `core/intel_client.py` | the server edition and its trust boundary |
| 11 | `core/outbox.py`, `core/outputs.py`, `core/mailer.py`, `core/cloud.py` | delivery guarantees |
| 12 | `engine/protection.py`, `core/quarantine.py`, `core/canary.py`, `core/response.py`, `core/containment.py` | desktop protection |
| 13 | `docker-compose.yml`, `Dockerfile`, `deploy/`, `deploy/kubernetes/` with `docs/KUBERNETES.md` | deployments |
| 14 | `docs/THREAT_MODEL.md`, `docs/FINDINGS_REGISTER.md`, `docs/VERIFICATION_MATRIX.md` | risks, open items, evidence |

# Appendix C: Architecture diagrams and their review

All eleven diagrams are generated from Python definitions in
`docs/architecture/uml-diagram-sources/` (`build_diagrams.py`, standard library only) and
stop the build on a label that does not fit, overlapping nodes or a connector crossing an
unrelated node. Diagrams 1, 5, 6, 7, 8, 9, 10 and 11 appear in the chapters; 2, 3 and 4
follow. The full review record is `docs/security-overview/DIAGRAM_REVIEW.md`.

| # | Diagram | Review outcome at `e012d3f` |
|---|---|---|
| 1 | Class | names and relationships match the code; note updated: the intel client also uses TLS (option E) |
| 2 | Use cases | unchanged; actors versus interfaces correct |
| 3 | Activity | updated: a result or snapshot naming another file is refused (RV-S2); intel transport note |
| 4 | System flowchart | updated: services reached through intel by Unix socket (Docker) or TLS (option E) |
| 5 | Desktop and Docker trust boundaries | unchanged; matches `docker-compose.yml` |
| 6 | Kubernetes base | drawing unchanged; page text corrected (it said no intel existed on Kubernetes) |
| 7-11 | Sequence, layer flow, nested containers, scoring versus completeness, option E | new |

@diagram 2-use-case-diagram.svg | Diagram 2 - actors and use cases. The GUI, CLI and REST API are interfaces, shown as tags, not actors. | landscape

@diagram 3-activity-diagram.svg | Diagram 3 - activity diagram of one isolated scan, with every outcome of the wait. | landscape

@diagram 4-system-flowchart.svg | Diagram 4 - system flowchart: six intake channels, one engine, per-channel destinations. | landscape

# Appendix D: Building this document

The PDF, its diagrams and the facts it quotes are reproducible from the repository:

```sh
.venv/bin/python docs/security-overview/build_overview.py
```

This (1) recomputes the quoted facts from the code (`facts.py`) and stops if they differ from
`src/facts.json`, (2) rebuilds all diagrams, (3) renders `src/*.md` with markdown-it-py,
inlining diagrams as SVG, (4) prints the HTML twice with headless Google Chrome to fill the
page numbers of the contents, with PDF bookmarks generated from the headings, and (5)
checks the PDF with pypdf (page text, bookmarks, links, no leftover placeholders). It needs
the repository's virtual environment (with `markdown-it-py`) and Chrome 131 or later.
Nothing is downloaded and no network is used. After a reviewed code change that alters a
quoted value, update the text and run `facts.py --write`. See
`docs/security-overview/README.md` for details and limitations.
