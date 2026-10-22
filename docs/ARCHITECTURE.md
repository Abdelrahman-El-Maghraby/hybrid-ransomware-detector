# Architecture overview

A short, defensible tour of how Aegis Sentinel is built and why. Each section
ends with the files to read.

## 1. One file, one context, many independent layers

`RansomwareScanner.scan_file(path)` creates a `ScanContext` (the path, the result
that ends up in the report, and a `signals` dict only the scoring reads) and runs
the layers of `default_pipeline()` in order. Layers never call each other; they
read what earlier layers left in the context. That keeps each one testable on its
own and makes the order a single, visible list.

```
hashes → allowlist → fuzzy → local-db → macro → yara → integrity → elf → script
→ mail⟲ → prompt-guard → relationships → qr → archive⟲ → web⟲ → embedded⟲
→ [ml · llm · virustotal · sandbox]   (slow layers: skipped at 100, else concurrent)
```

⟲ = container: members are unpacked into a temporary folder and scanned through
the whole pipeline again; the container inherits its worst member's evidence.

*Read:* `engine/scanner.py`, `engine/layers.py`, `engine/containers.py`.

## 2. Evidence → score: a registry, categories and caps

Every layer turns findings into **signals**; `ScoringMatrix` turns signals into
**contributions** (indicator, category, points, human-readable detail). Points come
from `detectors/indicators.yaml`. Categories are capped (technical 100, reputation
80, semantic 24, statistical 20, dynamic 100), summed, clamped to 100 and mapped to
verdict bands. Two rules make the score hard to game:

- semantic / statistical evidence alone never exceeds Medium (49);
- the LLM category is capped below the Medium ceiling, so a fooled model cannot
  outweigh one structural finding.

Why hand-set weights? There was no labelled data at the start. They are written
down in one place, tested by the regression corpus, and `tools/calibrate_weights.py`
proposes data-driven values (cross-validated) for review.

*Read:* `detectors/indicators.yaml`, `detectors/registry.py`, `detectors/scoring.py`.

## 3. Hostile input is the normal case

- **Bounded everything:** depth, member count, bytes, compression ratio, pixels,
  pages, decoding depth.
- **Guards:** each layer runs in a try-block (`layer_errors`); folder and API scans
  run each file in a worker process with a time and memory limit (`scan_failed`).
- **Fuzzing:** every parser, in CI and with atheris for long runs.

*Read:* `engine/workers.py`, `tests/test_fuzz_parsers.py`, `docs/THREAT_MODEL.md`.

## 4. Static first, dynamic optional

Everything above is static: no file is executed or rendered, links are never
followed. Behaviour that only shows at run time is the main blind spot; the optional
`sandbox` layer hands suspicious files to the user's own CAPEv2 server and scores
its behaviour signatures in a separate *dynamic* category.

*Read:* `core/sandbox.py`.

## 5. Privacy by default

Local layers need no network. VirusTotal is hash-only unless uploads are enabled;
the LLM prefers a local Ollama model; the sandbox is self-hosted; webhooks carry
metadata only.

## 6. Interfaces

CLI (`RansomwareScanner.py`), desktop app (`aegis_gui/`), background scheduler with
canary tripwires, JSON Lines and signed webhooks for SIEM/SOAR, and an optional REST
API. All results follow `api/scan_result.schema.json` (`schema_version`).

## 7. Keeping it trustworthy over time

Quality gates on every pull request (lint, types, coverage floor, dependency audit,
regression corpus); signed rule packs for content updates; tagged releases built in
CI with checksums, an SBOM and Sigstore signatures.

## Questions this design answers

| Question | Short answer |
|---|---|
| Why not one ML model? | No labelled data for most file types; explainability matters to an analyst; ML is one capped layer. |
| Why can't the LLM decide? | It reads attacker-controlled text. It is spotlighted, capped, and cannot clear technical findings. |
| How do you avoid false positives on compressed files? | Randomness is only tested after the format signature is already missing. |
| What if a parser hangs? | Worker timeout → `scan_failed` (Medium), the scan continues. |
| How are weights justified? | Registry + regression corpus now; calibration from labelled data next. |
| What does it not catch? | Run-time-only behaviour without the sandbox; detection rate on real samples is not yet measured. |
