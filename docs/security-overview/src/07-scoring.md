# Scoring and verdicts

## From signals to a score

`ScoringMatrix.score(signals)` (`detectors/scoring.py`) does four things, in order:

1. **Contributions.** Each of the {{fact:scorers}} scorer functions in `SCORERS` looks at
   one signal and returns zero or more `Contribution(indicator, category, points, detail)`.
   The indicator names, categories, weights and labels are defined once, in
   `detectors/indicators.yaml` ({{fact:indicators}} indicators, registry
   {{fact:registry_version}}). Most weights are fixed points; a few scale with a measured
   value (fuzzy confidence, VirusTotal ratio, ML probability, LLM confidence).
2. **Category caps.** Points are summed per category and each sum is capped:

   | Category | Cap | Sources |
   |---|---|---|
   | `technical` | {{fact:cap_technical}} | every structural layer, the local database, `scan_failed` |
   | `reputation` | {{fact:cap_reputation}} | VirusTotal |
   | `semantic` | {{fact:cap_semantic}} | LLM, lure subject, QR code with a link |
   | `statistical` | {{fact:cap_statistical}} | ML |
   | `dynamic` | {{fact:cap_dynamic}} | emulation, sandbox |

3. **Total and safeguards.** The capped categories are added and clamped to
   {{fact:max_raw}}. If no `technical`, `reputation` or `dynamic` points exist, the total is
   clamped to {{fact:semantic_only_max}}: semantic and statistical evidence alone can never
   reach High. If the SHA-256 is allowlisted and the MD5 is not in the malware database, the
   total becomes 0 and the contributions are replaced by one zero-point `allowlisted` entry
   that says how many findings were kept for reference.
4. **Bands.** `risk_score` is the rounded total. The verdict is its band:
   {{fact:bands}}. `severity_score` is the legacy 0-10 value (`risk_score / 10`);
   `is_malicious` is true when any contribution has positive points. `registry_version` is
   recorded with every result, with `+override` when reviewed weight overrides were loaded.

The score orders evidence; it is **not a probability**. Two files at 60 can carry very
different evidence, which is why every result lists its contributions.

## Containers: the worst member, not the sum

A container (archive, message, web page, embedded container) scores **its own indicators
plus the contributions of its single highest-scoring member**, re-prefixed with the
container kind (`archive_member:`, `mail_attachment:`, `web_payload:`, `embedded_member:`) and put through
the same caps and safeguards. Members are not added together: a ZIP with ten Medium
documents is Medium, not Critical. Nested containers compound the prefixes, so the
evidence trail shows exactly which member at which depth fired.

Completeness travels separately (chapter 8): members' incomplete reasons are carried to the
container, and the container takes the most severe status.

## Worked examples

The following were computed by running the actual `ScoringMatrix` at the baseline on
hand-built signals. **The evidence is illustrative**; no file was scanned.

| Case | Contributions (points) | Category totals | Result |
|---|---|---|---|
| A. Document: auto-run macro + one `CreateObject` call; LLM says lure at 0.50 | `macro_autoexec` 22, `macro_suspicious` 10, `llm_semantic` 12 | technical 32, semantic 12 | **44, Medium** |
| B. ZIP holding document A, nothing else | `archive_member:macro_autoexec` 22, `archive_member:macro_suspicious` 10, `archive_member:llm_semantic` 12 | technical 32, semantic 12 | **44, Medium** (same evidence, prefixed) |
| C. Document: auto-run + `Shell` primitive; LLM lure at 0.80 | `macro_autoexec` 22, `macro_exec_primitive` 40, `macro_dropper_synergy` 20, `llm_semantic` 19.2 | technical 82, semantic 19.2 → 101.2, clamped | **100, Critical** |
| D. LLM only, confidence 0.95 | `llm_semantic` 22.8 | semantic 22.8 (cap 24; semantic-only clamp 49) | **23, Low** |
| E. Document C, but its SHA-256 is allowlisted | `allowlisted` 0 ("3 finding(s) kept for reference, not scored") | all 0 | **0, Clean**, `is_malicious` false |
| F. Worker timed out, nothing reported before | `scan_failed` 25 | technical 25 | **25, Medium (failed scan)** |

Case C also shows why heavy layers can be skipped: once the fast layers reach 100, the LLM
could not change the verdict, so `_run_heavy` skips the heavy group (unless
`SKIP_HEAVY_WHEN_SATURATED=false`).



## Allowlist behaviour and its exception

The allowlist is keyed by SHA-256 and is meant for known-good files that look bad (an
installer script, an administration tool). It does not stop analysis: every layer except
the heavy group still runs and is reported, so an analyst can see what was suppressed. The
one exception is deliberate: a file whose MD5 is in the operator's malware database is
scored normally even if allowlisted, so an allowlist mistake cannot hide a known-bad
sample.

## Verdicts, alerts and actions are separate decisions

- **Verdict:** the band of the score.
- **Alert:** a verdict alert is queued when the verdict reaches the channel minimum
  (`WEBHOOK_MIN_VERDICT`, `ALERT_EMAIL_MIN_VERDICT`, both {{fact:webhook_min_verdict}} by
  default). Failed-scan and incomplete-scan notices are separate alert kinds marked
  `detection: false` and go to every configured channel.
- **Quarantine:** automatic only after batch scans and only at or above `AUTO_QUARANTINE`
  (unset by default, so nothing is moved unless an operator asks for it).
- **Completeness never changes any of these.** A `partial` scan with a Low verdict is still
  Low; the label just says "(partial scan)".

## Calibration status

Weights were set by expert judgement and are versioned. `tools/calibrate_weights.py` can
propose weights from labelled results in the same format as `WEIGHTS_OVERRIDE`, but no
calibration on real labelled samples has been done (real-sample evaluation is gated to an
isolated VM and a separate authorisation). Changing weights, thresholds or inspection
coverage requires an explicit owner decision (`AGENTS.md`).

@diagram 10-scoring-vs-completeness.svg | Diagram 10 - scoring and completeness are computed independently and meet only in verdict_label. | landscape
