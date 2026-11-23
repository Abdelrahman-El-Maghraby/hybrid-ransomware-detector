"""Diagram 10 - two independent answers: how risky (score, verdict) and how much
was inspected (scan_status).

Read from detectors/scoring.py (ScoringMatrix._aggregate, BANDS),
detectors/indicators.yaml (caps, semantic_only_max), engine/completeness.py
(assess, PRECEDENCE, verdict_label) and core/outbox.py (channels_for,
failed_alert, incomplete_alert).
"""

from __future__ import annotations

from typing import List

from umlkit import MUTED, Diagram

TITLE = "Scoring versus completeness: two independent answers"

SC = "#eff6ff"
CO = "#f0fdf4"
JOIN = "#f5f3ff"
BAND = {"Clean": "#f1f5f9", "Low": "#dcfce7", "Medium": "#fef9c3", "High": "#fed7aa",
        "Critical": "#fecaca"}


def build(meta: dict) -> object:
    d = Diagram("d10", 1600, 750, TITLE,
                f"detectors/scoring.py, detectors/indicators.yaml (registry {meta.get('registry', '')}), "
                f"engine/completeness.py. Code at commit {meta['code_commit']}.",
                "Two parallel flows: contributions become a capped risk score and a verdict band; "
                "completeness reasons become a scan status; the two meet only in verdict_label.")
    d.title_block()

    # ---------------------------------------------------------- scoring
    d.frame(24, 92, 760, 490, "How risky?  ScoringMatrix.score(signals)", fill="#f8fafc")
    s1 = d.titled(48, 140, 712, "1  Contributions",
                  ["23 scorer functions; each fired indicator adds points in one category: "
                   "technical, reputation, semantic, statistical or dynamic. Containers add their "
                   "worst member's contributions with a prefix."], fill=SC, name="contrib")
    s2 = d.titled(48, s1.bottom + 26, 712, "2  Category caps, then the total",
                  ["technical 100, reputation 80, semantic 24, statistical 20, dynamic 100; "
                   "the capped categories are added and clamped to 100."], fill=SC, name="caps")
    s3 = d.titled(48, s2.bottom + 26, 712, "3  Safeguards",
                  ["No technical, reputation or dynamic points: at most 49 (Medium), however "
                   "confident the LLM or the ML rule engine. Allowlisted SHA-256: 0, findings kept "
                   "for reference, unless the MD5 is also in the local malware database."],
                  fill=SC, name="guards")
    s4 = d.titled(48, s3.bottom + 26, 712, "4  risk_score 0-100 and the verdict band",
                  ["severity_score = risk / 10 (legacy); is_malicious = any positive "
                   "contribution. The score is a weighted indicator total, not a probability."],
                  fill=SC, name="risk")
    for a, b in ((s1, s2), (s2, s3), (s3, s4)):
        d.edge([a.b(0.5), b.t(0.5)], "flow", ends=(a, b))
    bx, by = 48, s4.bottom + 18
    for label, rng in (("Clean", "0"), ("Low", "1-24"), ("Medium", "25-49"), ("High", "50-79"),
                       ("Critical", "80-100")):
        d.node(bx, by, 136, [label, rng], h=42, fill=BAND[label], size=12.5, bold=[True, False],
               rx=4, name=label)
        bx += 144

    # ------------------------------------------------------- completeness
    d.frame(816, 92, 760, 490, "How much was inspected?  assess(scanner, ctx)", fill="#f8fafc")
    c1 = d.titled(840, 140, 712, "1  Reasons, from every source",
                  ["layer errors and skips; an applicable layer that is unavailable; a parser "
                   "'could not analyse'; an external service error or time-out; members not "
                   "unpacked (limits, missing decompressor, encrypted); members over the scan "
                   "budget or the nesting limit; a truncated web page; members' own reasons."],
                  fill=CO, name="reasons")
    c2 = d.titled(840, c1.bottom + 26, 712, "2  The most severe status wins",
                  ["failed > locked > partial > unsupported > complete (members included). "
                   "At most 100 reasons are listed."], fill=CO, name="precedence")
    c3 = d.titled(840, c2.bottom + 26, 712, "3  Not a gap",
                  ["a heavy layer skipped at 100/100 or for an allowlisted file; a layer that does "
                   "not apply to the type; an optional layer switched off (recorded in "
                   "provenance)."], fill=CO, name="not a gap")
    c4 = d.titled(840, c3.bottom + 26, 712, "4  scan_status",
                  ["complete: every applicable, enabled layer ran. failed: the worker timed out, "
                   "crashed, hit the memory limit, sent an invalid reply, or no worker could "
                   "start. The status never changes the score, verdict or quarantine."],
                  fill=CO, name="status")
    for a, b in ((c1, c2), (c2, c3), (c3, c4)):
        d.edge([a.b(0.5), b.t(0.5)], "flow", ends=(a, b))

    # --------------------------------------------------------------- join
    j = d.titled(300, 612, 1000, "verdict_label: where the two meet",
                 ["complete: \"High\"   |   partial: \"Clean (partial scan)\"   |   failed: "
                  "\"Medium (failed scan)\" (scan_failed 25 points, or the findings kept "
                  "before the failure if they score higher)"], fill=JOIN, name="label")
    d.edge([(s4.cx, by + 42), (s4.cx, j.top)], "flow", ends=(j,), check=False)
    d.edge([c4.b(0.5), (c4.cx, j.top)], "flow", ends=(c4, j))
    d.text(800, 702, "Alerts follow the same split: a verdict alert at or above High (default); "
           "a separate scan_failed or incomplete-scan notice, kind 'detection: false'.",
           12.5, anchor="middle", fill=MUTED, maxw=1500)
    d.text(800, 724, "Clean with a complete scan means no indicator fired; it does not prove the "
           "file is safe.", 12.5, True, anchor="middle", maxw=1500)
    return d


NOTES: List[str] = [
    "Caps and the semantic-only maximum come from detectors/indicators.yaml (registry version "
    "recorded in every result's score_breakdown).",
    "A failed scan whose worker could not start (isolation_unavailable) gets no scan_failed "
    "points: the file was never opened (engine/workers.py, failure_result).",
]
