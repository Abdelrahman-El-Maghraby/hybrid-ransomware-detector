#!/usr/bin/env python3
"""
Measure the engine on labelled folders: detection rate, false-positive rate,
and every miss / false alarm with the reasons behind it.

    python tools/evaluate.py --malicious ~/samples/malicious \
                             --benign ~/samples/benign \
                             --labels ~/samples/labels.csv --out eval_out

What is measured
----------------
The ENGINE ONLY. Reputation look-ups would make known samples trivially
"detected" and say nothing about the detection logic, so by default:
  * VirusTotal is off (no API key is passed to the scanner),
  * the LLM layer is off (LLM_PROVIDER=none),
  * the result cache is off.
Pass --with-vt / --with-llm to measure the full product instead.

Every file is scanned in a worker process with a time limit, so one hostile
or pathological file cannot stop the run. Files whose extension the engine
does not support are counted separately and left out of the rates.

Before scanning, files are identified by SHA-256: a file present twice counts
once, and one labelled both malicious and benign is left out (both reported).
--split test evaluates only the test part of a fixed, family-grouped split
(tools/splits.py), the part tools/calibrate_weights.py --split calibration
never fits on - so proposed weights are measured on families they never saw.

Outputs (in --out):
  results.csv   one row per file: label, type, family, split, verdict, risk,
                scan_status, reasons
  summary.md    rates at three alert thresholds (and a worst case that counts
                errors and timeouts as misses), per file type, per family, scan
                completeness, timing, and the full list of misses and false alarms

Rates are reported at fixed verdict thresholds rather than as one "accuracy"
number: with few malicious files in real traffic, accuracy hides false alarms.
"""

from __future__ import annotations

import argparse
import csv
import multiprocessing as mp
import os
import statistics
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from tools.splits import SPLITS, dedupe, load_families, select, sha256_file  # noqa: E402

RANK = {"Clean": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}
THRESHOLDS = ("Low", "Medium", "High")
SKIP_DIRS = {"zips", "__MACOSX"}

_scanner = None


def _init_worker(with_vt: bool, with_llm: bool) -> None:
    """Build one scanner per worker process (the rule/model load is the slow part)."""
    global _scanner
    os.environ["CACHE_ENABLED"] = "0"
    if not with_llm:
        os.environ["LLM_PROVIDER"] = "none"
    if not with_vt:
        os.environ["VIRUSTOTAL_API_KEY"] = ""
    sys.path.insert(0, str(ROOT))
    import logging
    logging.disable(logging.CRITICAL)
    # The engine package directly: the CLI module also pulls in scheduler / GUI deps.
    from engine.config import CONFIG
    from engine.scanner import RansomwareScanner
    cfg = dict(CONFIG)
    cfg["cache_enabled"] = False
    if not with_vt:
        cfg["virustotal_api_key"] = ""
    if not with_llm:
        cfg["llm_provider"] = "none"
    _scanner = RansomwareScanner(cfg)


def _ping() -> bool:
    return _scanner is not None


def _scan(path: str) -> dict:
    t0 = time.time()
    try:
        r = _scanner.scan_file(path)
    except Exception as exc:                     # the engine should not raise; record it if it does
        return {"error": f"{type(exc).__name__}: {exc}", "seconds": time.time() - t0}
    contribs = (r.get("score_breakdown") or {}).get("contributions") or []
    contribs = sorted(contribs, key=lambda c: -float(c.get("points", 0)))
    return {
        "verdict": r.get("verdict", "Clean"),
        "risk": int(r.get("risk_score", 0)),
        "scan_status": r.get("scan_status", "complete"),
        "sha256": r.get("sha256_hash", ""),
        "reasons": " | ".join(f"{c.get('indicator')}({float(c.get('points', 0)):.0f})"
                              for c in contribs[:4]),
        "seconds": time.time() - t0,
    }


def collect(roots, label, supported):
    out = []
    for root in roots:
        root = Path(root).expanduser()
        for p in sorted(root.rglob("*")):
            if not p.is_file() or SKIP_DIRS & set(p.parts):
                continue
            rel = p.relative_to(root)
            group = rel.parts[0] if len(rel.parts) > 1 else root.name
            ext = p.suffix.lower()
            out.append({"path": str(p), "label": label, "group": group,
                        "ext": ext or "(none)", "supported": ext in supported})
    return out


def prepare(files, families, split):
    """Hash every file, count duplicates once, drop files labelled both ways, and
    keep one split. Returns (files, {"duplicates", "conflicts", "split"})."""
    for f in files:
        try:
            f["sha256"] = sha256_file(f["path"])
        except OSError:
            f["sha256"] = ""
    files, duplicates, conflicts = dedupe(files)
    files = select(files, split, families)
    return files, {"duplicates": duplicates, "conflicts": conflicts, "split": split}


def load_labels(path):
    return load_families(path)


def run(files, jobs, timeout, with_vt, with_llm):
    """Scan with a pool; a file that exceeds the time limit is recorded and the pool rebuilt."""
    ctx = mp.get_context("spawn")
    results, i, n = [], 0, len(files)
    while i < n:
        pool = ctx.Pool(jobs, initializer=_init_worker, initargs=(with_vt, with_llm))
        # Wait for the workers to load the engine so start-up time is not
        # charged to the first files' time limit.
        for p in [pool.apply_async(_ping) for _ in range(jobs)]:
            p.get(timeout=600)
        pending = [(k, pool.apply_async(_scan, (files[k]["path"],)))
                   for k in range(i, n)]
        broken = False
        for k, job in pending:
            try:
                res = job.get(timeout=timeout)
            except mp.TimeoutError:
                res = {"error": f"timeout after {timeout}s", "seconds": timeout}
                broken = True
            except Exception as exc:
                res = {"error": f"worker crashed: {exc}", "seconds": 0}
                broken = True
            results.append({**files[k], **res})
            done = len(results)
            if done % 25 == 0 or done == n:
                print(f"  {done}/{n} scanned", flush=True)
            if broken:
                i = k + 1
                break
        else:
            i = n
        pool.terminate()
        pool.join()
    return results


def rate(rows, label, thr):
    sel = [r for r in rows if r["label"] == label and "error" not in r]
    if not sel:
        return 0.0, 0, 0
    hit = sum(1 for r in sel if RANK.get(r["verdict"], 0) >= RANK[thr])
    return 100.0 * hit / len(sel), hit, len(sel)


def summarise(rows, unsupported, out: Path, args) -> str:
    L = []
    mal = [r for r in rows if r["label"] == "malicious"]
    ben = [r for r in rows if r["label"] == "benign"]
    errors = [r for r in rows if "error" in r]
    L.append("# Evaluation summary\n")
    L.append(f"- Malicious files scanned: **{len(mal)}**   Benign files scanned: **{len(ben)}**")
    L.append(f"- Unsupported extensions skipped: {len(unsupported)}"
             + (f" ({', '.join(f'{e} {c}' for e, c in Counter(u['ext'] for u in unsupported).most_common(8))})"
                if unsupported else ""))
    L.append(f"- Errors / timeouts: {len(errors)}")
    prep = getattr(args, "prep", {}) or {}
    if prep:
        L.append(f"- Duplicates (same SHA-256) counted once: {prep.get('duplicates', 0)}; "
                 f"labelled both malicious and benign, left out: {len(prep.get('conflicts', []))}")
        L.append(f"- Split: **{prep.get('split', 'all')}** (family-grouped, tools/splits.py)")
    L.append(f"- Reputation layers: VirusTotal {'ON' if args.with_vt else 'off'}, "
             f"LLM {'ON' if args.with_llm else 'off'} (engine-only unless ON)\n")

    L.append("## Rates by alert threshold\n")
    L.append("| Alert when verdict ≥ | Detection rate (malicious) | False-positive rate (benign) |")
    L.append("|---|---|---|")
    for thr in THRESHOLDS:
        d, dh, dn = rate(rows, "malicious", thr)
        f, fh, fn = rate(rows, "benign", thr)
        L.append(f"| {thr} | {d:.1f}% ({dh}/{dn}) | {f:.2f}% ({fh}/{fn}) |")
    mal_err = sum(1 for r in mal if "error" in r)
    if mal_err:
        d, dh, dn = rate(rows, "malicious", args.alert)
        L.append(f"\nWorst case at {args.alert}: {100.0 * dh / (dn + mal_err):.1f}% "
                 f"({dh}/{dn + mal_err}) when the {mal_err} malicious file(s) that errored or "
                 "timed out count as misses.")

    L.append("\n## Scan completeness\n")
    L.append("| scan_status | Malicious | Benign |")
    L.append("|---|---|---|")
    for st in ("complete", "partial", "locked", "unsupported", "failed"):
        L.append(f"| {st} | {sum(1 for r in mal if r.get('scan_status') == st)} "
                 f"| {sum(1 for r in ben if r.get('scan_status') == st)} |")

    L.append("\n## Verdict distribution\n")
    L.append("| Verdict | Malicious | Benign |")
    L.append("|---|---|---|")
    for v in RANK:
        L.append(f"| {v} | {sum(1 for r in mal if r.get('verdict') == v)} "
                 f"| {sum(1 for r in ben if r.get('verdict') == v)} |")

    def breakdown(title, key, label):
        groups = defaultdict(list)
        for r in rows:
            if r["label"] == label and "error" not in r:
                groups[r[key]].append(r)
        if not groups:
            return
        L.append(f"\n## {title}\n")
        L.append("| Group | Files | ≥ Low | ≥ Medium | ≥ High |")
        L.append("|---|---|---|---|---|")
        for g, rs in sorted(groups.items(), key=lambda kv: -len(kv[1])):
            cells = [f"{100.0 * sum(1 for r in rs if RANK[r['verdict']] >= RANK[t]) / len(rs):.0f}%"
                     for t in THRESHOLDS]
            L.append(f"| {g} | {len(rs)} | " + " | ".join(cells) + " |")

    breakdown("Malicious — by file type", "ext", "malicious")
    breakdown("Malicious — by family (labels.csv)", "family", "malicious")
    breakdown("Malicious — by folder", "group", "malicious")
    breakdown("Benign — by file type (alert rate = false positives)", "ext", "benign")
    breakdown("Benign — by folder", "group", "benign")

    secs = [r["seconds"] for r in rows if "seconds" in r]
    if secs:
        L.append("\n## Speed\n")
        L.append(f"- Median {statistics.median(secs):.2f}s per file, "
                 f"95th percentile {sorted(secs)[int(0.95 * (len(secs) - 1))]:.2f}s, "
                 f"slowest {max(secs):.1f}s")

    thr = args.alert
    misses = [r for r in mal if "error" not in r and RANK[r["verdict"]] < RANK[thr]]
    fps = [r for r in ben if "error" not in r and RANK[r["verdict"]] >= RANK[thr]]
    L.append(f"\n## Misses — malicious below {thr} ({len(misses)})\n")
    for r in sorted(misses, key=lambda r: (r["ext"], r["risk"]))[:300]:
        L.append(f"- `{Path(r['path']).name}` [{r['ext']}, {r.get('family') or '?'}] "
                 f"{r['verdict']} {r['risk']}/100 ({r.get('scan_status', 'complete')} scan) — "
                 f"{r['reasons'] or 'no signal'}")
    L.append(f"\n## False alarms — benign at or above {thr} ({len(fps)})\n")
    for r in sorted(fps, key=lambda r: -r["risk"])[:300]:
        L.append(f"- `{Path(r['path']).name}` [{r['ext']}, {r['group']}] "
                 f"{r['verdict']} {r['risk']}/100 — {r['reasons']}")
    if errors:
        L.append(f"\n## Errors ({len(errors)})\n")
        for r in errors[:100]:
            L.append(f"- `{Path(r['path']).name}` [{r['label']}] {r['error']}")
    text = "\n".join(L) + "\n"
    (out / "summary.md").write_text(text, encoding="utf-8")
    return text


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Detection rate / false-positive rate on labelled folders.")
    ap.add_argument("--malicious", nargs="+", default=[], help="folder(s) of malicious samples")
    ap.add_argument("--benign", nargs="+", default=[], help="folder(s) of benign files")
    ap.add_argument("--labels", help="CSV with sha256,type,family,... (MalwareBazaar labels)")
    ap.add_argument("--out", default="eval_out", help="output folder (default: eval_out)")
    ap.add_argument("--alert", choices=THRESHOLDS, default="Medium",
                    help="threshold used for the miss / false-alarm lists (default Medium)")
    ap.add_argument("--jobs", type=int, default=max(1, (os.cpu_count() or 2) - 1))
    ap.add_argument("--timeout", type=int, default=180, help="seconds per file (default 180)")
    ap.add_argument("--limit", type=int, default=0, help="scan at most N files per label (0 = all)")
    ap.add_argument("--with-vt", action="store_true", help="include VirusTotal (needs VIRUSTOTAL_API_KEY)")
    ap.add_argument("--with-llm", action="store_true", help="include the LLM layer")
    ap.add_argument("--split", choices=SPLITS, default="all",
                    help="'test': only the family-grouped test part (never used by "
                         "calibrate_weights.py --split calibration); default all")
    args = ap.parse_args(argv)
    if not args.malicious and not args.benign:
        ap.error("give --malicious and/or --benign")

    sys.path.insert(0, str(ROOT))
    from engine.config import SUPPORTED_EXTENSIONS
    supported = set(SUPPORTED_EXTENSIONS)

    files = collect(args.malicious, "malicious", supported) + collect(args.benign, "benign", supported)
    unsupported = [f for f in files if not f["supported"]]
    files = [f for f in files if f["supported"]]
    families = load_labels(args.labels)
    files, args.prep = prepare(files, families, args.split)
    if args.limit:
        keep, seen = [], Counter()
        for f in files:
            if seen[f["label"]] < args.limit:
                keep.append(f)
                seen[f["label"]] += 1
        files = keep
    if not files:
        print("No supported files found.")
        return 1

    # Build the scanner once here first: a failing worker initializer would make
    # the pool respawn workers forever instead of reporting the problem.
    try:
        _init_worker(args.with_vt, args.with_llm)
    except Exception as exc:
        print(f"Cannot start the engine: {type(exc).__name__}: {exc}\n"
              f"Install the requirements first:  pip install -r requirements.txt")
        return 2

    out = Path(args.out).expanduser()
    out.mkdir(parents=True, exist_ok=True)
    print(f"Scanning {len(files)} files with {args.jobs} worker(s) "
          f"({len(unsupported)} unsupported skipped)...")
    t0 = time.time()
    rows = run(files, args.jobs, args.timeout, args.with_vt, args.with_llm)

    for r in rows:
        r["family"] = families.get((r.get("sha256") or "").lower(), "") if r["label"] == "malicious" else ""
        r.setdefault("verdict", "Clean")
        r.setdefault("risk", 0)
        r.setdefault("reasons", "")
        r["family_group"] = r["family"] or "unlabelled"
    for r in rows:
        r["family"] = r["family_group"]

    with open(out / "results.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["label", "folder", "ext", "family", "split", "verdict", "risk",
                    "scan_status", "seconds", "sha256", "reasons", "error", "path"])
        for r in rows:
            w.writerow([r["label"], r["group"], r["ext"], r["family"], r.get("split", ""),
                        r["verdict"], r["risk"], r.get("scan_status", ""),
                        f"{r.get('seconds', 0):.2f}", r.get("sha256", ""), r["reasons"],
                        r.get("error", ""), r["path"]])
    text = summarise(rows, unsupported, out, args)
    print("\n" + text.split("## Verdict distribution")[0])
    print(f"Done in {time.time() - t0:.0f}s. Full report: {out / 'summary.md'}  Rows: {out / 'results.csv'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
