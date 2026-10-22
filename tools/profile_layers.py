#!/usr/bin/env python3
"""
Where does scan time go? Scans files in this process (no workers) and reports
the time spent in each pipeline layer, the slowest files and the verdicts.

    python tools/profile_layers.py ~/samples/benign            # a folder
    python tools/profile_layers.py --list files.txt --out prof.json

For detection / false-alarm rates use tools/evaluate.py; this tool is about
speed. LLM, VirusTotal and the result cache are off so only local work is timed.
"""

from __future__ import annotations

import argparse
import collections
import json
import logging
import os
import sys
import tempfile
import time
from pathlib import Path
from typing import Dict, Iterable, List

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def _files(folders: Iterable[str]) -> List[str]:
    out: List[str] = []
    for folder in folders:
        for dirpath, _dirs, names in os.walk(folder):
            out.extend(os.path.join(dirpath, n) for n in sorted(names))
    return out


def profile(paths: List[str]) -> Dict:
    os.environ["LLM_PROVIDER"] = "none"
    previous_disable = logging.root.manager.disable
    logging.disable(logging.CRITICAL)
    import RansomwareScanner as RS
    from engine import scanner as scanner_mod

    layer_time: Dict[str, float] = collections.defaultdict(float)
    original = scanner_mod.RansomwareScanner._run_layer

    def timed(self, layer, ctx):
        start = time.perf_counter()
        try:
            original(self, layer, ctx)
        finally:
            layer_time[layer.name] += time.perf_counter() - start

    scanner_mod.RansomwareScanner._run_layer = timed       # type: ignore[method-assign]
    work = Path(tempfile.mkdtemp(prefix="hrd-profile-"))
    cfg = dict(RS.CONFIG)
    cfg.update({"llm_provider": "none", "virustotal_api_key": "", "chatgpt_api_key": "",
                "cache_enabled": False, "parallel_heavy_layers": False, "auto_quarantine": "",
                "report_directory": str(work / "reports"),
                "cache_db_path": str(work / "cache.sqlite3"),
                "quarantine_dir": str(work / "vault"), "keystore_dir": str(work / "keys"),
                "canary_registry": str(work / "canaries.json")})
    scanner = RS.RansomwareScanner(cfg)
    rows = []
    started = time.perf_counter()
    try:
        for p in paths:
            t = time.perf_counter()
            try:
                r = scanner.scan_file(p)
            except Exception as e:                  # the scanner guards layers; be safe
                rows.append({"path": p, "error": f"{type(e).__name__}: {e}"})
                continue
            rows.append({"path": p, "ms": round((time.perf_counter() - t) * 1000, 1),
                         "verdict": r["verdict"], "risk": r["risk_score"]})
    finally:
        scanner_mod.RansomwareScanner._run_layer = original  # type: ignore[method-assign]
        logging.disable(previous_disable)
    return {"files": len(paths), "seconds": round(time.perf_counter() - started, 2),
            "layers": {k: round(v, 2) for k, v in sorted(layer_time.items(),
                                                         key=lambda kv: -kv[1])},
            "rows": rows}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("folders", nargs="*", help="folders to scan (recursively)")
    ap.add_argument("--list", help="text file with one path per line")
    ap.add_argument("--out", help="write the full result as JSON here")
    ap.add_argument("--top", type=int, default=10, help="slowest files to show")
    a = ap.parse_args(argv)
    paths = _files(a.folders)
    if a.list:
        paths += [p for p in Path(a.list).read_text().splitlines() if p.strip()]
    if not paths:
        ap.error("no files: give folders and/or --list")
    res = profile(paths)
    total = sum(res["layers"].values()) or 1.0
    print(f"{res['files']} files in {res['seconds']} s "
          f"({res['files'] / max(res['seconds'], 1e-9):.1f} files/s, in-process)\n")
    for name, sec in res["layers"].items():
        print(f"  {name:15s} {sec:8.2f} s  {sec / total:6.1%}")
    ok = [r for r in res["rows"] if "ms" in r]
    print("\nslowest files:")
    for r in sorted(ok, key=lambda r: -r["ms"])[:a.top]:
        print(f"  {r['ms'] / 1000:7.2f} s  {r['path']}")
    print("\nverdicts:", dict(collections.Counter(r["verdict"] for r in ok)))
    errors = [r for r in res["rows"] if "error" in r]
    if errors:
        print(f"errors: {len(errors)} (first: {errors[0]['error']})")
    if a.out:
        Path(a.out).write_text(json.dumps(res, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
