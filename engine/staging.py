"""
Running the pipeline over one file: the fast layers in order, the slow
("heavy") layers skipped when they cannot change the verdict and otherwise run
concurrently on copies of the context, merged back in pipeline order. A mixin
of engine.scanner.RansomwareScanner.
"""

from __future__ import annotations

import copy
import logging
from concurrent.futures import ThreadPoolExecutor
from typing import TYPE_CHECKING, Any, Dict, List, Optional, cast

from .config import ENGINE_VERSION
from .layers import Layer, ScanContext

if TYPE_CHECKING:  # pragma: no cover
    from .scanner import RansomwareScanner

logger = logging.getLogger("RansomwareScanner")


class StagedPipelineMixin:
    config: Dict
    pipeline: List[Layer]
    scoring: Any
    _heavy_pool: Optional[ThreadPoolExecutor]

    # ------------------------------------------------------------- scanning
    def scan_file(self, file_path: str, _depth: int = 0,
                  _display_name: Optional[str] = None) -> Dict:
        """Scan a single file through every layer of the pipeline and score it.

        `_depth` / `_display_name` are used internally when scanning the
        members of a container (e.g. "invoice.zip!/payload.docm").
        """
        display = _display_name or file_path
        logger.info(f"Scanning file: {display}")
        ctx = ScanContext.start(cast("RansomwareScanner", self), file_path, _depth, display, ENGINE_VERSION)
        heavy: List[Layer] = []
        for layer in self.pipeline:
            if getattr(layer, "heavy", False):
                heavy.append(layer)
                continue
            self._run_heavy(heavy, ctx)          # a fast layer after slow ones keeps its order
            heavy = []
            self._run_layer(layer, ctx)
        self._run_heavy(heavy, ctx)

        # Fuse every signal through the weighted scoring matrix
        score = self.scoring.score(ctx.signals)
        result = ctx.result
        result["is_malicious"] = score.is_malicious
        result["severity_score"] = score.severity_score   # legacy 0-10 (DB hit => 10.0)
        result["risk_score"] = score.risk_score            # 0-100
        result["verdict"] = score.verdict                  # Clean|Low|Medium|High|Critical
        result["score_breakdown"] = score.as_dict()        # full evidence trail

        logger.info(
            "Scan completed for %s. Verdict: %s (risk %d/100, severity %.1f/10).",
            display, result["verdict"], result["risk_score"], result["severity_score"],
        )
        return result

    def _run_layer(self, layer: Layer, ctx: ScanContext) -> None:
        """Run one layer; a parser that raises on a hostile file costs that layer's
        evidence, not the whole file's verdict. The error is kept in the result."""
        try:
            layer.run(cast("RansomwareScanner", self), ctx)
        except Exception as e:
            logger.warning("Layer %s failed on %s: %s: %s", layer.name, ctx.display,
                           type(e).__name__, e)
            ctx.scan_results.setdefault("layer_errors", {})[layer.name] = (
                f"{type(e).__name__}: {str(e)[:200]}")

    def _run_heavy(self, layers: List[Layer], ctx: ScanContext) -> None:
        """Run a group of slow layers: skipped at a saturated score, else concurrently."""
        if not layers:
            return
        if ctx.signals.allowlisted and not ctx.signals.local_db_hit:
            ctx.scan_results["skipped_layers"] = {
                "layers": [layer.name for layer in layers],
                "reason": "File is on the allowlist; these layers cannot change the verdict.",
            }
            return
        if (self.config.get("skip_heavy_when_saturated", True)
                and self.scoring.score(ctx.signals).risk_score >= 100):
            ctx.scan_results["skipped_layers"] = {
                "layers": [layer.name for layer in layers],
                "reason": "Earlier layers already scored 100/100; these layers cannot "
                          "change the verdict.",
            }
            return
        if len(layers) == 1 or not self.config.get("parallel_heavy_layers", True):
            for layer in layers:
                self._run_layer(layer, ctx)
            return

        def run_on_copy(layer: Layer) -> ScanContext:
            sub = copy.copy(ctx)
            sub.result = {**ctx.result, "scan_results": {}}
            sub.signals = ctx.signals.copy()
            self._run_layer(layer, sub)
            return sub

        if self._heavy_pool is None:
            self._heavy_pool = ThreadPoolExecutor(max_workers=4,
                                                  thread_name_prefix="heavy-layer")
        before_signals, before_result = ctx.signals.copy(), dict(ctx.result)
        futures = [self._heavy_pool.submit(run_on_copy, layer) for layer in layers]
        for fut in futures:                      # merge in pipeline order: same report order
            sub = fut.result()
            ctx.scan_results.update(sub.scan_results)
            for key, value in sub.signals.changed_since(before_signals).items():
                ctx.signals.set(key, value)              # only what this layer changed
            for key, value in sub.result.items():
                if key != "scan_results" and value is not before_result.get(key):
                    ctx.result[key] = value

