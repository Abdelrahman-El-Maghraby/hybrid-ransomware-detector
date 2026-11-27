"""
Running the pipeline over one file: the fast layers in order, the slow
("heavy") layers skipped when they cannot change the verdict and otherwise run
concurrently on copies of the context, merged back in pipeline order. A mixin
of engine.scanner.RansomwareScanner.
"""

from __future__ import annotations

import copy
import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import TYPE_CHECKING, Any, Callable, Dict, List, Optional, Tuple, cast

from .completeness import assess, verdict_label
from .config import ENGINE_VERSION
from .layers import Layer, ScanContext
from .provenance import FAILED, NOT_APPLICABLE, RAN, SKIPPED, file_provenance

if TYPE_CHECKING:  # pragma: no cover
    from .scanner import RansomwareScanner

logger = logging.getLogger("RansomwareScanner")


class StagedPipelineMixin:
    config: Dict
    pipeline: List[Layer]
    scoring: Any
    _heavy_pool: Optional[ThreadPoolExecutor]
    provisional_listener: Optional[Callable[[Dict, bool], None]]   # set in a worker (M26)

    completed_listener: Optional[Callable[[Dict], None]]
    clear_provisional_listener: Optional[Callable[[], None]]

    # ------------------------------------------------------------- scanning
    def scan_file(self, file_path: str, _depth: int = 0,
                  _display_name: Optional[str] = None) -> Dict:
        """Scan a single file through every layer of the pipeline and score it.

        `_depth` / `_display_name` are used internally when scanning the
        members of a container (e.g. "invoice.zip!/payload.docm").
        """
        display = _display_name or file_path
        if _depth == 0 and hasattr(self, "refresh_detection_content"):
            self.refresh_detection_content()       # a rule update never serves old verdicts
        started = time.perf_counter()
        logger.info("Scanning file: %s", display, extra={"event": "scan_started", "path": display})
        ctx = ScanContext.start(cast("RansomwareScanner", self), file_path, _depth, display, ENGINE_VERSION)
        heavy: List[Layer] = []
        for layer in self.pipeline:
            if getattr(layer, "heavy", False):
                heavy.append(layer)
                continue
            self._run_heavy(heavy, ctx)          # a fast layer after slow ones keeps its order
            heavy = []
            self._clear_provisional(ctx)
            self._run_layer(layer, ctx)
        self._run_heavy(heavy, ctx)

        result = self._assemble(ctx)
        completed = getattr(self, "completed_listener", None)
        if self._in_worker(ctx) and completed is not None:
            completed(result)  # evidence only; delivery remains in the parent
        own = [s for s in result["provenance"]["shared"] if "member_path" not in s]
        if own:
            logger.info("Sent outside for %s: %s", display,
                        "; ".join(f"{s['service']} ({', '.join(s['sent'])}"
                                  + (f", {s['destination']}" if s.get("destination") else "") + ")"
                                  for s in own),
                        extra={"event": "external_share", "path": display, "shared": own})
        result["scan_duration_ms"] = int((time.perf_counter() - started) * 1000)

        logger.info(
            "Scan completed for %s. Verdict: %s (risk %d/100, severity %.1f/10).",
            display, result["verdict"], result["risk_score"], result["severity_score"],
            extra={"event": "scan_completed", "path": display,
                   "sha256": result.get("sha256_hash", ""), "verdict": result["verdict"],
                   "risk_score": result["risk_score"], "scan_status": result["scan_status"],
                   "duration_ms": result["scan_duration_ms"]})
        return result

    def _assemble(self, ctx: ScanContext) -> Dict:
        """Score the file and write the verdict, completeness and provenance into
        ctx.result. No logging and no other side effect: the M26 provisional
        result is built with it too."""
        score = self.scoring.score(ctx.signals)     # every signal through the scoring matrix
        result = ctx.result
        result["is_malicious"] = score.is_malicious
        result["severity_score"] = score.severity_score   # legacy 0-10 (DB hit => 10.0)
        result["risk_score"] = score.risk_score            # 0-100
        result["verdict"] = score.verdict                  # Clean|Low|Medium|High|Critical
        result["score_breakdown"] = score.as_dict()        # full evidence trail
        # How far the evidence goes; independent of the score and verdict above.
        result["scan_status"], result["incomplete_reasons"] = assess(
            cast("RansomwareScanner", self), ctx)
        result["verdict_label"] = verdict_label(result)
        result["provenance"] = file_provenance(cast("RansomwareScanner", self), ctx)
        return result

    def assembled_copy(self, ctx: ScanContext, entries: Dict[str, Tuple[str, Dict[str, Any]]]
                       ) -> Dict:
        """The result the file would get with `entries` ({layer: (result key,
        result)}) added, assembled on a copy (ctx is not changed)."""
        sub = copy.copy(ctx)
        sub.result = {**ctx.result, "scan_results": {**ctx.scan_results,
                                                     **{k: e for k, e in entries.values()}}}
        sub.signals = ctx.signals.copy()
        sub.layer_log = list(ctx.layer_log) + [(layer, RAN) for layer in entries]
        sub.member_reasons = list(ctx.member_reasons)
        sub.member_shared = list(ctx.member_shared)
        return self._assemble(sub)

    def provisional_result(self, ctx: ScanContext,
                           stopped: Dict[str, Tuple[str, Dict[str, Any]]]) -> Dict:
        """M26, I-6: the result the file gets if the worker must be stopped while
        the `stopped` layers (sandbox, VirusTotal, LLM) wait on their service:
        those layers at `timeout`, named in `scan_results.stopped_layers`. The
        worker sends it before that wait; the parent uses it only if it stops
        the worker at the scan limit."""
        result = self.assembled_copy(ctx, stopped)
        result["scan_results"]["stopped_layers"] = sorted(stopped)
        return result

    def _in_worker(self, ctx: ScanContext) -> bool:
        return (ctx.depth == 0 and getattr(self, "provisional_listener", None) is not None
                and cast("RansomwareScanner", self).time_left() is not None)

    def _send_stage_provisional(self, layers: List[Layer], ctx: ScanContext) -> None:
        """I-6: before the slow layers that may wait on an outside service
        (VirusTotal, the LLM) run in a worker, send the parent the result it
        keeps if the worker is stopped during their wait."""
        stopped = {}
        for layer in layers:
            entry = layer.stopped_entry(cast("RansomwareScanner", self), ctx)
            if entry is not None:
                stopped[layer.name] = entry
        if stopped:
            listen = self.provisional_listener
            if listen is not None:
                listen(self.provisional_result(ctx, stopped), False)

    def _sandbox_last(self, ctx: ScanContext) -> bool:
        """M26: in an isolated worker with a sandbox, the sandbox runs after the
        other slow layers, so the provisional result it sends first holds their
        findings. Elsewhere the slow layers run together as before."""
        return self._in_worker(ctx) and getattr(self, "sandbox", None) is not None

    def _run_layer(self, layer: Layer, ctx: ScanContext) -> None:
        """Run one layer; a parser that raises on a hostile file costs that layer's
        evidence, not the whole file's verdict. The error is kept in the result."""
        keys = set(ctx.scan_results)
        try:
            layer.run(cast("RansomwareScanner", self), ctx)
            # a layer that does not apply to this file type returns without evidence
            ctx.layer_log.append((layer.name, RAN if set(ctx.scan_results) - keys
                                  else NOT_APPLICABLE))
        except MemoryError:
            raise  # the worker must report a memory failure, never a timeout fallback
        except Exception as e:
            ctx.layer_log.append((layer.name, FAILED))
            logger.warning("Layer %s failed on %s: %s: %s", layer.name, ctx.display,
                           type(e).__name__, e,
                           extra={"event": "layer_error", "layer": layer.name,
                                  "path": ctx.display, "error": type(e).__name__})
            ctx.scan_results.setdefault("layer_errors", {})[layer.name] = (
                f"{type(e).__name__}: {str(e)[:200]}")

    def _run_heavy(self, layers: List[Layer], ctx: ScanContext) -> None:
        """Run a group of slow layers: skipped at a saturated score, else concurrently."""
        if not layers:
            return
        if ctx.signals.allowlisted and not ctx.signals.local_db_hit:
            ctx.layer_log.extend((layer.name, SKIPPED) for layer in layers)
            ctx.scan_results["skipped_layers"] = {
                "layers": [layer.name for layer in layers],
                "reason": "File is on the allowlist; these layers cannot change the verdict.",
            }
            return
        if (self.config.get("skip_heavy_when_saturated", True)
                and self.scoring.score(ctx.signals).risk_score >= 100):
            ctx.layer_log.extend((layer.name, SKIPPED) for layer in layers)
            ctx.scan_results["skipped_layers"] = {
                "layers": [layer.name for layer in layers],
                "reason": "Earlier layers already scored 100/100; these layers cannot "
                          "change the verdict.",
            }
            return
        last = [layer for layer in layers if layer.name == "sandbox"] \
            if self._sandbox_last(ctx) else []
        if last:                                 # M26: the others first, then the sandbox
            self._run_together([layer for layer in layers if layer not in last], ctx)
            for layer in last:
                self._run_layer(layer, ctx)
            return
        self._run_together(layers, ctx)

    def _run_together(self, layers: List[Layer], ctx: ScanContext) -> None:
        if not layers:
            return
        if len(layers) == 1 or not self.config.get("parallel_heavy_layers", True):
            for layer in layers:
                self._clear_provisional(ctx)
                self._publish_pending([layer], ctx)
                self._run_layer(layer, ctx)
            self._clear_provisional(ctx)    # a finished layer must not stay "at timeout"
            return

        def run_on_copy(layer: Layer) -> ScanContext:
            sub = copy.copy(ctx)
            sub.result = {**ctx.result, "scan_results": {}}
            sub.signals = ctx.signals.copy()
            # No mutable bookkeeping is shared with other layer threads.
            sub.layer_log = []
            sub.member_reasons = list(ctx.member_reasons)
            sub.member_shared = list(ctx.member_shared)
            self._run_layer(layer, sub)
            return sub

        if self._heavy_pool is None:
            self._heavy_pool = ThreadPoolExecutor(max_workers=4,
                                                  thread_name_prefix="heavy-layer")
        before_signals, before_result = ctx.signals.copy(), dict(ctx.result)
        self._publish_pending(layers, ctx)
        futures = {self._heavy_pool.submit(run_on_copy, layer): i
                   for i, layer in enumerate(layers)}
        finished: Dict[int, ScanContext] = {}
        for fut in as_completed(futures):
            finished[futures[fut]] = fut.result()
            # Only the coordinator assembles snapshots. Completed contexts are
            # immutable here; merging in pipeline order makes conflicting fields
            # deterministic even when completion order differs.
            snapshot = copy.copy(ctx)
            snapshot.result = copy.deepcopy(ctx.result)
            snapshot.signals = ctx.signals.copy()
            snapshot.layer_log = list(ctx.layer_log)
            for index in sorted(finished):
                self._merge_layer(snapshot, finished[index], before_signals, before_result)
            pending = [layer for i, layer in enumerate(layers) if i not in finished]
            self._publish_pending(pending, snapshot)
        for index in sorted(finished):
            self._merge_layer(ctx, finished[index], before_signals, before_result)
        self._clear_provisional(ctx)        # every layer finished: no snapshot stops one

    def _clear_provisional(self, ctx: ScanContext) -> None:
        clear = getattr(self, "clear_provisional_listener", None)
        if self._in_worker(ctx) and clear is not None:
            clear()

    def _publish_pending(self, pending: List[Layer], ctx: ScanContext) -> None:
        if not pending or not self._in_worker(ctx):
            return
        # A stalled parser/ML/emulator is a failure, not an external timeout.
        if any(layer.stopped_entry(cast("RansomwareScanner", self), ctx) is None
               for layer in pending):
            return
        self._send_stage_provisional(pending, ctx)

    @staticmethod
    def _merge_layer(ctx: ScanContext, sub: ScanContext, before_signals: Any,
                     before_result: Dict) -> None:
        ctx.scan_results.update({k: v for k, v in sub.scan_results.items() if k != "layer_errors"})
        if sub.scan_results.get("layer_errors"):
            ctx.scan_results.setdefault("layer_errors", {}).update(sub.scan_results["layer_errors"])
        ctx.layer_log.extend(sub.layer_log)
        for key, value in sub.signals.changed_since(before_signals).items():
            ctx.signals.set(key, value)
        for key, value in sub.result.items():
            if key != "scan_results" and value is not before_result.get(key):
                ctx.result[key] = value
