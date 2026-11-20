"""Outside opinions: the LLM backend and VirusTotal (both cached by SHA-256)."""

import logging
import os
import time
from typing import TYPE_CHECKING, Any, Dict, List, Optional

from .text import extract_suspicious_strings

logger = logging.getLogger("RansomwareScanner")

VT_POLL_SECONDS = 15.0          # between status checks of an uploaded file
MIN_CALL_SECONDS = 1.0          # I-6: in a worker, no call starts with less time left
VT_POLLS = 10
_VT_CUT = object()              # the upload wait ended at the scan time limit


class ExternalLookupsMixin:
    """LLM semantic analysis and VirusTotal reputation lookups."""

    # provided by RansomwareScanner
    config: Dict[str, Any]
    cache: Any
    llm_backend: Any
    vt_limiter: Any
    http: Any
    http_timeout: float
    intel: Any = None               # core.intel_client.IntelClient (Docker), or in-process

    if TYPE_CHECKING:
        def calculate_hashes(self, file_path: str) -> Dict[str, str]: ...
        def _extract_text_from_file(self, file_path: str, allow_ocr: bool = True,
                                    errors: Optional[List[str]] = None,
                                    omitted: Optional[List[str]] = None) -> str: ...

    def _llm_cache_layer(self) -> str:
        """Cache key part of an LLM answer: everything that changes it - the back-end,
        the model, the prompt (PROMPT_VERSION) and the engine that extracted the text."""
        from detectors.llm_backends import PROMPT_VERSION

        from .config import ENGINE_VERSION
        backend = self.llm_backend
        return (f"llm:{getattr(backend, 'name', 'none')}:{getattr(backend, 'model', '')}"
                f":prompt-{PROMPT_VERSION}:engine-{ENGINE_VERSION}")

    def _vt_cache_layer(self) -> str:
        """With uploads switched on, an earlier "unknown, not uploaded" answer must
        not be served: the two settings keep separate entries."""
        return "virustotal:upload" if self._vt_upload_on() else "virustotal"

    def _vt_upload_on(self) -> bool:
        if self.intel is not None:
            return bool(self.intel.service("virustotal").get("upload"))
        return bool(self.config.get("virustotal_upload_unknown"))

    def analyze_with_llm(self, file_path: str, file_content: Optional[str] = None,
                         embedded_strings: Optional[str] = None,
                         sha256: Optional[str] = None) -> Dict:
        """Send document content + embedded strings to the configured LLM backend.

        The backend is chosen once at init (local Ollama by default for OPSEC,
        cloud OpenAI optional). Prompt-injection hardening lives in the backend:
        analyst instructions in the system role, untrusted file content in the
        user role wrapped in per-request nonce delimiters, temperature 0,
        JSON-only output. Answers are cached by SHA-256 when one is given.
        """
        try:
            if not getattr(self.llm_backend, "available", True):
                return self.llm_backend.analyze("")       # uniform "skipped" result

            cache_layer = self._llm_cache_layer()
            if sha256 and self.cache is not None:
                cached = self.cache.get(sha256, cache_layer)
                if cached is not None:
                    cached["cached"] = True
                    return cached

            # Extract visible content (and strings: code/keywords/shell hints)
            if file_content is None:
                file_content = self._extract_text_from_file(file_path)
            if embedded_strings is None:
                embedded_strings = extract_suspicious_strings(file_path)

            # Skip empty results before spending an LLM call
            if not file_content.strip() and not embedded_strings.strip():
                logger.warning("No content or strings extracted from %s. Skipping LLM analysis.", file_path)
                return {
                    "is_malicious": False,
                    "confidence": 0,
                    "details": "No content or strings to analyze.",
                    "suspicious_elements": []
                }

            # Combine both (truncated to keep the prompt bounded)
            combined = (
                "Visible Document Content:\n"
                f"{file_content[:3000]}\n\n"
                "Extracted Embedded Strings:\n"
                f"{embedded_strings[:2000]}"
            )

            end = self._vt_end()                     # I-6: None outside a worker
            if end is None:
                result = self.llm_backend.analyze(combined)
            elif self._no_time_for_a_call(end):
                return {"is_malicious": False, "confidence": 0, "suspicious_elements": [],
                        "status": "timeout",
                        "details": "LLM not asked: no time left in the scan limit.",
                        "detail": "not asked: no time left in the scan limit"}
            else:
                self._note_external("llm", ["text"],
                                    "local" if self.llm_backend.is_local else "cloud")
                result = self.llm_backend.analyze(combined,
                                                  timeout=self._call_timeout(180, end))
            if sha256 and self.cache is not None and result.get("analyzed"):
                self.cache.put(sha256, cache_layer, result)
            if not result.get("cached"):             # intel may have answered from its cache
                result = dict(result, sent=["text"],
                              destination="local" if self.llm_backend.is_local else "cloud")
            return result
        except Exception as e:
            logger.error("Error in LLM analysis for %s: %s", file_path, str(e))
            return {
                "is_malicious": False,
                "confidence": 0,
                "details": "LLM analysis failed.",
                "error": type(e).__name__,
                "suspicious_elements": []
            }

    # Backward-compatible alias: older callers / docs reference analyze_with_chatgpt.
    def analyze_with_chatgpt(self, file_path: str) -> Dict:
        return self.analyze_with_llm(file_path)

    def _vt_end(self) -> Optional[float]:
        """I-6: in an isolated worker, when the VirusTotal and LLM waits must end:
        the scan's limit less the M26 margin (10 %, at least 1 s). None outside a
        worker, where nothing changes."""
        time_left = getattr(self, "time_left", None)
        left = time_left() if callable(time_left) else None
        if left is None:
            return None
        limit = float(self.config.get("scan_timeout_seconds", 300) or 300)
        return time.monotonic() + left - max(1.0, 0.1 * limit)

    def _vt_no_time(self, end: Optional[float]) -> bool:
        return end is not None and end - time.monotonic() < VT_POLL_SECONDS

    def _no_time_for_a_call(self, end: Optional[float], wait: float = 0.0) -> bool:
        return end is not None and end - time.monotonic() - wait < MIN_CALL_SECONDS

    def _call_timeout(self, normal: float, end: Optional[float]) -> float:
        """A request's timeout: `normal`, or in a worker the time left (at most
        `normal`); MIN_CALL_SECONDS was checked before the call."""
        return normal if end is None else max(0.01, min(normal, end - time.monotonic()))

    def _note_external(self, service: str, sent: List[str],
                       destination: Optional[str] = None) -> None:
        """I-6: tell a worker's parent what is about to leave the machine, before
        the call; it is reported as a possible transmission if the worker must be
        stopped during that call. Nothing outside a worker."""
        listen = getattr(self, "external_listener", None)
        if listen is not None:
            listen(service, sent, destination)

    def vt_may_contact(self) -> bool:
        """Whether the VirusTotal layer would contact VirusTotal (or intel for it)."""
        if self.intel is not None:
            return bool(self.intel.service("virustotal").get("enabled"))
        return bool(self.config.get("virustotal_api_key"))

    def _vt_session(self, end: Optional[float]):
        """(session, owned): in a worker a session of this call without automatic
        retries (a retry and its back-off would not see the deadline), closed by
        the caller; else the shared session, as before."""
        import requests
        if end is None or not isinstance(self.http, requests.Session):
            return self.http, False                  # outside a worker, or a stand-in
        from core.http import build_session
        return build_session(total_retries=0), True

    def _vt_not_uploaded(self) -> Dict:
        return self._vt_empty(not_found=True, status="timeout",
                              details="Hash unknown to VirusTotal; not uploaded: no time left "
                                      "in the scan limit.")

    def _vt_empty(self, **extra) -> Dict:
        result = {"is_malicious": False, "detection_ratio": 0, "malicious_detections": 0,
                  "suspicious_detections": 0, "total_engines": 0, "permalink": ""}
        result.update(extra)
        return result

    def scan_file_with_virustotal(self, file_path: str, hashes: Optional[Dict] = None) -> Dict:
        """Look the file up on VirusTotal by SHA-256 (upload only if opted in).

        Results are cached per SHA-256 (24 h for verdicts, 6 h for "unknown"),
        requests are paced to the API quota, and every call has a timeout. The
        result's `sent` lists what left the machine for it: "sha256", "file"
        (nothing when the answer came from a cache)."""
        sent: List[str] = []
        result = self._virustotal(file_path, hashes, sent)
        return dict(result, sent=sent) if sent else result

    def _virustotal(self, file_path: str, hashes: Optional[Dict], sent: List[str]) -> Dict:
        if self.intel is not None:
            return self._virustotal_via_intel(file_path, hashes, sent)
        if not self.config.get("virustotal_api_key"):
            return self._vt_empty(details="VirusTotal API key not configured; "
                                          "reputation layer skipped.")
        try:
            # VirusTotal identifies files primarily by SHA-256
            hashes = hashes or self.calculate_hashes(file_path)
            file_hash = hashes["sha256"] or hashes["md5"]

            if self.cache is not None:
                cached = self.cache.get(file_hash, self._vt_cache_layer())
                if cached is not None:
                    cached["cached"] = True
                    return cached

            headers = {"x-apikey": self.config["virustotal_api_key"]}
            check_url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
            end = self._vt_end()
            pace = getattr(self.vt_limiter, "delay", None) if end is not None else None
            if self._no_time_for_a_call(end, pace() if callable(pace) else 0.0):
                return self._vt_empty(status="timeout",
                                      details="VirusTotal not asked: no time left in the scan "
                                              "limit.")
            http, owned = self._vt_session(end)
            try:
                return self._vt_lookup(file_path, file_hash, headers, check_url, sent, http, end)
            finally:
                if owned:
                    http.close()
        except Exception as e:
            logger.error("Error in VirusTotal scan for %s: %s", file_path, str(e))
            return self._vt_empty(error=str(e))

    def _vt_lookup(self, file_path: str, file_hash: str, headers: Dict, check_url: str,
                   sent: List[str], http: Any, end: Optional[float]) -> Dict:
        try:
            self.vt_limiter.wait()
            sent.append("sha256")
            self._note_external("virustotal", ["sha256"])
            response = http.get(check_url, headers=headers,
                                timeout=self._call_timeout(self.http_timeout, end))

            if response.status_code == 404:
                if not self.config.get("virustotal_upload_unknown"):
                    result = self._vt_empty(
                        not_found=True,
                        details="Hash unknown to VirusTotal. Upload is disabled for privacy "
                                "(set VT_UPLOAD_UNKNOWN=true to submit unknown files).")
                    if self.cache is not None:
                        self.cache.put(file_hash, self._vt_cache_layer(), result,
                                       ttl_seconds=6 * 3600)
                    return result
                if self._vt_no_time(end):
                    return self._vt_not_uploaded()          # nothing more is sent
                sent.append("file")
                self._note_external("virustotal", ["file"])
                uploaded = self._vt_upload_and_wait(file_path, headers, check_url, end, http)
                if uploaded is _VT_CUT:
                    return self._vt_empty(
                        not_found=True, status="timeout",
                        details="Uploaded to VirusTotal; its analysis did not finish before the "
                                "scan time limit (look the file up later).")
                response = uploaded or response

            # Process VirusTotal results
            if response.status_code == 200:
                attributes = response.json().get("data", {}).get("attributes", {})
                stats = attributes.get("last_analysis_stats", {})

                # Calculate detection ratio
                total_engines = sum(v for v in stats.values() if isinstance(v, int))
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                detection_ratio = (malicious + suspicious) / total_engines if total_engines > 0 else 0

                result = {
                    "is_malicious": (malicious + suspicious) > 0,
                    "detection_ratio": detection_ratio,
                    "malicious_detections": malicious,
                    "suspicious_detections": suspicious,
                    "total_engines": total_engines,
                    "permalink": f"https://www.virustotal.com/gui/file/{file_hash}/detection"
                }
                if self.cache is not None and total_engines:
                    self.cache.put(file_hash, self._vt_cache_layer(), result)
                return result
            if response.status_code == 404:
                # CO-1: uploads are on and this one gave no report (refused, or its
                # analysis did not finish): the layer has no answer, not a clean one
                return self._vt_empty(not_found=True,
                                      error="Hash unknown to VirusTotal; the upload did not "
                                            "complete, so there is no report for this file.",
                                      details="Hash unknown to VirusTotal; upload did not complete.")
            logger.error("VirusTotal API error: %s - %s", response.status_code, response.text[:200])
            return self._vt_empty(error=f"API Error: {response.status_code}")

        except Exception as e:
            logger.error("Error in VirusTotal scan for %s: %s", file_path, str(e))
            return self._vt_empty(error=str(e))

    def _virustotal_via_intel(self, file_path: str, hashes: Optional[Dict],
                              sent: List[str]) -> Dict:
        """The same look-up through the intel service (no network here): the hash
        first, the file only when it is unknown and intel allows uploads."""
        from core.intel_client import IntelError
        info = self.intel.service("virustotal")
        if not info.get("enabled"):
            why = "unreachable" if info.get("unreachable") else "not configured"
            return self._vt_empty(details=f"VirusTotal via the intel service: {why}; "
                                          "reputation layer skipped.",
                                  **({"error": "intel service unreachable"}
                                     if info.get("unreachable") else {}))
        sha = (hashes or self.calculate_hashes(file_path))["sha256"]
        layer = self._vt_cache_layer()
        if self.cache is not None:
            cached = self.cache.get(sha, layer)
            if cached is not None:
                cached["cached"] = True
                return cached
        end = self._vt_end()
        if self._no_time_for_a_call(end):
            return self._vt_empty(status="timeout",
                                  details="VirusTotal not asked: no time left in the scan limit.")
        try:
            self._note_external("virustotal", ["sha256"])
            result = (self.intel.vt_lookup(sha) if end is None else
                      self.intel.vt_lookup(sha, timeout=self._call_timeout(60, end)))
            sent.extend(result.pop("sent", None) or [])
            if result.get("not_found") and info.get("upload"):
                if self._vt_no_time(end):
                    return self._vt_not_uploaded()          # nothing more is sent
                self._note_external("virustotal", ["file"])
                result = (self.intel.vt_upload(file_path) if end is None else
                          self.intel.vt_upload(file_path, timeout=end - time.monotonic()))
                sent.extend(s for s in result.pop("sent", None) or [] if s not in sent)
        except (IntelError, OSError) as e:
            logger.error("VirusTotal via the intel service failed for %s: %s", file_path, e)
            return self._vt_empty(error=str(e))
        if self.cache is not None and not result.get("error"):
            if result.get("total_engines"):
                self.cache.put(sha, layer, result)
            elif result.get("not_found") and not info.get("upload"):
                self.cache.put(sha, layer, result, ttl_seconds=6 * 3600)
        return result

    def _vt_upload_and_wait(self, file_path: str, headers: Dict, check_url: str,
                            end: Optional[float] = None, http: Any = None):
        """Opt-in upload of an unknown file; returns the final file report response,
        None, or _VT_CUT when `end` (an isolated worker's limit, I-6) came first:
        the wait then stops instead of outlasting the scan."""
        http = http or self.http
        logger.info("File %s not found in VirusTotal. Uploading (VT_UPLOAD_UNKNOWN=true)...", file_path)
        # VirusTotal: files < 32 MB use the standard /files endpoint;
        # larger files require a dedicated one-time upload URL.
        file_size = os.path.getsize(file_path)
        upload_url = "https://www.virustotal.com/api/v3/files"
        if file_size >= 32 * 1024 * 1024:
            logger.info("File >= 32 MB; requesting a dedicated upload URL...")
            self.vt_limiter.wait()
            r = http.get("https://www.virustotal.com/api/v3/files/upload_url",
                              headers=headers, timeout=self._call_timeout(self.http_timeout, end))
            if r.status_code != 200:
                logger.error("Error getting VirusTotal upload URL: %s", r.status_code)
                return None
            upload_url = r.json().get("data", "")
        self.vt_limiter.wait()
        with open(file_path, "rb") as file:
            files = {"file": (os.path.basename(file_path), file)}
            upload = http.post(upload_url, headers=headers, files=files,
                                    timeout=self._call_timeout(max(120, self.http_timeout), end))
        if upload.status_code != 200:
            logger.error("Error uploading file to VirusTotal: %s", upload.status_code)
            return None
        analysis_id = upload.json().get("data", {}).get("id", "")
        logger.info("File uploaded to VirusTotal. Analysis ID: %s. Waiting for results...", analysis_id)
        analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        for _attempt in range(VT_POLLS):
            if self._vt_no_time(end):
                return _VT_CUT
            time.sleep(VT_POLL_SECONDS)  # Wait between status checks
            self.vt_limiter.wait()
            status_resp = http.get(analysis_url, headers=headers, timeout=self._call_timeout(self.http_timeout, end))
            if status_resp.status_code == 200 and status_resp.json().get("data", {}) \
                    .get("attributes", {}).get("status") == "completed":
                self.vt_limiter.wait()
                return http.get(check_url, headers=headers, timeout=self._call_timeout(self.http_timeout, end))
        return None

