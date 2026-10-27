"""Outside opinions: the LLM backend and VirusTotal (both cached by SHA-256)."""

import logging
import os
import time
from typing import TYPE_CHECKING, Any, Dict, Optional

from .text import extract_suspicious_strings

logger = logging.getLogger("RansomwareScanner")


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
        def _extract_text_from_file(self, file_path: str, allow_ocr: bool = True) -> str: ...

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

            result = self.llm_backend.analyze(combined)
            if sha256 and self.cache is not None and result.get("analyzed"):
                self.cache.put(sha256, cache_layer, result)
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

    def _vt_empty(self, **extra) -> Dict:
        result = {"is_malicious": False, "detection_ratio": 0, "malicious_detections": 0,
                  "suspicious_detections": 0, "total_engines": 0, "permalink": ""}
        result.update(extra)
        return result

    def scan_file_with_virustotal(self, file_path: str, hashes: Optional[Dict] = None) -> Dict:
        """Look the file up on VirusTotal by SHA-256 (upload only if opted in).

        Results are cached per SHA-256 (24 h for verdicts, 6 h for "unknown"),
        requests are paced to the API quota, and every call has a timeout.
        """
        if self.intel is not None:
            return self._virustotal_via_intel(file_path, hashes)
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
            self.vt_limiter.wait()
            response = self.http.get(check_url, headers=headers, timeout=self.http_timeout)

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
                response = self._vt_upload_and_wait(file_path, headers, check_url) or response

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
                return self._vt_empty(not_found=True,
                                      details="Hash unknown to VirusTotal; upload did not complete.")
            logger.error("VirusTotal API error: %s - %s", response.status_code, response.text[:200])
            return self._vt_empty(error=f"API Error: {response.status_code}")

        except Exception as e:
            logger.error("Error in VirusTotal scan for %s: %s", file_path, str(e))
            return self._vt_empty(error=str(e))

    def _virustotal_via_intel(self, file_path: str, hashes: Optional[Dict]) -> Dict:
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
        try:
            result = self.intel.vt_lookup(sha)
            if result.get("not_found") and info.get("upload"):
                result = self.intel.vt_upload(file_path)
        except (IntelError, OSError) as e:
            logger.error("VirusTotal via the intel service failed for %s: %s", file_path, e)
            return self._vt_empty(error=str(e))
        if self.cache is not None and not result.get("error"):
            if result.get("total_engines"):
                self.cache.put(sha, layer, result)
            elif result.get("not_found") and not info.get("upload"):
                self.cache.put(sha, layer, result, ttl_seconds=6 * 3600)
        return result

    def _vt_upload_and_wait(self, file_path: str, headers: Dict, check_url: str):
        """Opt-in upload of an unknown file; returns the final file report response."""
        logger.info("File %s not found in VirusTotal. Uploading (VT_UPLOAD_UNKNOWN=true)...", file_path)
        # VirusTotal: files < 32 MB use the standard /files endpoint;
        # larger files require a dedicated one-time upload URL.
        file_size = os.path.getsize(file_path)
        upload_url = "https://www.virustotal.com/api/v3/files"
        if file_size >= 32 * 1024 * 1024:
            logger.info("File >= 32 MB; requesting a dedicated upload URL...")
            self.vt_limiter.wait()
            r = self.http.get("https://www.virustotal.com/api/v3/files/upload_url",
                              headers=headers, timeout=self.http_timeout)
            if r.status_code != 200:
                logger.error("Error getting VirusTotal upload URL: %s", r.status_code)
                return None
            upload_url = r.json().get("data", "")
        self.vt_limiter.wait()
        with open(file_path, "rb") as file:
            files = {"file": (os.path.basename(file_path), file)}
            upload = self.http.post(upload_url, headers=headers, files=files,
                                    timeout=max(120, self.http_timeout))
        if upload.status_code != 200:
            logger.error("Error uploading file to VirusTotal: %s", upload.status_code)
            return None
        analysis_id = upload.json().get("data", {}).get("id", "")
        logger.info("File uploaded to VirusTotal. Analysis ID: %s. Waiting for results...", analysis_id)
        analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        for _attempt in range(10):
            time.sleep(15)  # Wait between status checks
            self.vt_limiter.wait()
            status_resp = self.http.get(analysis_url, headers=headers, timeout=self.http_timeout)
            if status_resp.status_code == 200 and status_resp.json().get("data", {}) \
                    .get("attributes", {}).get("status") == "completed":
                self.vt_limiter.wait()
                return self.http.get(check_url, headers=headers, timeout=self.http_timeout)
        return None

