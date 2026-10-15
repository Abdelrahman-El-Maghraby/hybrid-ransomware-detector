#!/usr/bin/env python3
"""
test_smoke.py — End-to-end verification suite for AEGIS SENTINEL v5.2.0.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import docx

from config import CONFIG
from core.quarantine import QuarantineManager
from core.supply_chain import URLPrivacyFilter, generate_cyclonedx_sbom
from scanner import AegisSentinelScanner


class AegisSentinelSmokeTests(unittest.TestCase):
    def test_quarantine_aes_gcm_self_test(self) -> None:
        self.assertTrue(QuarantineManager.self_test())

    def test_url_privacy_filter(self) -> None:
        flt = URLPrivacyFilter(internal_domains=["corp.example.com"])
        ok_int, _, _ = flt.prepare_url_for_external_lookup("https://portal.corp.example.com/login")
        self.assertFalse(ok_int)
        ok_ext, clean_u, _ = flt.prepare_url_for_external_lookup("https://evil.org/phish?token=secret123&id=5")
        self.assertTrue(ok_ext)
        self.assertIn("token=REDACTED", clean_u)

    def test_end_to_end_scan_and_canary_tripwire(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cfg = dict(CONFIG)
            cfg.update({
                "scan_directories": [str(root)],
                "cache_db_path": str(root / "cache.sqlite3"),
                "quarantine_dir": str(root / "qvault"),
                "quarantine_db_path": str(root / "q.sqlite3"),
                "quarantine_key_path": str(root / "q.key"),
                "incident_db_path": str(root / "inc.sqlite3"),
                "canary_db_path": str(root / "canary.sqlite3"),
                "llm_provider": "none",
            })
            scanner = AegisSentinelScanner(cfg)

            clean_doc = root / "clean.docx"
            d = docx.Document()
            d.add_paragraph("Standard project schedule.")
            d.save(clean_doc)
            res_clean = scanner.scan_file(str(clean_doc))
            self.assertEqual(res_clean["verdict"], "Clean")

            deployed = scanner.canary_manager.deploy_canaries([root])
            self.assertGreaterEqual(len(deployed), 1)
            canary_path = Path(deployed[0]["canary_path"])
            canary_path.write_bytes(b"TAMPERED_BY_RANSOMWARE")
            audit = scanner.canary_manager.verify_canaries()
            self.assertTrue(audit.triggered)

            sbom = generate_cyclonedx_sbom(output_path=root / "sbom.json")
            self.assertGreater(sbom["components_count"], 5)


if __name__ == "__main__":
    unittest.main(verbosity=2)