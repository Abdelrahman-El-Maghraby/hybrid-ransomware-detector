"""The engine's structure: pipeline order, adding layers, adding container types,
and the names RansomwareScanner.py keeps exporting for the GUI and older callers."""

import contextlib
import importlib.util
from dataclasses import dataclass, field
from pathlib import Path
from typing import List

import pytest

import RansomwareScanner as RS
from engine import config as engine_config
from engine.containers import ArchiveHandler, ContainerHandler, MailHandler
from engine.layers import ContainerLayer, Layer, ScanContext, default_pipeline
from tests.helpers import make_pdf
from tests.test_file_integrity import _pe_bytes
from tests.test_scanner_integration import _config

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def scanner(tmp_path):
    return RS.RansomwareScanner(_config(tmp_path))


def test_default_pipeline_order():
    names = [layer.name for layer in default_pipeline()]
    assert names == ["hashes", "fuzzy", "local-db", "macro", "yara", "integrity", "elf", "mail",
                     "prompt-guard", "relationships", "qr", "archive", "web", "ml", "llm",
                     "virustotal"]
    # The mail container must run before the prompt guard: the guard reads the body.
    assert names.index("mail") < names.index("prompt-guard")


def test_a_new_layer_can_be_added_without_touching_scan_file(scanner, tmp_path):
    class SizeLayer(Layer):
        name = "size-note"

        def run(self, scanner, ctx):
            ctx.scan_results["size_note"] = {"bytes": ctx.result["file_size"],
                                             "saw_sha256": bool(ctx.hashes.get("sha256"))}

    scanner.pipeline.insert(1, SizeLayer())
    p = tmp_path / "scan" / "letter.pdf"
    p.write_bytes(make_pdf("hello"))
    r = scanner.scan_file(str(p))
    assert r["scan_results"]["size_note"] == {"bytes": p.stat().st_size, "saw_sha256": True}
    assert r["verdict"] == "Clean"


def test_pipeline_order_is_the_report_order(scanner, tmp_path):
    p = tmp_path / "scan" / "letter.pdf"
    p.write_bytes(make_pdf("hello"))
    keys = list(scanner.scan_file(str(p))["scan_results"])
    assert keys == ["fuzzy_hash", "local_database", "macro_analysis", "yara", "file_integrity",
                    "prompt_guard", "relationships", "ml_classifier", "chatgpt_analysis",
                    "virustotal"]


# A whole new container type in a few lines: a "folder bundle" whose members
# are the files of a directory named <file>.d next to it.
@dataclass
class _Bundle:
    files: List[Path] = field(default_factory=list)

    def as_dict(self):
        return {"member_count": len(self.files)}


class BundleHandler(ContainerHandler):
    result_key = signal_key = "bundle"
    members_key = "member_results"
    worst_key = "worst_member"
    error_label = "bundle member"

    def applies(self, ctx):
        return ctx.path.endswith(".bundle")

    @contextlib.contextmanager
    def open(self, scanner, path):
        yield _Bundle(sorted(Path(path + ".d").iterdir()))

    def budget(self, scanner):
        return 2

    def items(self, view, ctx):
        for f in view.files:
            yield str(f), f"{ctx.display}!/{f.name}", f.name

    def signals(self, d):
        return {}


def test_a_new_container_type_reuses_the_scanning_loop(scanner, tmp_path):
    bundle = tmp_path / "scan" / "set.bundle"
    bundle.write_bytes(b"bundle manifest")
    members = Path(str(bundle) + ".d")
    members.mkdir()
    (members / "a_letter.pdf").write_bytes(make_pdf("hi"))
    (members / "b_invoice.pdf").write_bytes(_pe_bytes(2048))     # disguised executable
    (members / "c_extra.pdf").write_bytes(make_pdf("over budget"))
    scanner.pipeline.insert(-3, ContainerLayer(BundleHandler()))

    r = scanner.scan_file(str(bundle))
    b = r["scan_results"]["bundle"]
    assert b["member_count"] == 3 and b["deep_scanned"] == 2 and b["not_scanned_budget"] == 1
    assert [m["name"].split("!/")[-1] for m in b["member_results"]] == ["a_letter.pdf",
                                                                        "b_invoice.pdf"]
    verdicts = {m["name"].split("!/")[-1]: m["verdict"] for m in b["member_results"]}
    assert verdicts == {"a_letter.pdf": "Clean", "b_invoice.pdf": "Critical"}
    assert b["member_results"][1]["name"] == f"{bundle}!/b_invoice.pdf"


def test_built_in_handlers_keep_their_result_keys():
    assert (ArchiveHandler.result_key, ArchiveHandler.members_key) == ("archive", "member_results")
    assert (MailHandler.result_key, MailHandler.members_key) == ("mail", "attachment_results")
    assert ArchiveHandler.worst_key == "worst_member"
    assert MailHandler.worst_key == "worst_attachment"


def test_scan_context_start(scanner, tmp_path):
    p = tmp_path / "scan" / "m.eml"
    p.write_text("Subject: hi\n\nbody")
    ctx = ScanContext.start(scanner, str(p), 1, "outer.zip!/m.eml", "x")
    assert ctx.is_mail and not ctx.is_archive
    assert ctx.result["file_name"] == "m.eml" and ctx.result["file_path"] == "outer.zip!/m.eml"
    assert ctx.signals == {"archive": {}, "mail": {}, "ml": {}}


@pytest.mark.parametrize("name", [
    "RansomwareScanner", "CONFIG", "ENGINE_VERSION", "SUPPORTED_EXTENSIONS", "APP_DIR",
    "LOG_FILE", "REPORT_DIR", "ENV_FILE", "BUNDLED_RULES_DIR", "FROZEN", "defang",
    "DEFUSEDXML_AVAILABLE", "FUZZY_AVAILABLE", "OLEVBA_AVAILABLE", "YARA_AVAILABLE",
    "MSG_AVAILABLE", "SKLEARN_AVAILABLE", "import_hash_database", "setup_autostart",
    "remove_autostart", "winreg", "AUTOSTART_LABEL", "AUTOSTART_NAME", "SYSTEMD_UNIT",
    "extract_suspicious_strings",
])
def test_entry_point_keeps_exporting(name):
    assert hasattr(RS, name)


def test_config_is_shared_not_copied():
    assert RS.CONFIG is engine_config.CONFIG
    assert RS.ENGINE_VERSION == engine_config.ENGINE_VERSION


def test_bundled_assets_resolve_from_the_repo_root():
    assert RS.BUNDLED_RULES_DIR == ROOT / "rules" and RS.BUNDLED_RULES_DIR.is_dir()
    assert RS.BUNDLED_FUZZY_SIGS.is_file()


def test_build_script_reads_the_engine_version():
    spec = importlib.util.spec_from_file_location("hrd_build", ROOT / "build.py")
    build = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(build)
    assert build.engine_version() == RS.ENGINE_VERSION
