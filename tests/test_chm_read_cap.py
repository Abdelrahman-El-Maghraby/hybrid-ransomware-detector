"""L-D7, option (b), owner-approved 2026-11-11: _chm starts one `7z e -so` per page
to look for the HTML Help ShortCut object. It now reads at most MAX_CHM_READS
(1,000) pages and files in sorted path order; the rest are named in one skipped
note, which makes the scan partial. A CHM with at most 1,000 pages is unchanged. (Unchanged also: every .htm page is a
member, so a help file with more than 25 pages already reads partial through the
member limit; see the last tests.)
The 7-Zip calls are stand-ins: nothing is unpacked or run."""

import pytest

import detectors.embedded_content as ec
import detectors.macos_packages as mp
from detectors.embedded_content import EmbeddedContentAnalyzer
from tests.test_scanner_integration import scanner  # noqa: F401  (fixture)

SHORTCUT = (b'<html><object id=x classid="clsid:adb880a6-d8ff-11cf-9377-00aa003b7a11">'
            b'<param name="Command" value="ShortCut"></object></html>')
PLAIN = b"<html><body>Help topic</body></html>"


def _pages(n, shortcut_at=None, internal=0, ext=".htm"):
    """n pages named so that sorted order is numeric order; page `shortcut_at`
    (1-based) holds the ShortCut object."""
    items = [mp.ListedItem(f"#STRINGS{i:05d}", 8, False, False) for i in range(internal)]
    items += [mp.ListedItem(f"html/p{i:05d}{ext}", len(PLAIN), False, False)
              for i in range(1, n + 1)]
    content = {f"html/p{shortcut_at:05d}{ext}": SHORTCUT} if shortcut_at else {}
    return items, content


@pytest.fixture
def chm(tmp_path, monkeypatch):
    reads = []

    def install(n, shortcut_at=None, internal=0, ext=".htm"):
        items, content = _pages(n, shortcut_at, internal, ext)
        monkeypatch.setattr(mp, "sevenzip_list", lambda tool, archive, *a, **k: items)

        def read(tool, archive, name, *a, **k):
            reads.append(name)
            return content.get(name, PLAIN)
        monkeypatch.setattr(mp, "sevenzip_read", read)
        p = tmp_path / "help.chm"
        p.write_bytes(b"ITSF\x03\x00\x00\x00" + b"\x00" * 200)
        return p
    return install, reads


READ_NOTE = "help pages not read (read limit 1000)"


def _read_notes(res):
    return [s for s in res.skipped if READ_NOTE in s]


def _analyze(path):
    with EmbeddedContentAnalyzer(sevenzip=lambda: "7z").open(path, extract=False) as res:
        return res


def test_the_cap_is_1000(chm):
    assert ec.MAX_CHM_READS == 1000


def test_reads_stop_at_the_cap_and_the_rest_is_named(chm):
    install, reads = chm
    res = _analyze(install(1200))
    assert len(reads) == 1000 and reads[-1] == "html/p01000.htm"
    assert "200 of 1200 help pages not read (read limit 1000)" in res.skipped


def test_a_shortcut_on_the_last_page_read_is_found(chm):
    install, reads = chm
    res = _analyze(install(1000, shortcut_at=1000))
    assert res.chm_shortcut and _read_notes(res) == [] and len(reads) == 1000


def test_a_shortcut_beyond_the_cap_is_not_found_and_says_so(chm):
    install, reads = chm
    res = _analyze(install(1001, shortcut_at=1001))
    assert not res.chm_shortcut and len(reads) == 1000
    assert _read_notes(res) == ["1 of 1001 help pages not read (read limit 1000)"]


def test_a_small_help_file_is_read_completely(chm):
    install, reads = chm
    res = _analyze(install(20, shortcut_at=12))
    assert res.chm_shortcut and len(reads) == 20 and res.skipped == []


def test_internal_streams_do_not_count(chm):
    install, reads = chm
    res = _analyze(install(10, internal=2000))
    assert len(reads) == 10 and res.skipped == []


def test_the_member_limit_is_unchanged_inside_the_cap(chm):
    install, reads = chm
    res = _analyze(install(40, ext=".js"))
    assert len(reads) == 40 and len(res.members) == ec.MAX_MEMBERS
    assert sum("member limit reached" in s for s in res.skipped) == 40 - ec.MAX_MEMBERS


def test_through_the_scanner_a_shortcut_beyond_the_cap_is_clean_but_partial(scanner, chm):
    install, _ = chm
    scanner.embedded_analyzer.sevenzip = lambda: "7z"
    path = install(1001, shortcut_at=1001)
    beyond = scanner.scan_file(str(path))
    assert beyond["scan_status"] == "partial"
    assert any("help pages not read (read limit 1000)" in str(r)
               for r in beyond["incomplete_reasons"])
    assert "chm_shortcut_command" not in {c["indicator"] for c in
                                          beyond["score_breakdown"]["contributions"]}
    within = scanner.scan_file(str(install(1000, shortcut_at=1000)))
    assert "chm_shortcut_command" in {c["indicator"] for c in
                                      within["score_breakdown"]["contributions"]}
    assert not any(READ_NOTE in str(r) for r in within["incomplete_reasons"])
    small = scanner.scan_file(str(install(20, shortcut_at=20)))
    assert small["scan_status"] == "complete" and small["verdict"] == "High"


def test_more_than_25_pages_already_read_partial_through_the_member_limit(chm):
    """Not changed by the cap: recorded so a later change is deliberate."""
    install, _ = chm
    res = _analyze(install(30))
    assert _read_notes(res) == [] and sum("member limit reached" in s for s in res.skipped) == 5


def test_the_partial_clean_result_is_visible_but_sends_no_alert(scanner, chm, tmp_path,
                                                                monkeypatch):
    """Pinned, not changed (owner decision pending): alerts follow the verdict only,
    so a ShortCut page beyond the cap gives a Clean, partial result that every
    output marks as partial but that queues no webhook or e-mail alert."""
    from core.outputs import alert_payload, deliver
    install, _ = chm
    scanner.embedded_analyzer.sevenzip = lambda: "7z"
    r = scanner.scan_file(str(install(1001, shortcut_at=1001)))
    assert r["verdict"] == "Clean" and r["scan_status"] == "partial"
    assert alert_payload(r)["scan_status"] == "partial"
    assert "Clean (partial scan)" in scanner.generate_report([r])
    monkeypatch.setattr("requests.post", lambda *a, **k: None)
    cfg = dict(scanner.config, webhook_url="https://siem.example.invalid/hook",
               outbox_dir=str(tmp_path / "outbox"), jsonl_path=str(tmp_path / "out.jsonl"))
    deliver([r], cfg)
    assert not list((tmp_path / "outbox").rglob("*.json"))
    assert '"scan_status": "partial"' in (tmp_path / "out.jsonl").read_text()
