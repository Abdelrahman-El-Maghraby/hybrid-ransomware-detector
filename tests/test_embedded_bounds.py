"""L-D4 and L-D6.

L-D4: a OneNote file made of repeated FileDataStoreObject GUIDs with impossible
lengths added one "skipped" entry per 16 input bytes (check 6), so a 50 MB
upload would give a result of about 135 MB. The list is now capped; the rest
is counted in one line, and the result stays partial.

L-D6: YARA rule files were compiled under their stem, so `a.yar` and `a.yara`
shared one namespace and one of them was not loaded."""

import pytest

from detectors import embedded_content as ec
from detectors.yara_engine import YARA_AVAILABLE, YaraEngine

ONE_HEADER = ec.ONENOTE_MAGIC + b"\x00" * 16


def test_a_flood_of_impossible_entries_gives_a_bounded_list(tmp_path):
    bad = ec._ONENOTE_FILEDATA + (2**60).to_bytes(8, "little") + b"\x00" * 12
    p = tmp_path / "flood.one"
    p.write_bytes(ONE_HEADER + bad * 20_000)              # 720 KB, 20,000 bad entries
    with ec.EmbeddedContentAnalyzer().open(p) as res:
        skipped = res.as_dict()["skipped"]
    assert 1 < len(skipped) <= ec.MAX_SKIPPED + 1
    assert skipped[-1].endswith("more not listed") and "19,950" in skipped[-1]


def test_a_short_list_is_unchanged():
    res = ec.EmbeddedResult()
    for i in range(3):
        res.skip(f"entry {i}")
    assert res.as_dict()["skipped"] == ["entry 0", "entry 1", "entry 2"]


@pytest.mark.skipif(not YARA_AVAILABLE, reason="yara-python not installed")
def test_rule_files_with_one_stem_are_both_loaded(tmp_path):
    (tmp_path / "a.yar").write_text('rule From_Yar { strings: $a = "alpha-marker" condition: $a }')
    (tmp_path / "a.yara").write_text('rule From_Yara { strings: $b = "beta-marker" condition: $b }')
    sample = tmp_path / "s.txt"
    sample.write_text("alpha-marker beta-marker")
    found = {m.rule for m in YaraEngine(rules_dir=str(tmp_path)).scan_file(str(sample)).matches}
    assert found == {"From_Yar", "From_Yara"}
