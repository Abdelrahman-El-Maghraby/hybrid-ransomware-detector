"""tools/mbox_to_eml.py splits mailboxes into one .eml per message."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
import mbox_to_eml  # noqa: E402

MSG = "From a@example.com Mon Jan  1 00:00:00 2024\nFrom: a@example.com\nSubject: {s}\n\nbody {s}\n\n"


def test_messages_are_split_and_duplicates_dropped(tmp_path):
    box = tmp_path / "phishing-2024"
    box.write_text(MSG.format(s="one") + MSG.format(s="two") + MSG.format(s="one"))
    written, dups, errors = mbox_to_eml.split([box], tmp_path / "out")
    files = sorted((tmp_path / "out").glob("*.eml"))
    assert (written, dups, errors) == (2, 1, 0)
    assert [f.name for f in files] == ["phishing-2024_00001.eml", "phishing-2024_00002.eml"]
    assert b"Subject: two" in files[1].read_bytes()


def test_limit_and_cli(tmp_path, capsys):
    box = tmp_path / "a.mbox"
    box.write_text("".join(MSG.format(s=str(i)) for i in range(5)))
    assert mbox_to_eml.main([str(tmp_path / "o"), str(box), "--limit", "3"]) == 0
    assert len(list((tmp_path / "o").glob("*.eml"))) == 3
    assert "3 message(s) written" in capsys.readouterr().out
