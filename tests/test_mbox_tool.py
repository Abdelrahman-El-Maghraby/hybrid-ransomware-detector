"""tools/mbox_to_eml.py splits mailboxes into one .eml per message."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
import mbox_to_eml

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


def test_two_mailboxes_with_one_name_keep_all_messages(tmp_path):
    """L-C8: a/inbox.mbox and b/inbox.mbox both wrote inbox_00001.eml and up; the
    second overwrote the first and both were counted as written."""
    boxes = []
    for folder in ("a", "b"):
        (tmp_path / folder).mkdir()
        box = tmp_path / folder / "inbox.mbox"
        box.write_text(MSG.format(s=f"{folder}-1") + MSG.format(s=f"{folder}-2"))
        boxes.append(box)
    written, dups, errors = mbox_to_eml.split(boxes, tmp_path / "out")
    files = list((tmp_path / "out").glob("*.eml"))
    assert written == 4 and len(files) == 4
    bodies = b"".join(f.read_bytes() for f in files)
    assert all(f"Subject: {s}".encode() in bodies for s in ("a-1", "a-2", "b-1", "b-2"))
