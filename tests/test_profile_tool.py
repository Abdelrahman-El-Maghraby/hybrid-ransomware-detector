"""I-B4: tools/profile_layers.py added a container layer's time (which includes
its members' layers) and the members' layer times again, so the per-layer
totals exceeded the wall time; its hrd-profile- work folder was never removed."""

import io
import zipfile
from pathlib import Path

from tests.helpers import make_pdf
from tools import profile_layers as P


def test_layer_totals_do_not_exceed_the_wall_time_and_the_folder_is_removed(tmp_path,
                                                                            monkeypatch):
    from types import SimpleNamespace
    work = tmp_path / "profile-work"
    monkeypatch.setattr(P, "tempfile", SimpleNamespace(            # the tool's folder only
        mkdtemp=lambda prefix="": (work.mkdir(), str(work))[1]))
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for i in range(4):
            z.writestr(f"doc{i}.pdf", make_pdf(f"quarterly figures {i}"))
    archive = tmp_path / "bundle.zip"
    archive.write_bytes(buf.getvalue())
    ticks = iter(range(1_000_000))         # the tool's clock only: one "second" per read
    monkeypatch.setattr(P, "time", SimpleNamespace(perf_counter=lambda: float(next(ticks))))
    result = P.profile([str(archive)])
    assert result["rows"][0].get("verdict")
    assert sum(result["layers"].values()) <= result["seconds"]
    assert not Path(work).exists()
