"""detectors/tlsh_py.py must give exactly python-tlsh's digests and distances.

The golden values were produced by python-tlsh 4.5.0, so they are checked on
every OS - including Windows, where the C library cannot be installed."""

import random

import pytest

from detectors import tlsh_py

try:
    import tlsh as c_tlsh
except ImportError:  # pragma: no cover - Windows
    c_tlsh = None


def gen(seed, n, alphabet=None):
    r = random.Random(seed)
    return bytes(r.choice(alphabet) if alphabet else r.getrandbits(8) for _ in range(n))


GOLDEN = [
    ((1, 60, None), "T1A7A022A0B00CA80808220C20208082280020C8888000B380A0230080020C230330BA00"),
    ((2, 1000, None), "T11A11986AA2CD4CB39380EBEA325B27D1C1404C26EB43B4DD74D7C62FAD0E69A549E51C"),
    ((3, 40000, None), "T1CD0302FD0BDB5E3877E065D9CEEB9305E8F648D3B133587DEA249439A8830948A35E10"),
    ((4, 5000, b"abcdefgh \n"),
     "T12EA1DB74CBE64D4E7C77D2D0D7179E98CE92EB35F398C49988EC485D9144868C07327A"),
    ((5, 300000, None), "T1745423029E3ACCF4CCDFA4854D7599EC6F41100440DE229467DAED76D2EEC25AE2DD3A"),
    ((6, 200, b"ab"), "TNULL"),              # too uniform
]


@pytest.mark.parametrize("args, digest", GOLDEN)
def test_golden_digests(args, digest):
    assert tlsh_py.hash(gen(*args)) == digest


def test_golden_distance():
    assert tlsh_py.diff(GOLDEN[2][1], GOLDEN[3][1]) == 549
    assert tlsh_py.diff(GOLDEN[2][1], GOLDEN[2][1]) == 0


def test_short_input_is_null():
    assert tlsh_py.hash(b"x" * 49) == "TNULL"
    assert tlsh_py.hash(b"") == "TNULL"


def test_without_numpy_same_digest(monkeypatch):
    data = gen(2, 1000)
    monkeypatch.setattr(tlsh_py, "_np", None)
    assert tlsh_py.hash(data) == GOLDEN[1][1]


def test_without_numpy_large_input_is_capped(monkeypatch):
    monkeypatch.setattr(tlsh_py, "_np", None)
    monkeypatch.setattr(tlsh_py, "PURE_PYTHON_LIMIT", 1000)
    assert tlsh_py.hash(gen(2, 1000) + b"tail" * 500) == GOLDEN[1][1]


def test_diff_rejects_garbage():
    with pytest.raises(ValueError):
        tlsh_py.diff("T1ABC", GOLDEN[0][1])


@pytest.mark.skipif(c_tlsh is None, reason="python-tlsh not installed")
def test_matches_the_c_library_on_varied_inputs():
    rng = random.Random(11)
    inputs = []
    for n in (50, 51, 64, 100, 257, 700, 3200, 9000, 70_000):
        inputs.append(bytes(rng.getrandbits(8) for _ in range(n)))
        inputs.append(bytes(rng.choice(b"<html> body, the of and 0123") for _ in range(n)))
    for data in inputs:
        assert tlsh_py.hash(data) == c_tlsh.hash(data)
    digests = [d for d in (c_tlsh.hash(x) for x in inputs) if d != "TNULL"]
    for _ in range(300):
        a, b = rng.choice(digests), rng.choice(digests)
        assert tlsh_py.diff(a, b) == c_tlsh.diff(a, b)
