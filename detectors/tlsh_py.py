"""
Pure-Python TLSH (128 buckets, 1-byte checksum, "T1" digests) - a drop-in for
the two python-tlsh functions the scanner uses, `hash(data)` and `diff(a, b)`.

Why: python-tlsh ships no Windows wheels and its source build fails there, so
Windows installs (and the Windows release binary) had ssdeep only. Digests and
distances are byte-for-byte identical to python-tlsh 4.x; the test suite checks
this against the C library wherever it is installed.

Speed: with numpy the bucket counting is vectorised (tens of MB/s); without it a
plain loop is used, which is slow, so `hash` only reads the first
PURE_PYTHON_LIMIT bytes in that case and the digest then describes that prefix.

Ported from TLSH by Trend Micro (Apache License 2.0),
https://github.com/trendmicro/tlsh - tlsh_impl.cpp / tlsh_util.cpp.
"""

from __future__ import annotations

import bisect
from typing import List, Optional, Tuple

try:
    import numpy as _np
except Exception:  # pragma: no cover - numpy is optional
    _np = None  # type: ignore[assignment]

MIN_DATA_LENGTH = 50
CODE_SIZE = 32
EFF_BUCKETS = 128
PURE_PYTHON_LIMIT = 2 * 1024 * 1024
NULL = "TNULL"

# Pearson permutation table (v_table in tlsh_impl.cpp)
V_TABLE = bytes([
    1, 87, 49, 12, 176, 178, 102, 166, 121, 193, 6, 84, 249, 230, 44, 163,
    14, 197, 213, 181, 161, 85, 218, 80, 64, 239, 24, 226, 236, 142, 38, 200,
    110, 177, 104, 103, 141, 253, 255, 50, 77, 101, 81, 18, 45, 96, 31, 222,
    25, 107, 190, 70, 86, 237, 240, 34, 72, 242, 20, 214, 244, 227, 149, 235,
    97, 234, 57, 22, 60, 250, 82, 175, 208, 5, 127, 199, 111, 62, 135, 248,
    174, 169, 211, 58, 66, 154, 106, 195, 245, 171, 17, 187, 182, 179, 0, 243,
    132, 56, 148, 75, 128, 133, 158, 100, 130, 126, 91, 13, 153, 246, 216, 219,
    119, 68, 223, 78, 83, 88, 201, 99, 122, 11, 92, 32, 136, 114, 52, 10,
    138, 30, 48, 183, 156, 35, 61, 26, 143, 74, 251, 94, 129, 162, 63, 152,
    170, 7, 115, 167, 241, 206, 3, 150, 55, 59, 151, 220, 90, 53, 23, 131,
    125, 173, 15, 238, 79, 95, 89, 16, 105, 137, 225, 224, 217, 160, 37, 123,
    118, 73, 2, 157, 46, 116, 9, 145, 134, 228, 207, 212, 202, 215, 69, 229,
    27, 188, 67, 124, 168, 252, 42, 4, 29, 108, 21, 247, 19, 205, 39, 203,
    233, 40, 186, 147, 198, 192, 155, 33, 164, 191, 98, 204, 165, 180, 117, 76,
    140, 36, 210, 172, 41, 54, 159, 8, 185, 232, 113, 196, 231, 47, 146, 120,
    51, 65, 28, 144, 254, 221, 93, 189, 194, 139, 112, 43, 71, 109, 184, 209,
])

# Upper bounds of each length class (topval in tlsh_util.cpp)
_TOPVAL = [
    1, 2, 3, 5, 7, 11, 17, 25, 38, 57, 86, 129, 194, 291, 437, 656, 854, 1110, 1443,
    1876, 2439, 3171, 3475, 3823, 4205, 4626, 5088, 5597, 6157, 6772, 7450, 8195, 9014,
    9916, 10907, 11998, 13198, 14518, 15970, 17567, 19323, 21256, 23382, 25720, 28292,
    31121, 34233, 37656, 41422, 45564, 50121, 55133, 60646, 66711, 73382, 80721, 88793,
    97672, 107439, 118183, 130002, 143002, 157302, 173032, 190335, 209369, 230306,
    253337, 278670, 306538, 337191, 370911, 408002, 448802, 493682, 543050, 597356,
    657091, 722800, 795081, 874589, 962048, 1058252, 1164078, 1280486, 1408534, 1549388,
    1704327, 1874759, 2062236, 2268459, 2495305, 2744836, 3019320, 3321252, 3653374,
    4018711, 4420582, 4862641, 5348905, 5883796, 6472176, 7119394, 7831333, 8614467,
    9475909, 10423501, 11465851, 12612437, 13873681, 15261050, 16787154, 18465870,
    20312458, 22343706, 24578077, 27035886, 29739474, 32713425, 35984770, 39583245,
    43541573, 47895730, 52685306, 57953837, 63749221, 70124148, 77136564, 84850228,
    93335252, 102668779, 112935659, 124229227, 136652151, 150317384, 165349128,
    181884040, 200072456, 220079703, 242087671, 266296456, 292926096, 322218735,
    354440623, 389884688, 428873168, 471760495, 518936559, 570830240, 627913311,
    690704607, 759775136, 835752671, 919327967, 1011260767, 1112386880, 1223623232,
    1345985727, 1480584256, 1628642751, 1791507135, 1970657856, 2167723648, 2384496256,
    2622945920, 2885240448, 3173764736, 3491141248, 3840255616, 4224281216,
]

# (salt, offsets of the two older bytes) for the six triplets of the 5-byte window;
# the salt is already v_table[n] ("fast_b_mapping" in tlsh_impl.cpp).
_TRIPLETS: Tuple[Tuple[int, int, int], ...] = (
    (49, 1, 2), (12, 1, 3), (178, 2, 3), (166, 2, 4), (84, 1, 4), (230, 3, 4))
_CHECKSUM_SALT = 1


def _l_capturing(length: int) -> int:
    idx = bisect.bisect_left(_TOPVAL, length)
    return min(idx, len(_TOPVAL) - 1) & 0xFF


def _swap(b: int) -> int:
    return ((b & 0xF0) >> 4) | ((b & 0x0F) << 4)


def _pair_table(salt: int) -> bytes:
    """t[a*256 + b] = v[v[salt ^ a] ^ b]: the first two Pearson steps."""
    v = V_TABLE
    return bytes(v[v[salt ^ a] ^ b] for a in range(256) for b in range(256))


_PAIR = {s: _pair_table(s) for s in {_CHECKSUM_SALT, *(t[0] for t in _TRIPLETS)}}


def _checksum(data: bytes) -> int:
    """Sequential (each step needs the previous value), so it stays a loop; with
    numpy the per-byte table lookup is done up front."""
    v, pair = V_TABLE, _PAIR[_CHECKSUM_SALT]
    c = 0
    if _np is not None:
        d = _np.frombuffer(data, dtype=_np.uint8)
        idx = (d[4:].astype(_np.int32) << 8) | d[3:-1]
        for x in _np.frombuffer(pair, dtype=_np.uint8)[idx].tobytes():
            c = v[x ^ c]
        return c
    for i in range(4, len(data)):
        c = v[pair[(data[i] << 8) | data[i - 1]] ^ c]
    return c


def _buckets_numpy(data: bytes) -> List[int]:
    assert _np is not None
    d = _np.frombuffer(data, dtype=_np.uint8)
    n = len(d)
    hi = d[4:].astype(_np.int32) << 8
    shifted = {k: d[4 - k:n - k] for k in (1, 2, 3, 4)}
    v = _np.frombuffer(V_TABLE, dtype=_np.uint8)
    counts = _np.zeros(256, dtype=_np.int64)
    for salt, a, b in _TRIPLETS:
        pair = _np.frombuffer(_PAIR[salt], dtype=_np.uint8)
        idx = v[pair[hi | shifted[a]] ^ shifted[b]]
        counts += _np.bincount(idx, minlength=256)
    return [int(x) for x in counts[:EFF_BUCKETS]]


def _buckets_python(data: bytes) -> List[int]:
    v = V_TABLE
    counts = [0] * 256
    tables = [(_PAIR[s], a, b) for s, a, b in _TRIPLETS]
    for i in range(4, len(data)):
        hi = data[i] << 8
        for pair, a, b in tables:
            counts[v[pair[hi | data[i - a]] ^ data[i - b]]] += 1
    return counts[:EFF_BUCKETS]


def hash(data: bytes) -> str:  # same name as python-tlsh
    """T1 digest of `data`, or "TNULL" when it is too short or too uniform."""
    data = bytes(data)
    if _np is None and len(data) > PURE_PYTHON_LIMIT:
        data = data[:PURE_PYTHON_LIMIT]
    if len(data) < MIN_DATA_LENGTH:
        return NULL
    buckets = _buckets_numpy(data) if _np is not None else _buckets_python(data)
    ordered = sorted(buckets)
    q1, q2, q3 = ordered[EFF_BUCKETS // 4 - 1], ordered[EFF_BUCKETS // 2 - 1], ordered[EFF_BUCKETS - EFF_BUCKETS // 4 - 1]
    if q3 == 0 or sum(1 for b in buckets if b > 0) <= 4 * CODE_SIZE // 2:
        return NULL
    code = []
    for i in range(CODE_SIZE):
        h = 0
        for j in range(4):
            k = buckets[4 * i + j]
            if q3 < k:
                h += 3 << (j * 2)
            elif q2 < k:
                h += 2 << (j * 2)
            elif q1 < k:
                h += 1 << (j * 2)
        code.append(h)
    q1_ratio = int(float(q1 * 100) / float(q3)) % 16
    q2_ratio = int(float(q2 * 100) / float(q3)) % 16
    qb = (q2_ratio << 4) | q1_ratio                 # Q1ratio is the low nibble
    out = bytes([_swap(_checksum(data)), _swap(_l_capturing(len(data))), _swap(qb)]
                + code[::-1])
    return "T1" + out.hex().upper()


def _parse(digest: str) -> Optional[Tuple[int, int, int, int, bytes]]:
    s = digest[2:] if digest[:2] in ("T1", "t1") else digest
    if len(s) != 70:
        return None
    raw = bytes.fromhex(s)
    qb = _swap(raw[2])
    return _swap(raw[0]), _swap(raw[1]), qb & 0x0F, qb >> 4, raw[3:][::-1]


def _mod_diff(x: int, y: int, r: int) -> int:
    d = abs(x - y)
    return min(d, r - d)


def _byte_diff(x: int, y: int) -> int:
    diff = 0
    for _ in range(4):
        d = abs((x & 3) - (y & 3))
        diff += 6 if d == 3 else d
        x >>= 2
        y >>= 2
    return diff


_BYTE_DIFF = [bytes(_byte_diff(x, y) for y in range(256)) for x in range(256)]


def diff(a: str, b: str) -> int:
    """TLSH distance (with the length term), as python-tlsh's diff()."""
    pa, pb = _parse(a), _parse(b)
    if pa is None or pb is None:
        raise ValueError("not a TLSH digest")
    ca, la, q1a, q2a, code_a = pa
    cb, lb, q1b, q2b, code_b = pb
    ldiff = _mod_diff(la, lb, 256)
    total = ldiff if ldiff <= 1 else ldiff * 12
    for qa, qb in ((q1a, q1b), (q2a, q2b)):
        qd = _mod_diff(qa, qb, 16)
        total += qd if qd <= 1 else (qd - 1) * 12
    if ca != cb:
        total += 1
    total += sum(_BYTE_DIFF[x][y] for x, y in zip(code_a, code_b))
    return total
