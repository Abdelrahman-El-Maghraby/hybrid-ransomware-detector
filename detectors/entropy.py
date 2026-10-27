"""Shannon entropy of bytes - one implementation shared by the integrity, ELF and
ML layers (each had its own copy, and it was a hot path: every 1 KB window)."""

import math
from collections import Counter

try:                                    # 15x faster byte counting on large inputs
    import numpy as _np
except ImportError:                     # pragma: no cover - numpy is optional
    _np = None  # type: ignore[assignment]

_NUMPY_FROM = 64 * 1024                 # below this, Counter is as fast

_TABLE_SIZE = 8193
_C_LOG2_C = [0.0] + [c * math.log2(c) for c in range(1, _TABLE_SIZE)]   # c*log2(c)


def shannon_entropy(data: bytes) -> float:
    """Bits per byte, 0.0 - 8.0. Uses H = log2(n) - sum(c*log2(c)) / n: the same
    value as -sum(p*log2(p)) with one table lookup per distinct byte."""
    n = len(data)
    if n == 0:
        return 0.0
    if _np is not None and n >= _NUMPY_FROM:
        hist = _np.bincount(_np.frombuffer(data, dtype=_np.uint8), minlength=256)
        counts = [int(c) for c in hist if c]
    else:
        counts = list(Counter(data).values())
    if len(counts) == 1:
        return 0.0
    table = _C_LOG2_C
    s = sum(table[c] if c < _TABLE_SIZE else c * math.log2(c) for c in counts)
    return min(8.0, max(0.0, math.log2(n) - s / n))
