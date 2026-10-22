"""Loads detectors/indicators.yaml: scoring weights, category caps and the labels
of every indicator, from one file (see that file's header)."""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional, Union

import yaml

REGISTRY_PATH = Path(__file__).with_name("indicators.yaml")


@dataclass
class Registry:
    version: str
    caps: Dict[str, float]
    max_raw: float
    semantic_only_max: int
    weights: Dict[str, Any]
    indicators: Dict[str, Dict[str, Any]] = field(default_factory=dict)

    def label(self, indicator: str) -> str:
        base = indicator.rsplit(":", 1)[-1]
        entry = self.indicators.get(base) or {}
        return entry.get("label") or base.replace("_", " ")

    def with_overrides(self, overrides: Optional[Dict[str, Any]]) -> Registry:
        """A copy with some weights replaced (e.g. a reviewed calibration result)."""
        reg = copy.deepcopy(self)
        for name, value in (overrides or {}).items():
            if name not in reg.weights:
                raise KeyError(f"unknown weight {name!r} in override")
            if isinstance(reg.weights[name], dict) != isinstance(value, dict):
                raise TypeError(f"weight {name!r} must keep its shape")
            reg.weights[name] = value
        return reg


def load_registry(path: Union[str, Path] = REGISTRY_PATH) -> Registry:
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    return Registry(version=str(data["version"]), caps={k: float(v) for k, v in data["caps"].items()},
                    max_raw=float(data["max_raw"]), semantic_only_max=int(data["semantic_only_max"]),
                    weights=data["weights"], indicators=data.get("indicators") or {})


def load_overrides(path: Optional[Union[str, Path]]) -> Dict[str, Any]:
    """`weights:` section of an override file ({} when there is none)."""
    if not path or not Path(path).is_file():
        return {}
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    return dict(data.get("weights") or {})


REGISTRY = load_registry()
