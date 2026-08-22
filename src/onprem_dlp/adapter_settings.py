"""Uniform settings value passed to every configuration-bound adapter."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any


@dataclass(frozen=True, slots=True)
class AdapterSettings:
    values: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "values", MappingProxyType(dict(self.values)))

    def get(self, name: str, default: Any = None) -> Any:
        return self.values.get(name, default)

    def require(self, name: str) -> Any:
        value = self.values.get(name)
        if value in (None, ""):
            raise ValueError(f"adapter setting {name!r} is required")
        return value
