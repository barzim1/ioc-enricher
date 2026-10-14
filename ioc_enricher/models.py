from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

from .indicators import Indicator


@dataclass
class ProviderResult:
    provider: str
    ok: bool = True
    not_found: bool = False
    malicious: int = 0
    suspicious: int = 0
    total_engines: int = 0
    abuse_confidence: Optional[int] = None
    details: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    cached: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ProviderResult":
        return cls(**data)

    @property
    def has_data(self) -> bool:
        return self.ok and not self.not_found


@dataclass
class Verdict:
    score: int
    label: str
    reasons: List[str] = field(default_factory=list)
    recommendation: str = ""


@dataclass
class Enrichment:
    indicator: Indicator
    results: List[ProviderResult]
    verdict: Verdict
