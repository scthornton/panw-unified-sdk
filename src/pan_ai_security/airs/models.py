"""AIRS-specific data models."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class AIRSScanRequest:
    """Request payload for an AIRS text scan."""

    prompt: str
    response: str = ""
    ai_profile: str = ""
    metadata: dict[str, str] = field(default_factory=dict)
    tr_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {"prompt": self.prompt}
        if self.response:
            result["response"] = self.response
        if self.ai_profile:
            result["ai_profile"] = self.ai_profile
        if self.metadata:
            result["metadata"] = self.metadata
        if self.tr_id:
            result["tr_id"] = self.tr_id
        return result
