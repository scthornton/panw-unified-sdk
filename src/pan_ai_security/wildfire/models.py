"""WildFire-specific data models."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class SubmitResult:
    """Result from submitting a file to WildFire."""

    sha256: str
    md5: str
    filename: str
    file_type: str
    size: int
    url: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "sha256": self.sha256,
            "md5": self.md5,
            "filename": self.filename,
            "file_type": self.file_type,
            "size": self.size,
            "url": self.url,
        }


@dataclass
class VerdictResult:
    """Raw verdict from WildFire before normalization."""

    sha256: str
    verdict_code: int
    md5: str = ""

    @property
    def is_pending(self) -> bool:
        return self.verdict_code == -100

    @property
    def is_benign(self) -> bool:
        return self.verdict_code == 0

    @property
    def is_malicious(self) -> bool:
        return self.verdict_code == 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "sha256": self.sha256,
            "verdict_code": self.verdict_code,
            "md5": self.md5,
            "is_pending": self.is_pending,
        }
