"""Toxicity provider interface and no-op implementation."""
from dataclasses import dataclass, field
from typing import Protocol


@dataclass
class ToxicityAssessment:
    score: float | None = None
    spans: list[tuple[int, int]] = field(default_factory=list)
    message: str | None = None


class ToxicityFilter(Protocol):
    def assess(self, text: str) -> ToxicityAssessment:
        """Return a document score and optional character spans."""


class NoOpToxicityFilter:
    """Explicitly disables toxicity analysis; it does not claim text is safe."""

    def assess(self, text: str) -> ToxicityAssessment:
        return ToxicityAssessment(score=None, spans=[], message="Toxicity filtering is disabled.")
