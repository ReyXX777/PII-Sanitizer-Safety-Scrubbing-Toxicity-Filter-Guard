"""Presidio-backed PII detection and custom recognizer registration."""
from presidio_analyzer import AnalyzerEngine
from presidio_analyzer.nlp_engine import NlpEngineProvider

from ..config import PIISettings
from ..schemas import Finding
from .checksums import luhn_valid
from .recognizers import build_custom_recognizers


class PIIDetector:
    def __init__(self, settings: PIISettings):
        self.settings = settings
        # Use Presidio's default NLP engine configuration; install the spaCy model
        # documented in README for contextual NER.
        self.engine = AnalyzerEngine()
        if settings.enable_custom_recognizers:
            registry = self.engine.registry
            for recognizer in build_custom_recognizers():
                registry.add_recognizer(recognizer)

    def detect(self, text: str) -> list[Finding]:
        if not text:
            return []
        results = self.engine.analyze(
            text=text,
            language=self.settings.language,
            entities=self.settings.entities,
            score_threshold=self.settings.score_threshold,
        )
        findings: list[Finding] = []
        for result in results:
            start, end = int(result.start), int(result.end)
            if start < 0 or end > len(text) or start >= end:
                continue
            snippet = text[start:end]
            if (
                result.entity_type == "CREDIT_CARD"
                and self.settings.validate_credit_cards_with_luhn
                and not luhn_valid(snippet)
            ):
                continue
            findings.append(Finding(
                entity_type=result.entity_type,
                start=start,
                end=end,
                score=float(result.score),
                detector="presidio",
            ))
        return self._deduplicate(findings)

    @staticmethod
    def _deduplicate(findings: list[Finding]) -> list[Finding]:
        unique: dict[tuple[str, int, int], Finding] = {}
        for finding in findings:
            key = (finding.entity_type, finding.start, finding.end)
            if key not in unique or finding.score > unique[key].score:
                unique[key] = finding
        return sorted(unique.values(), key=lambda f: (f.start, f.end, f.entity_type))
