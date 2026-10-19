"""Deterministic redaction operations applied to immutable source offsets."""
from presidio_analyzer import RecognizerResult
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig

from ..config import PIISettings
from ..schemas import Finding


class PIIRedactor:
    def __init__(self, settings: PIISettings):
        self.settings = settings
        self.engine = AnonymizerEngine()

    def redact(self, text: str, findings: list[Finding]) -> str:
        if not findings:
            return text
        results = [
            RecognizerResult(
                entity_type=f.entity_type,
                start=f.start,
                end=f.end,
                score=f.score,
            )
            for f in findings
            if 0 <= f.start < f.end <= len(text)
        ]
        if not results:
            return text
        operator = OperatorConfig("replace", {"new_value": self.settings.mask})
        operators = {finding.entity_type: operator for finding in findings}
        output = self.engine.anonymize(
            text=text,
            analyzer_results=results,
            operators=operators,
        )
        return output.text
