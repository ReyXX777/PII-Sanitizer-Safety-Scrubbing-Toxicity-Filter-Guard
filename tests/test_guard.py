from pii_toxicity_guard.config import GuardSettings
from pii_toxicity_guard.guard import Guard
from pii_toxicity_guard.schemas import Finding
from pii_toxicity_guard.toxicity.base import NoOpToxicityFilter


class FakeDetector:
    def detect(self, text):
        start = text.find("alice@example.com")
        if start < 0:
            return []
        return [Finding(entity_type="EMAIL_ADDRESS", start=start,
                        end=start + len("alice@example.com"), score=0.99)]


class FakeRedactor:
    def redact(self, text, findings):
        for finding in sorted(findings, key=lambda f: f.start, reverse=True):
            text = text[:finding.start] + "[REDACTED]" + text[finding.end:]
        return text


def test_guard_uses_immutable_source_offsets():
    guard = Guard(
        settings=GuardSettings(),
        detector=FakeDetector(),
        redactor=FakeRedactor(),
        toxicity_filter=NoOpToxicityFilter(),
    )
    result = guard.process("Contact alice@example.com now.")
    assert result.output_text == "Contact [REDACTED] now."
    assert result.changed
    assert result.pii_redaction_count == 1


def test_pipe_yields_incrementally():
    guard = Guard(
        settings=GuardSettings(),
        detector=FakeDetector(),
        redactor=FakeRedactor(),
    )
    results = list(guard.pipe(["nothing here", "alice@example.com"], batch_size=2))
    assert len(results) == 2
    assert results[1].output_text == "[REDACTED]"
