"""Top-level orchestration with explicit PII and toxicity stages."""
from collections.abc import Iterable, Iterator

from .config import GuardSettings
from .pii.detector import PIIDetector
from .pii.redactor import PIIRedactor
from .schemas import GuardRequest, GuardResult
from .toxicity.base import ToxicityFilter, NoOpToxicityFilter
from .toxicity.pipeline import ToxicityPipeline


class Guard:
    def __init__(
        self,
        settings: GuardSettings | None = None,
        toxicity_filter: ToxicityFilter | None = None,
        detector: PIIDetector | None = None,
        redactor: PIIRedactor | None = None,
    ):
        self.settings = settings or GuardSettings()
        self.detector = detector or PIIDetector(self.settings.pii)
        self.redactor = redactor or PIIRedactor(self.settings.pii)
        self.toxicity = ToxicityPipeline(
            self.settings.toxicity,
            toxicity_filter or NoOpToxicityFilter(),
        )

    def process(self, text_or_request: str | GuardRequest) -> GuardResult:
        request = (
            text_or_request if isinstance(text_or_request, GuardRequest)
            else GuardRequest(text=text_or_request)
        )
        original = request.text

        # Detect all PII against the same immutable source string.
        findings = self.detector.detect(original)
        pii_redacted = self.redactor.redact(original, findings)

        # Toxicity is intentionally downstream and independent of PII recognizers.
        final_text, toxicity_result = self.toxicity.process(pii_redacted)

        warnings: list[str] = []
        if not self.settings.toxicity.enabled:
            warnings.append("Toxicity analysis was disabled; output is not certified toxicity-free.")
        return GuardResult(
            request_id=request.request_id,
            input_length=len(original),
            output_text=final_text,
            pii_findings=findings,
            toxicity=toxicity_result,
            pii_redaction_count=len(findings),
            changed=(final_text != original),
            warnings=warnings,
        )

    def pipe(self, documents: Iterable[str], *, batch_size: int = 32) -> Iterator[GuardResult]:
        """Yield results incrementally. batch_size validates the intended chunk size.

        Presidio inference is synchronous; this generator bounds result accumulation.
        For parallel execution, add a controlled executor after benchmarking model
        thread-safety and memory usage.
        """
        if batch_size < 1:
            raise ValueError("batch_size must be >= 1")
        for document in documents:
            yield self.process(document)

    def process_batch(self, documents: Iterable[str], *, batch_size: int = 32) -> list[GuardResult]:
        return list(self.pipe(documents, batch_size=batch_size))
