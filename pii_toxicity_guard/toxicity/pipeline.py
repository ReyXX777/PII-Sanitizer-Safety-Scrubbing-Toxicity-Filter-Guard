"""Policy layer for toxicity outcomes; independent of PII detection."""
from ..config import ToxicitySettings
from ..schemas import ToxicityResult
from .base import ToxicityFilter, NoOpToxicityFilter


class ToxicityPipeline:
    def __init__(self, settings: ToxicitySettings, classifier: ToxicityFilter | None = None):
        self.settings = settings
        self.classifier = classifier or NoOpToxicityFilter()

    def process(self, text: str) -> tuple[str, ToxicityResult]:
        if not self.settings.enabled:
            return text, ToxicityResult(status="disabled", action="none",
                                        message="Toxicity filtering is disabled.")
        assessment = self.classifier.assess(text)
        score = assessment.score
        if score is None:
            return text, ToxicityResult(status="not_detected", score=None, action="none",
                                        message=assessment.message or "Classifier returned no score.")
        flagged = score >= self.settings.threshold
        if not flagged:
            return text, ToxicityResult(status="not_detected", score=score, action="none",
                                        message=assessment.message)

        if self.settings.action == "report_only":
            output, action = text, "report_only"
        elif self.settings.action == "mask_document":
            output, action = self.settings.mask, "mask_document"
        else:
            # Only mask spans if a span-capable provider supplied valid offsets.
            valid = sorted(
                {(start, end) for start, end in assessment.spans
                 if 0 <= start < end <= len(text)},
                reverse=True,
            )
            output = text
            for start, end in valid:
                output = output[:start] + self.settings.mask + output[end:]
            if valid:
                action = "mask_spans"
            else:
                # Never claim span masking occurred when the provider only returns a
                # document score. Fail closed for a flagged document by masking it.
                output, action = self.settings.mask, "mask_document_fallback"
        return output, ToxicityResult(
            status="detected", score=score, spans=assessment.spans,
            action=action, message=assessment.message,
        )
