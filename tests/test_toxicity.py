from pii_toxicity_guard.config import ToxicitySettings
from pii_toxicity_guard.toxicity.base import ToxicityAssessment
from pii_toxicity_guard.toxicity.pipeline import ToxicityPipeline


class FixedClassifier:
    def __init__(self, score, spans=None):
        self.score = score
        self.spans = spans or []

    def assess(self, text):
        return ToxicityAssessment(score=self.score, spans=self.spans)


def test_disabled_toxicity_does_not_modify_text():
    pipeline = ToxicityPipeline(ToxicitySettings(enabled=False), FixedClassifier(0.99))
    output, result = pipeline.process("sample text")
    assert output == "sample text"
    assert result.status == "disabled"


def test_document_score_falls_back_to_masking_document():
    settings = ToxicitySettings(enabled=True, threshold=0.5, action="mask_spans")
    pipeline = ToxicityPipeline(settings, FixedClassifier(0.9))
    output, result = pipeline.process("harmful document")
    assert output == "[TOXIC]"
    assert result.action == "mask_document_fallback"


def test_span_masking_uses_original_offsets_and_reverse_order():
    settings = ToxicitySettings(enabled=True, threshold=0.5, action="mask_spans")
    pipeline = ToxicityPipeline(settings, FixedClassifier(0.9, [(0, 3), (8, 11)]))
    output, result = pipeline.process("bad text bad")
    assert output == "[TOXIC] text [TOXIC]"
    assert result.action == "mask_spans"
