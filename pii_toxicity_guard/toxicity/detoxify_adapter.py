"""Optional Detoxify document classifier adapter.

Detoxify provides document-level scores, not reliable character-level toxic spans.
Therefore this adapter returns no spans and lets policy choose document masking,
report-only behavior, or no action. Install with: pip install -e '.[toxicity]'.
"""
from .base import ToxicityAssessment


class DetoxifyAdapter:
    def __init__(self, model_name: str = "original"):
        try:
            from detoxify import Detoxify
        except ImportError as exc:
            raise RuntimeError(
                "Detoxify is optional. Install it with `pip install -e '.[toxicity]'`."
            ) from exc
        self.model = Detoxify(model_name)

    def assess(self, text: str) -> ToxicityAssessment:
        if not text.strip():
            return ToxicityAssessment(score=0.0, spans=[])
        prediction = self.model.predict(text)
        # Detoxify's toxicity output is typically a float or scalar tensor.
        value = prediction.get("toxicity", 0.0)
        if hasattr(value, "item"):
            value = value.item()
        return ToxicityAssessment(score=float(value), spans=[], message=(
            "Document-level classifier; no character spans are provided."
        ))
