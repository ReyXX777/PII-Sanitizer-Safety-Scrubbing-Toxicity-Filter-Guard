"""Validated configuration for the guard."""
from pydantic import BaseModel, ConfigDict, Field


class PIISettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    language: str = "en"
    entities: list[str] = Field(default_factory=lambda: [
        "EMAIL_ADDRESS",
        "PHONE_NUMBER",
        "IP_ADDRESS",
        "PERSON",
        "LOCATION",
        "CREDIT_CARD",
        "US_SSN",
    ])
    score_threshold: float = Field(default=0.45, ge=0.0, le=1.0)
    mask: str = "[REDACTED]"
    enable_custom_recognizers: bool = True
    validate_credit_cards_with_luhn: bool = True


class ToxicitySettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = False
    threshold: float = Field(default=0.75, ge=0.0, le=1.0)
    mask: str = "[TOXIC]"
    action: str = Field(default="mask_spans", pattern="^(mask_spans|mask_document|report_only)$")


class GuardSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    pii: PIISettings = Field(default_factory=PIISettings)
    toxicity: ToxicitySettings = Field(default_factory=ToxicitySettings)
    collapse_adjacent_redactions: bool = False
