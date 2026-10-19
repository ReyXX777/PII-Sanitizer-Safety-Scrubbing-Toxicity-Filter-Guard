"""Pydantic schemas defining the public boundaries of the pipeline."""
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field


class GuardRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    text: str
    request_id: str | None = None


class Finding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    entity_type: str
    start: int = Field(ge=0)
    end: int = Field(gt=0)
    score: float = Field(ge=0.0, le=1.0)
    detector: str = "presidio"


class ToxicityResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal["disabled", "not_detected", "detected", "error"] = "disabled"
    score: float | None = Field(default=None, ge=0.0, le=1.0)
    spans: list[tuple[int, int]] = Field(default_factory=list)
    action: str = "none"
    message: str | None = None


class GuardResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    request_id: str | None = None
    input_length: int = Field(ge=0)
    output_text: str
    pii_findings: list[Finding] = Field(default_factory=list)
    toxicity: ToxicityResult = Field(default_factory=ToxicityResult)
    pii_redaction_count: int = Field(ge=0)
    changed: bool
    warnings: list[str] = Field(default_factory=list)
