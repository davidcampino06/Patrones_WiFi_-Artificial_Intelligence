"""Contract of POST /api/v1/quality/score (JSON in camelCase, like the rest of the service)."""
from enum import Enum

from pydantic import Field, model_validator

from app.schemas import CamelModel, InputModel


class QualityGrade(str, Enum):
    EXCELLENT = "EXCELLENT"
    GOOD = "GOOD"
    FAIR = "FAIR"
    POOR = "POOR"


class MetricStatus(str, Enum):
    GOOD = "GOOD"
    FAIR = "FAIR"
    POOR = "POOR"


class QualityRequest(InputModel):
    latency_ms: float = Field(ge=0, le=10_000)
    jitter_ms: float = Field(ge=0, le=10_000)
    packet_loss_pct: float | None = Field(default=None, ge=0, le=100)
    download_mbps: float | None = Field(default=None, ge=0, le=10_000)
    upload_mbps: float | None = Field(default=None, ge=0, le=10_000)
    contracted_mbps: float | None = Field(default=None, gt=0, le=10_000)
    signal_dbm: float | None = Field(default=None, ge=-100, le=0)

    @model_validator(mode="after")
    def contracted_needs_download(self) -> "QualityRequest":
        if self.contracted_mbps is not None and self.download_mbps is None:
            raise ValueError("contractedMbps requires downloadMbps")
        return self


class MetricResult(CamelModel):
    metric: str
    label: str
    value: float
    unit: str
    score: int = Field(ge=0, le=100)
    status: MetricStatus


class ActivityResult(CamelModel):
    activity: str
    label: str
    suitable: bool | None = Field(description="None when a metric the activity needs was not measured")


class QualityResponse(CamelModel):
    score: int = Field(ge=0, le=100)
    grade: QualityGrade
    grade_label: str
    metrics: list[MetricResult]
    activities: list[ActivityResult]
    tips: list[str]
    contracted_ratio: float | None = Field(description="Measured download / contracted speed")
    model_version: str
