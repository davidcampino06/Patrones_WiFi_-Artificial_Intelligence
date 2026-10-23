from datetime import datetime
from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field
from pydantic.alias_generators import to_camel

from app.diagnosis import AnomalyType


class CamelModel(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)


class InputModel(CamelModel):
    """What a client sends. NaN and infinity are rejected (422): a measurement must be a real number, and an infinite
    latency would pass "greater than or equal to 0" and reach the model."""
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True, allow_inf_nan=False)


class Severity(str, Enum):
    NONE = "NONE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class MeasurementInput(InputModel):
    latency: float = Field(ge=0, description="Latency in ms")
    jitter: float = Field(ge=0, description="Jitter in ms")
    packet_loss: float = Field(ge=0, le=100, description="Packet loss in %")
    bandwidth: float | None = Field(default=None, ge=0, description="Mbps")
    signal_strength: float | None = Field(default=None, ge=-100, le=0, description="RSSI in dBm")
    traffic_volume: float | None = Field(default=None, ge=0, description="MB per interval")
    connected_devices: int | None = Field(default=None, ge=0)
    packet_count: int | None = Field(default=None, ge=0)
    timestamp: datetime | None = None


class AnalysisRequest(InputModel):
    network_id: int
    simulated_data: bool = Field(description="True when measurements come from the simulation data source")
    measurements: list[MeasurementInput] = Field(min_length=1, max_length=1000)


class AnalysisResponse(CamelModel):
    anomaly_detected: bool
    anomaly_score: float = Field(ge=0, le=1)
    severity: Severity
    anomaly_type: AnomalyType = AnomalyType.NONE
    diagnosis: str | None = None
    message: str
    recommendation: str | None
    recommendation_source: Literal["RULES", "CLAUDE"] = "RULES"
    contributing_features: list[str]
    feature_deviations: dict[str, float] = Field(default_factory=dict,
                                                 description="Robust deviation per feature; positive means worse")
    anomalous_samples: int
    sample_size: int
    imputed_features: list[str]
    model_version: str
    simulated_data: bool


class ModelInfo(CamelModel):
    algorithm: str
    model_version: str
    features: list[str]
    threshold: float
    trained_on: str
    recommendation_engine: str
    real_data: bool = False
    trained_samples: int | None = None
    trained_at: str | None = None


class TrainingSample(InputModel):
    """One real measurement of a network (the same metrics the detector uses); only latency is required."""
    latency: float = Field(ge=0, le=10000)
    jitter: float | None = Field(default=None, ge=0, le=10000)
    packet_loss: float | None = Field(default=None, ge=0, le=100)
    bandwidth: float | None = Field(default=None, ge=0, le=100000)
    signal_strength: float | None = Field(default=None, ge=-100, le=0)
    traffic_volume: float | None = Field(default=None, ge=0)
    connected_devices: int | None = Field(default=None, ge=0, le=1024)
    packet_count: int | None = Field(default=None, ge=0)
    timestamp: datetime | None = None


class TrainingRequest(InputModel):
    version: str = Field(pattern=r"^[a-z0-9][a-z0-9.-]{2,39}$")
    samples: list[TrainingSample] = Field(min_length=1, max_length=20000)
    seed: int = Field(default=42, ge=0, le=2**32 - 1)  # scikit-learn accepts seeds in this range
    activate: bool = Field(default=True, description="Replace the model in use if the new one is better")
    restore: bool = Field(default=False, description="Rebuild a model that was already promoted, without evaluating")


class TrainingMetrics(CamelModel):
    precision: float
    recall: float
    f1: float
    false_positive_rate: float


class TrainingResult(CamelModel):
    version: str
    samples: int
    train_samples: int
    test_normal: int
    test_faults: int
    decision: Literal["PROMOTED", "REJECTED", "RESTORED"]
    reason: str
    candidate: TrainingMetrics | None = None
    current: TrainingMetrics | None = None
    current_version: str
    active: bool


class AlgorithmMetrics(CamelModel):
    algorithm: str
    precision: float
    recall: float
    f1: float
    false_positive_rate: float
    roc_auc: float
    average_precision: float
    recall_by_type: dict[str, float]
    fit_ms: float
    predict_us_per_sample: float
    production: bool


class TuningCandidate(CamelModel):
    n_estimators: int
    max_samples: str
    f1: float
    recall: float
    false_positive_rate: float
    best: bool = False


class SensitivityPoint(CamelModel):
    contamination: float
    precision: float
    recall: float
    false_positive_rate: float
    production: bool


class DiagnosisMetrics(CamelModel):
    accuracy: float
    evaluated: int
    confusion: dict[str, dict[str, int]] = Field(description="Real fault -> probable cause given -> count")


class EvaluationReport(CamelModel):
    dataset: str
    train_samples: int
    test_normal: int
    test_anomalies: int
    production_algorithm: str
    model_version: str
    algorithms: list[AlgorithmMetrics]
    tuning: list[TuningCandidate]
    sensitivity: list[SensitivityPoint]
    diagnosis: DiagnosisMetrics
    generated_at: datetime
