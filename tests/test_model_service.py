import joblib
import pytest

from app import scenarios
from app.diagnosis import AnomalyType
from app.model_service import MODEL_VERSION, AnomalyDetectionService, generate_baseline
from app.schemas import AnalysisRequest, MeasurementInput, Severity
from tests.conftest import DEGRADED, NORMAL


@pytest.fixture(scope="module")
def service():
    return AnomalyDetectionService.train(generate_baseline())


def request(*measurements):
    return AnalysisRequest(network_id=1, simulated_data=True, measurements=list(measurements))


def test_normal_measurement_is_not_anomalous(service):
    result = service.detect(request(NORMAL))

    assert not result.anomaly_detected
    assert result.severity == Severity.NONE
    assert result.recommendation is None


def test_degraded_measurement_is_anomalous_with_explanation(service):
    result = service.detect(request(NORMAL, NORMAL, DEGRADED))

    assert result.anomaly_detected
    assert result.severity in (Severity.MEDIUM, Severity.HIGH)
    assert "packet_loss" in result.contributing_features
    assert result.recommendation
    assert result.sample_size == 3


def test_score_is_bounded(service):
    result = service.detect(request(DEGRADED))

    assert 0 <= result.anomaly_score <= 1


def test_model_is_persisted_and_reloaded(tmp_path):
    path = tmp_path / "model.joblib"

    first = AnomalyDetectionService.load_or_train(str(path))
    second = AnomalyDetectionService.load_or_train(str(path))

    assert path.exists()
    assert first.threshold == second.threshold


@pytest.mark.parametrize("fault", scenarios.FAULT_TYPES)
def test_clear_fault_is_detected_and_diagnosed(service, fault):
    healthy = generate_baseline().median()
    degraded = scenarios.degrade(healthy, fault, intensity=1.0)
    sample = MeasurementInput(**{f: int(v) if f in ("connected_devices", "packet_count") else float(v)
                                 for f, v in degraded.items()})

    result = service.detect(request(sample))

    assert result.anomaly_detected
    assert result.anomaly_type == AnomalyType(fault)
    assert result.diagnosis.startswith("Causa probable")


def test_feature_deviations_cover_every_feature(service):
    result = service.detect(request(NORMAL, DEGRADED))

    assert len(result.feature_deviations) == 8
    assert result.feature_deviations["signal_strength"] > 0  # weaker signal is worse, so positive


def test_model_from_another_version_is_retrained(tmp_path):
    path = tmp_path / "model.joblib"
    AnomalyDetectionService.load_or_train(str(path))
    state = joblib.load(path)
    joblib.dump({**state, "version": "isolation-forest-0.9"}, path)

    AnomalyDetectionService.load_or_train(str(path))

    assert joblib.load(path)["version"] == MODEL_VERSION
