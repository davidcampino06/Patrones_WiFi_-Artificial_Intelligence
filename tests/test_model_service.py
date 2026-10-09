import pytest

from app.model_service import AnomalyDetectionService, generate_baseline
from app.schemas import AnalysisRequest, Severity
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
