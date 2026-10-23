"""Invalid, incomplete and extreme measurements: the service answers 422 with the reason (never 500) or, for extreme
but valid values, a normal result that flags the anomaly."""
import pytest

from tests.conftest import NORMAL

DETECT = "/api/v1/anomalies/detect"
HEADERS = {"Content-Type": "application/json"}


@pytest.mark.parametrize("value", ["NaN", "Infinity", "-Infinity", '"NaN"'])
def test_a_measurement_that_is_not_a_number_is_rejected_with_422(client, value):
    body = '{"networkId": 1, "simulatedData": false, "measurements": [{"latency": %s, "jitter": 4, "packetLoss": 0}]}' % value

    response = client.post(DETECT, content=body, headers=HEADERS)

    assert response.status_code == 422
    assert response.json()["detail"][0]["loc"] == ["body", "measurements", 0, "latency"]


def test_quality_with_nan_is_rejected_too(client):
    response = client.post("/api/v1/quality/score", content='{"latencyMs": NaN, "jitterMs": 3}', headers=HEADERS)

    assert response.status_code == 422


@pytest.mark.parametrize("payload, field", [
    ({"networkId": 1, "simulatedData": False, "measurements": []}, "measurements"),
    ({"networkId": 1, "simulatedData": False, "measurements": [{"jitter": 4, "packetLoss": 0}]}, "latency"),
    ({"networkId": 1, "simulatedData": False, "measurements": [{**NORMAL, "packetLoss": 140}]}, "packetLoss"),
    ({"networkId": 1, "simulatedData": False, "measurements": [{**NORMAL, "signalStrength": 20}]}, "signalStrength"),
    ({"networkId": 1, "measurements": [NORMAL]}, "simulatedData"),
])
def test_incomplete_or_out_of_range_measurements_are_rejected(client, payload, field):
    response = client.post(DETECT, json=payload)

    assert response.status_code == 422
    assert field in str(response.json()["detail"])


def test_missing_optional_metrics_are_filled_and_reported(client):
    response = client.post(DETECT, json={"networkId": 1, "simulatedData": False,
                                         "measurements": [{"latency": 25, "jitter": 3, "packetLoss": 0}]})

    body = response.json()
    assert response.status_code == 200
    assert {"bandwidth", "signal_strength", "traffic_volume", "packet_count"} <= set(body["imputedFeatures"])


def test_extreme_but_valid_values_are_an_anomaly_not_an_error(client):
    worst = {"latency": 10000, "jitter": 10000, "packetLoss": 100, "bandwidth": 0, "signalStrength": -100,
             "trafficVolume": 0, "connectedDevices": 0, "packetCount": 0}

    response = client.post(DETECT, json={"networkId": 1, "simulatedData": False, "measurements": [NORMAL, worst]})

    body = response.json()
    assert response.status_code == 200
    assert body["anomalyDetected"] is True
    assert body["severity"] == "HIGH"
    assert 0 <= body["anomalyScore"] <= 1


def test_a_training_seed_outside_the_range_of_scikit_learn_is_rejected(client):
    samples = [{"latency": 20 + i % 7} for i in range(300)]

    response = client.post("/api/v1/model/train", json={"version": "real-prueba-1", "seed": -1, "samples": samples})

    assert response.status_code == 422
    assert "seed" in str(response.json()["detail"])
