import importlib.util
import json
from pathlib import Path

from app.main import MAX_BODY_BYTES

LOAD = Path(__file__).resolve().parent.parent / "load-tests" / "carga_ia.py"


def load_script():
    spec = importlib.util.spec_from_file_location("carga_ia", LOAD)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_a_body_bigger_than_the_limit_is_refused_before_reading_it(client):
    response = client.post("/api/v1/quality/score", content=b"x" * (MAX_BODY_BYTES + 1),
                           headers={"Content-Type": "application/json"})

    assert response.status_code == 413
    assert response.json()["detail"] == "La solicitud es demasiado grande."


def test_normal_requests_are_not_affected(client):
    response = client.post("/api/v1/quality/score", json={"latencyMs": 35, "jitterMs": 6})
    assert response.status_code == 200


def test_percentile_is_the_value_a_person_reads_in_the_sorted_list():
    carga = load_script()
    values = [float(v) for v in range(1, 101)]
    assert carga.percentile(values, 50) == 50
    assert carga.percentile(values, 95) == 95
    assert carga.percentile(values, 99) == 99
    assert carga.percentile([7.0], 95) == 7
    assert carga.percentile([], 95) == 0


def test_the_load_payloads_are_valid_requests_for_the_service(client):
    carga = load_script()
    rng = __import__("random").Random(1)
    for name, path, body in carga.payloads(rng):
        response = client.post(path, content=json.dumps(body), headers={"Content-Type": "application/json"})
        assert response.status_code == 200, (name, response.text)
