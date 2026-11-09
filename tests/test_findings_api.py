"""Los dos análisis nuevos por la API: contrato, validación (422) y clave del servicio."""


def test_traffic_analyze_answers_facts_inferences_and_uncertainty(client):
    response = client.post("/api/v1/traffic/analyze", json={"durationSeconds": 20, "packets": 0, "bytes": 0})

    body = response.json()
    assert response.status_code == 200
    assert body["facts"][0]["code"] == "EMPTY_CAPTURE"
    assert body["inferences"] == [] and body["uncertainty"] and body["modelVersion"] == "traffic-1.0"


def test_nearby_analyze_answers_facts_inferences_and_uncertainty(client):
    response = client.post("/api/v1/nearby/analyze", json={"accessPoints": [
        {"ssid": "Casa", "authentication": "WPA2", "channel": 6, "band": "2.4", "connected": True}]})

    assert response.status_code == 200
    assert response.json()["modelVersion"] == "nearby-1.0"


def test_a_packet_or_an_address_cannot_be_sent_to_the_ai(client):
    for extra in ({"payload": "cGFzc3dvcmQ="}, {"sourceAddresses": ["192.168.1.2"]}):
        response = client.post("/api/v1/traffic/analyze", json={"durationSeconds": 20, "packets": 0, "bytes": 0,
                                                                 **extra})
        assert response.status_code == 200
        assert "192.168" not in response.text and "cGFzc3dvcmQ" not in response.text


def test_invalid_statistics_are_rejected(client):
    for body in ({"durationSeconds": 0, "packets": 1, "bytes": 1},
                 {"durationSeconds": 20, "packets": -1, "bytes": 0},
                 {"durationSeconds": 20, "packets": 1, "bytes": 1, "protocols": [
                     {"protocol": "TELNET; DROP TABLE", "packets": 1, "bytes": 1}]},
                 {"durationSeconds": 20, "packets": 1, "bytes": 1, "stopReason": "FOREVER"}):
        assert client.post("/api/v1/traffic/analyze", json=body).status_code == 422
    assert client.post("/api/v1/nearby/analyze", json={"accessPoints": [{"authentication": "WPA9"}]}
                       ).status_code == 422


def test_both_require_the_api_key(client):
    for path in ("/api/v1/traffic/analyze", "/api/v1/nearby/analyze"):
        assert client.post(path, headers={"X-API-Key": "wrong"}, json={}).status_code == 401
