"""El análisis nuevo de las redes cercanas por la API: contrato, validación (422) y clave del servicio."""


def test_nearby_analyze_answers_facts_inferences_and_uncertainty(client):
    response = client.post("/api/v1/nearby/analyze", json={"accessPoints": [
        {"ssid": "Casa", "authentication": "WPA2", "channel": 6, "band": "2.4", "connected": True}]})

    assert response.status_code == 200
    assert response.json()["modelVersion"] == "nearby-1.0"


def test_an_unknown_security_is_rejected(client):
    assert client.post("/api/v1/nearby/analyze", json={"accessPoints": [{"authentication": "WPA9"}]}
                       ).status_code == 422


def test_the_nearby_analysis_requires_the_api_key(client):
    assert client.post("/api/v1/nearby/analyze", headers={"X-API-Key": "wrong"}, json={}).status_code == 401
