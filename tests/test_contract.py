"""Contract with the backend (WiFiSense-backend): the JSON examples in tests/contracts are the same files the backend
tests use in src/test/resources/contracts. The backend checks that it sends exactly these requests and can read these
answers; this side checks that it accepts the requests and still answers every field of the examples, with the same
type. If a field is renamed or removed here, this test fails before the backend breaks in production."""
import json
from pathlib import Path

import pytest

CONTRACTS = Path(__file__).parent / "contracts"
ENDPOINTS = [("anomalies", "/api/v1/anomalies/detect"), ("quality", "/api/v1/quality/score"),
             ("security", "/api/v1/security/assess"), ("channel", "/api/v1/channel/recommend")]


def load(name: str):
    return json.loads((CONTRACTS / name).read_text(encoding="utf-8"))


def shape(value):
    """The structure of a JSON value without its data: field names and types, recursively (lists by their first item)."""
    if isinstance(value, dict):
        return {key: shape(item) for key, item in value.items()}
    if isinstance(value, list):
        return [shape(value[0])] if value else []
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, (int, float)):
        return "number"
    return "string" if isinstance(value, str) else "null"


def missing(expected, actual, path="$") -> list[str]:
    """Fields of the example that the real answer lacks or answers with another type (null may be either)."""
    if expected == "null" or actual == "null":
        return []
    if isinstance(expected, dict):
        if not isinstance(actual, dict):
            return [f"{path} ya no es un objeto"]
        return [problem for key, item in expected.items()
                for problem in (missing(item, actual[key], f"{path}.{key}") if key in actual else [f"falta {path}.{key}"])]
    if isinstance(expected, list):
        if not isinstance(actual, list):
            return [f"{path} ya no es una lista"]
        return missing(expected[0], actual[0], f"{path}[0]") if expected and actual else []
    return [] if expected == actual else [f"{path} era {expected} y ahora es {actual}"]


@pytest.mark.parametrize("name,path", ENDPOINTS)
def test_the_service_accepts_what_the_backend_sends_and_answers_what_it_reads(client, name, path):
    response = client.post(path, json=load(f"{name}_request.json"))

    assert response.status_code == 200, response.text
    assert missing(shape(load(f"{name}_response.json")), shape(response.json())) == []


def test_the_model_description_keeps_the_fields_the_backend_reads(client):
    response = client.get("/api/v1/model")

    assert response.status_code == 200
    assert missing(shape(load("model_response.json")), shape(response.json())) == []


def test_the_comparison_detects_a_renamed_field():
    example = shape({"score": 80, "findings": [{"severity": "HIGH"}]})

    assert missing(example, shape({"score": 80, "findings": [{"level": "HIGH"}]})) == ["falta $.findings[0].severity"]
    assert missing(example, shape({"score": "80", "findings": []})) == ["$.score era number y ahora es string"]
