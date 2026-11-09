"""Lectura de una captura: hechos contados aparte de inferencias con su confianza, sin afirmar nunca más de lo que
los números muestran."""
import pytest

from app import traffic
from app.schemas_findings import Level
from app.schemas_traffic import TrafficRequest


def request(**changes) -> TrafficRequest:
    body = {"durationSeconds": 30, "packets": 1200, "bytes": 840000, "droppedByTool": 0, "malformed": 0,
            "broadcast": 40, "multicast": 80, "remoteHosts": 20, "stopReason": "DURATION",
            "protocols": [{"protocol": "HTTPS", "packets": 1000, "bytes": 800000},
                          {"protocol": "DNS", "packets": 200, "bytes": 40000}],
            "intervals": [{"second": s, "packets": 40, "bytes": 28000} for s in range(30)]}
    body.update(changes)
    return TrafficRequest.model_validate(body)


def codes(items):
    return [item.code for item in items]


def test_an_ordinary_capture_gives_facts_and_no_alarm():
    answer = traffic.analyze(request())

    assert codes(answer.facts) == ["TRAFFIC_VOLUME", "TOP_PROTOCOLS"]
    assert answer.inferences == []
    assert "40.0 paquetes por segundo" in answer.facts[0].evidence
    assert "HTTPS 83 %" in answer.facts[1].evidence


def test_the_three_losses_are_never_mixed():
    answer = traffic.analyze(request(droppedByTool=60, connectionLossPct=3.5))

    dropped = next(f for f in answer.facts if f.code == "TOOL_DROPPED")
    connection = next(f for f in answer.facts if f.code == "CONNECTION_LOSS")
    assert "no de la red" in dropped.evidence and dropped.severity == Level.WARNING
    assert "otra medida" in connection.evidence and connection.severity == Level.WARNING
    assert all(i.code not in ("TOOL_DROPPED", "CONNECTION_LOSS") for i in answer.inferences)


def test_an_unknown_drop_count_is_said_in_the_uncertainty_not_invented_as_zero():
    answer = traffic.analyze(request(droppedByTool=None))

    assert "TOOL_DROPPED" not in codes(answer.facts)
    assert "no informó si perdió paquetes" in answer.uncertainty
