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


def test_a_burst_is_an_inference_with_its_seconds_and_a_confidence():
    intervals = [{"second": s, "packets": 40, "bytes": 28000} for s in range(30)]
    intervals[12] = {"second": 12, "packets": 400, "bytes": 280000}
    answer = traffic.analyze(request(packets=1560, intervals=intervals))

    burst = next(i for i in answer.inferences if i.code == "TRAFFIC_BURST")
    assert "segundos 12" in burst.evidence and "400" in burst.evidence
    assert 0.4 <= burst.confidence <= 0.85
    assert burst.severity == Level.WARNING
    assert "TRAFFIC_BURST" not in codes(answer.facts)


def test_a_steady_capture_has_no_burst_even_with_some_noise():
    intervals = [{"second": s, "packets": 40 + (s % 5), "bytes": 28000} for s in range(30)]

    assert "TRAFFIC_BURST" not in codes(traffic.analyze(request(intervals=intervals)).inferences)


def test_much_arp_is_a_reason_to_look_never_an_accusation():
    answer = traffic.analyze(request(protocols=[{"protocol": "ARP", "packets": 600, "bytes": 36000},
                                                {"protocol": "HTTPS", "packets": 600, "bytes": 800000}]))

    arp = next(i for i in answer.inferences if i.code == "ARP_ACTIVITY")
    assert arp.confidence == 0.6
    assert "no basta para decir que alguno sea malicioso" in arp.recommendation
    for item in answer.facts + answer.inferences:
        assert "malicioso" not in item.title.lower()


@pytest.mark.parametrize("protocols, code", [
    ([{"protocol": "MDNS", "packets": 300, "bytes": 1}, {"protocol": "SSDP", "packets": 200, "bytes": 1},
      {"protocol": "HTTPS", "packets": 700, "bytes": 1}], "DISCOVERY_CHATTER"),
    ([{"protocol": "DNS", "packets": 500, "bytes": 1}, {"protocol": "HTTPS", "packets": 700, "bytes": 1}], "DNS_HEAVY"),
    ([{"protocol": "HTTP", "packets": 300, "bytes": 1}, {"protocol": "HTTPS", "packets": 900, "bytes": 1}],
     "UNENCRYPTED_WEB"),
])
def test_patterns_of_protocols_are_inferences(protocols, code):
    assert code in codes(traffic.analyze(request(protocols=protocols)).inferences)


def test_many_remote_hosts_in_little_time_is_a_low_confidence_inference():
    inference = next(i for i in traffic.analyze(request(remoteHosts=400)).inferences if i.code == "MANY_REMOTE_HOSTS")

    assert inference.confidence == 0.4


def test_an_empty_capture_says_so_and_infers_nothing():
    answer = traffic.analyze(request(packets=0, bytes=0, protocols=[], intervals=[], broadcast=0, multicast=0))

    assert codes(answer.facts)[0] == "EMPTY_CAPTURE"
    assert answer.inferences == []


def test_a_small_sample_makes_the_reading_uncertain_and_finds_no_patterns():
    answer = traffic.analyze(request(durationSeconds=5, packets=30, bytes=3000,
                                     protocols=[{"protocol": "ARP", "packets": 30, "bytes": 1800}],
                                     intervals=[{"second": s, "packets": 6, "bytes": 600} for s in range(5)]))

    assert "muestra pequeña" in answer.uncertainty
    assert answer.inferences == []


@pytest.mark.parametrize("reason, code", [("PACKET_LIMIT", "STOPPED_AT_LIMIT"), ("BYTE_LIMIT", "STOPPED_AT_LIMIT"),
                                          ("CANCELLED", "STOPPED_BY_ADMIN")])
def test_a_capture_that_stopped_early_says_it_describes_only_a_part(reason, code):
    assert code in codes(traffic.analyze(request(stopReason=reason)).facts)


def test_the_scope_of_a_local_capture_is_always_stated():
    assert "no lo que los demás equipos envían" in traffic.analyze(request()).uncertainty


def test_a_tiny_share_is_not_rounded_to_zero():
    fact = next(f for f in traffic.analyze(request(malformed=2)).facts if f.code == "MALFORMED_PACKETS")

    assert "menos de 1 %" in fact.evidence and fact.severity == Level.INFO
