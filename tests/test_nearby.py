"""Lectura de un escaneo de redes cercanas: hechos de lo que vio la antena e inferencias con su confianza."""
import json
from pathlib import Path

from app import nearby
from app.schemas_findings import Level
from app.schemas_nearby import NearbyRequest

CONTRACT = json.loads((Path(__file__).parent / "contracts" / "nearby_request.json").read_text(encoding="utf-8"))


def scan(points):
    return NearbyRequest.model_validate({"accessPoints": points})


def ap(ssid, auth="WPA2", channel=6, signal=60, connected=False, vendor=None, hidden=False):
    return {"ssid": ssid, "authentication": auth, "channel": channel, "band": "2.4" if channel <= 14 else "5",
            "signalPercent": signal, "connected": connected, "vendor": vendor, "hidden": hidden}


def codes(items):
    return [item.code for item in items]


def test_the_contract_example_gives_the_expected_reading():
    answer = nearby.analyze(NearbyRequest.model_validate(CONTRACT))

    assert codes(answer.facts) == ["NETWORKS_SEEN", "OWN_NETWORK", "OPEN_NETWORKS_NEARBY"]
    assert codes(answer.inferences) == ["BETTER_CHANNEL", "WEAK_OWN_SIGNAL", "LOOKALIKE_NETWORK"]
    assert answer.facts[0].evidence == "3 redes con nombre y 5 puntos de acceso en total; 1 oculta."


def test_an_unprotected_own_network_is_the_only_critical_thing_and_it_is_a_fact():
    answer = nearby.analyze(scan([ap("Casa", "OPEN", connected=True), ap("Vecino")]))

    own = answer.facts[1]
    assert own.code == "OWN_NETWORK_UNPROTECTED" and own.severity == Level.CRITICAL
    assert all(i.severity != Level.CRITICAL for i in answer.inferences)


def test_a_crowded_channel_is_counted_and_a_calmer_one_is_inferred():
    points = [ap("Casa", connected=True)] + [ap(f"Vecino {i}") for i in range(4)] + [ap("Otro", channel=1)]
    answer = nearby.analyze(scan(points))

    crowded = next(f for f in answer.facts if f.code == "CROWDED_CHANNEL")
    assert "4 redes vecinas" in crowded.evidence
    better = next(i for i in answer.inferences if i.code == "BETTER_CHANNEL")
    assert better.confidence == 0.7 and "11" in better.title and better.recommendation


def test_a_repeater_with_the_same_name_and_maker_is_not_a_lookalike():
    answer = nearby.analyze(scan([ap("Casa", connected=True, vendor="TP-Link"), ap("Casa", vendor="TP-Link")]))

    assert "LOOKALIKE_NETWORK" not in codes(answer.inferences)
