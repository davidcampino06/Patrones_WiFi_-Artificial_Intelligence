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
