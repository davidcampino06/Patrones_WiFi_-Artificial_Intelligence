"""Reading of one scan of the nearby Wi-Fi networks: facts (what the antenna saw) apart from inferences (possible
explanations with their confidence).

It reuses the channel recommendation of this service (app.channel): the access points of the scan become the channel
counts that the agent's reports already send. A network seen nearby is not one the user manages: nothing here invites
to connect to another network, and a network that looks like the user's own is only a "possible" look-alike (it is
often the user's own repeater), never an attacker.
"""
from __future__ import annotations

import re
from collections import Counter

from app import channel
from app.schemas_channel import ChannelCount, ChannelRequest
from app.schemas_findings import Fact, FindingsResponse, Inference, Level
from app.schemas_nearby import AccessPoint, NearbyRequest

MODEL_VERSION = "nearby-1.0"
WEAK_SIGNAL_PERCENT = 40


def analyze(request: NearbyRequest) -> FindingsResponse:
    seen = request.access_points
    if not seen:
        return FindingsResponse(facts=[Fact(code="NO_NETWORKS", title="No se vieron redes",
                                            evidence="El escaneo no encontró redes Wi-Fi.")],
                                inferences=[], uncertainty=_uncertainty(0), model_version=MODEL_VERSION)
    own = next((ap for ap in seen if ap.connected), None)
    others = [ap for ap in seen if not ap.connected]
    names = {(ap.ssid or "").strip() for ap in seen if ap.ssid and not ap.hidden}
    facts = [Fact(code="NETWORKS_SEEN", title="Redes cercanas",
                  evidence=_count(len(names), "red con nombre", "redes con nombre") + " y "
                           + _count(len(seen), "punto de acceso", "puntos de acceso") + " en total"
                           + (f"; {_count(hidden, 'oculta', 'ocultas')}." if (hidden := sum(1 for ap in seen
                                                                                       if ap.hidden)) else "."))]
    facts += _own_network(own)
    open_ones = [ap for ap in others if ap.authentication == "OPEN"]
    if open_ones:
        facts.append(Fact(code="OPEN_NETWORKS_NEARBY", title="Redes abiertas cerca",
                          evidence=(f"{_count(len(open_ones), 'punto de acceso cercano no pide', 'puntos de acceso cercanos no piden')} "
                                    "contraseña."),
                          recommendation="No te conectes a redes abiertas para nada privado: lo que envíes sin "
                                         "cifrar lo puede ver cualquiera cerca."))
    weak = [ap for ap in others if ap.authentication in ("WEP", "WPA")]
    if weak:
        facts.append(Fact(code="WEAK_SECURITY_NEARBY", title="Redes cercanas con seguridad vieja",
                          evidence=f"{_count(len(weak), 'punto de acceso usa', 'puntos de acceso usan')} WEP o WPA, que ya "
                                   "no protegen bien."))

    inferences: list[Inference] = []
    if own and own.channel:
        crowded, better = _channel(own, others)
        if crowded:
            facts.append(crowded)
        if better:
            inferences.append(better)
    if own and own.signal_percent is not None and own.signal_percent < WEAK_SIGNAL_PERCENT:
        inferences.append(Inference(
            code="WEAK_OWN_SIGNAL", severity=Level.WARNING, confidence=0.6,
            title="Tu Wi-Fi llega débil a este computador",
            evidence=f"La señal de tu red es {own.signal_percent} % en el lugar del computador del agente.",
            recommendation="Acerca el router o pon un repetidor; las paredes y los electrodomésticos la debilitan. "
                           "Mide de nuevo desde otro lugar para confirmarlo."))
    inferences += _lookalikes(own, others)
    return FindingsResponse(facts=facts, inferences=inferences, uncertainty=_uncertainty(len(seen)),
                            model_version=MODEL_VERSION)


def _own_network(own: AccessPoint | None) -> list[Fact]:
    if own is None:
        return [Fact(code="NOT_CONNECTED", title="Sin red conectada en el escaneo",
                     evidence="En este escaneo el computador no estaba conectado a ninguna de las redes vistas.")]
    security = own.authentication or "UNKNOWN"
    if security in ("OPEN", "WEP"):
        return [Fact(code="OWN_NETWORK_UNPROTECTED", severity=Level.CRITICAL,
                     title="Tu red no está protegida",
                     evidence=f"Tu red «{own.ssid or 'oculta'}» usa {'ninguna contraseña' if security == 'OPEN' else 'WEP'}.",
                     recommendation="Entra al router y cambia la seguridad a WPA2 o WPA3 con una contraseña larga.")]
    if security == "WPA":
        return [Fact(code="OWN_NETWORK_OLD_SECURITY", severity=Level.WARNING, title="Tu red usa WPA (antigua)",
                     evidence=f"Tu red «{own.ssid or 'oculta'}» usa WPA, que ya no se considera segura.",
                     recommendation="Cambia a WPA2 o WPA3 en la configuración del router.")]
    signal = f", señal {own.signal_percent} %" if own.signal_percent is not None else ""
    where = f" en el canal {own.channel}" if own.channel else ""
    return [Fact(code="OWN_NETWORK", title="Tu red",
                 evidence=f"«{own.ssid or 'oculta'}» usa {security}{where}{signal}.")]
