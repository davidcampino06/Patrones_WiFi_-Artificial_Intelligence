"""Reading of a technical capture: facts (what was counted) apart from inferences (possible explanations with their
confidence), with the uncertainty of the whole reading.

Only the statistical summary arrives (never a packet, an address or a payload), so nothing here can say which device
did what, and nothing claims that a device is malicious: an unusual pattern is a reason to look, with a defensive
action that the person can verify. Three different "losses" are never mixed: what the capture tool could not keep
(droppedByTool), the packet loss of the connection tests (connectionLossPct, another measurement) and an anomaly (an
inference).

The burst detection uses the median and the median absolute deviation of the packets per second, which a single huge
second cannot drag (the mean and the standard deviation can), the same robust idea as the statistical strategy of the
backend.
"""
from __future__ import annotations

import statistics

from app.schemas_findings import Fact, FindingsResponse, Inference, Level
from app.schemas_traffic import TrafficRequest

MODEL_VERSION = "traffic-1.0"
DISCOVERY = ("MDNS", "SSDP", "LLMNR", "NETBIOS")
MIN_PACKETS_FOR_PATTERNS = 50
SMALL_SAMPLE_PACKETS = 100
SMALL_SAMPLE_SECONDS = 10


def analyze(request: TrafficRequest) -> FindingsResponse:
    facts: list[Fact] = []
    inferences: list[Inference] = []
    packets = request.packets
    by_protocol = {p.protocol: p.packets for p in request.protocols}

    if packets == 0:
        facts.append(Fact(code="EMPTY_CAPTURE", severity=Level.WARNING, title="No se capturó ningún paquete",
                          evidence=f"En {request.duration_seconds:.0f} s la herramienta no entregó paquetes.",
                          recommendation="Revisa que el sensor esté conectado a la red y que la herramienta de captura "
                                         "funcione (capture-check en el computador del sensor)."))
        return FindingsResponse(facts=facts + _losses(request), inferences=[], model_version=MODEL_VERSION,
                                uncertainty=_uncertainty(request))

    rate = packets / request.duration_seconds
    facts.append(Fact(code="TRAFFIC_VOLUME", title="Volumen capturado",
                      evidence=f"{packets} paquetes y {_size(request.bytes)} en {request.duration_seconds:.0f} s "
                               f"({rate:.1f} paquetes por segundo)."))
    top = sorted(request.protocols, key=lambda p: p.packets, reverse=True)[:3]
    if top:
        facts.append(Fact(code="TOP_PROTOCOLS", title="Protocolos más usados",
                          evidence=", ".join(f"{p.protocol} {_pct(p.packets, packets)}" for p in top) + "."))
    facts += _losses(request)
    if request.broadcast is not None and request.broadcast >= MIN_PACKETS_FOR_PATTERNS \
            and request.broadcast / packets >= 0.3:
        facts.append(Fact(code="BROADCAST_SHARE", severity=Level.WARNING, title="Mucha difusión",
                          evidence=f"{request.broadcast} de {packets} paquetes ({_pct(request.broadcast, packets)}) "
                                   "fueron para todos los equipos de la red.",
                          recommendation="La difusión ocupa el aire de todos: revisa qué equipos la generan."))
    if request.malformed:
        share = request.malformed / packets
        facts.append(Fact(code="MALFORMED_PACKETS", severity=Level.WARNING if share >= 0.05 else Level.INFO,
                          title="Paquetes ilegibles",
                          evidence=f"{request.malformed} paquetes ({_pct(request.malformed, packets)}) tenían "
                                   "cabeceras cortadas o imposibles."))
    if request.stop_reason in ("PACKET_LIMIT", "BYTE_LIMIT"):
        facts.append(Fact(code="STOPPED_AT_LIMIT", title="La captura llegó a su límite",
                          evidence="Se detuvo al alcanzar el límite de "
                                   + ("paquetes" if request.stop_reason == "PACKET_LIMIT" else "bytes")
                                   + ": describe solo la primera parte del tiempo pedido."))
    elif request.stop_reason == "CANCELLED":
        facts.append(Fact(code="STOPPED_BY_ADMIN", title="Detenida por un administrador",
                          evidence="La captura se detuvo antes de tiempo; los conteos son de lo capturado hasta ahí."))

    burst = _burst(request)
    if burst:
        inferences.append(burst)
    inferences += _patterns(request, by_protocol)
    return FindingsResponse(facts=facts, inferences=inferences, uncertainty=_uncertainty(request),
                            model_version=MODEL_VERSION)


def _losses(request: TrafficRequest) -> list[Fact]:
    facts = []
    if request.dropped_by_tool:
        total = request.packets + request.dropped_by_tool
        share = request.dropped_by_tool / total
        facts.append(Fact(code="TOOL_DROPPED", severity=Level.WARNING if share >= 0.01 else Level.INFO,
                          title="La herramienta perdió paquetes",
                          evidence=f"La herramienta de captura informó {request.dropped_by_tool} paquetes que no "
                                   f"alcanzó a guardar ({_pct(request.dropped_by_tool, total)}). Es una pérdida de la "
                                   "captura, no de la red: los conteos son un mínimo.",
                          recommendation="Si se repite, captura menos tiempo o en un computador menos ocupado."))
    if request.connection_loss_pct is not None:
        facts.append(Fact(code="CONNECTION_LOSS",
                          severity=Level.WARNING if request.connection_loss_pct >= 2 else Level.INFO,
                          title="Pérdida en la última prueba de conexión",
                          evidence=f"La última prueba de conexión de esta red midió {request.connection_loss_pct:.1f} % "
                                   "de pérdida. Es otra medida: no sale de esta captura."))
    return facts
