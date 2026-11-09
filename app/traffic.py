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


def _burst(request: TrafficRequest) -> Inference | None:
    seconds = max(1, min(int(round(request.duration_seconds)), 361))
    counts = [0] * seconds
    for interval in request.intervals:
        if interval.second < seconds:
            counts[interval.second] = interval.packets
    if seconds < SMALL_SAMPLE_SECONDS or request.packets < MIN_PACKETS_FOR_PATTERNS:
        return None
    median = statistics.median(counts)
    mad = statistics.median(abs(c - median) for c in counts) or 1.0
    threshold = max(median + 6 * mad, 2 * median, 20)
    bursts = [second for second, count in enumerate(counts) if count > threshold]
    if not bursts:
        return None
    peak = max(counts[s] for s in bursts)
    confidence = round(min(0.85, 0.45 + 0.1 * len(bursts) + (0.1 if peak > 4 * max(median, 1) else 0)), 2)
    return Inference(code="TRAFFIC_BURST", severity=Level.WARNING, confidence=confidence,
                     title="Posible ráfaga de tráfico",
                     evidence=f"{len(bursts)} segundo(s) con hasta {peak} paquetes, cuando lo normal en esta captura "
                              f"fue {median:.0f} por segundo (segundos {_list(bursts)}).",
                     recommendation="Repite la captura en otro momento y compara: una descarga o una actualización "
                                    "explican una ráfaga; si se repite sin motivo, revisa los equipos conectados.")


def _patterns(request: TrafficRequest, by_protocol: dict[str, int]) -> list[Inference]:
    packets, found = request.packets, []
    arp = by_protocol.get("ARP", 0)
    if arp >= MIN_PACKETS_FOR_PATTERNS and arp / packets >= 0.2:
        found.append(Inference(
            code="ARP_ACTIVITY", severity=Level.WARNING, confidence=0.6 if arp / packets >= 0.4 else 0.45,
            title="Muchas preguntas ARP",
            evidence=f"{arp} de {packets} paquetes ({_pct(arp, packets)}) fueron ARP: equipos preguntando quién "
                     "tiene cada dirección de la red.",
            recommendation="Puede ser un equipo que recorre la red (un inventario, un antivirus, un escaneo) o uno mal "
                           "configurado. Revisa en Dispositivos si apareció un equipo nuevo; esto solo no basta para "
                           "decir que alguno sea malicioso."))
    discovery = sum(by_protocol.get(p, 0) for p in DISCOVERY)
    if discovery >= MIN_PACKETS_FOR_PATTERNS and discovery / packets >= 0.3:
        found.append(Inference(
            code="DISCOVERY_CHATTER", severity=Level.INFO, confidence=0.6,
            title="Mucho tráfico de descubrimiento",
            evidence=f"{discovery} paquetes ({_pct(discovery, packets)}) fueron mDNS, SSDP, LLMNR o NetBIOS.",
            recommendation="Suelen ser televisores, impresoras o parlantes anunciándose. Si molesta, desactiva el "
                           "descubrimiento en los equipos que no lo necesitan."))
    dns = by_protocol.get("DNS", 0)
    if dns >= MIN_PACKETS_FOR_PATTERNS and dns / packets >= 0.25:
        found.append(Inference(
            code="DNS_HEAVY", severity=Level.INFO, confidence=0.45, title="Muchas consultas de nombres",
            evidence=f"{dns} paquetes ({_pct(dns, packets)}) fueron consultas DNS.",
            recommendation="Puede ser una aplicación que consulta sin parar o un DNS que no responde y obliga a "
                           "repetir. Prueba con otro servidor DNS y compara."))
    http = by_protocol.get("HTTP", 0)
    if http >= 20 and http / packets >= 0.1:
        found.append(Inference(
            code="UNENCRYPTED_WEB", severity=Level.WARNING, confidence=0.6, title="Parte de la web va sin cifrar",
            evidence=f"{http} paquetes ({_pct(http, packets)}) usaron el puerto 80 (HTTP), que no va cifrado.",
            recommendation="Usa sitios con HTTPS y actualiza los equipos que aún hablan HTTP (cámaras, impresoras)."))
    if request.remote_hosts and request.remote_hosts >= 150 and request.duration_seconds <= 120:
        found.append(Inference(
            code="MANY_REMOTE_HOSTS", severity=Level.WARNING, confidence=0.4, title="Muchos destinos en poco tiempo",
            evidence=f"{request.remote_hosts} direcciones de fuera de la red en {request.duration_seconds:.0f} s.",
            recommendation="Puede ser un programa de descargas entre usuarios (P2P), una actualización distribuida o "
                           "un escaneo. Revisa qué programas corren en el computador del sensor."))
    return found


def _uncertainty(request: TrafficRequest) -> str:
    notes = ["La captura ve el tráfico del computador del sensor y la difusión de la red, no lo que los demás equipos "
             "envían a Internet."]
    if request.packets < SMALL_SAMPLE_PACKETS or request.duration_seconds < SMALL_SAMPLE_SECONDS:
        notes.append("Es una muestra pequeña: las inferencias son poco seguras.")
    if request.dropped_by_tool is None:
        notes.append("La herramienta no informó si perdió paquetes.")
    notes.append("Las inferencias son posibles explicaciones, no certezas: confírmalas antes de actuar.")
    return " ".join(notes)


def _pct(part: int, whole: int) -> str:
    if not whole:
        return "0 %"
    share = 100 * part / whole
    return "menos de 1 %" if 0 < share < 1 else f"{share:.0f} %"


def _size(size: int) -> str:
    return f"{size / 1_048_576:.1f} MB" if size >= 1_048_576 else f"{size / 1024:.0f} KB"


def _list(seconds: list[int]) -> str:
    shown = ", ".join(str(s) for s in seconds[:5])
    return shown + ("…" if len(seconds) > 5 else "")
