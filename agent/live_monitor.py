"""Medición en vivo (2.1.0): mientras alguien tiene abierto «En vivo» en la página, el agente mide cada 2 segundos.

Qué mide, sin gastar datos de más:

- **Bajada y subida de este momento**: lo que avanzaron los contadores de la tarjeta de red (los mismos del reporte),
  dividido por el tiempo. Es lo que el computador **está usando**, no lo que la conexión **aguanta** (eso lo mide
  «Probar mi conexión»).
- **Latencia al router y a internet**: el tiempo de una conexión TCP (como en el reporte). Si el router no contesta
  en ningún puerto, su latencia queda desconocida; si internet no contesta, esa muestra cuenta como perdida.
- **Señal y velocidad del enlace Wi-Fi** de la tarjeta.

Nada de esto incluye direcciones MAC, sitios visitados ni el contenido del tráfico: solo números del propio
computador. El servidor solo puede decir «mide» (cada cuántos segundos y por cuánto tiempo, como números) o «para»:
el agente nunca ejecuta órdenes que lleguen del servidor.
"""
from __future__ import annotations

import threading
import time
from typing import Callable, Optional

DEFAULT_SAMPLE_SECONDS = 2
MIN_SAMPLE_SECONDS = 1
MAX_SAMPLE_SECONDS = 10
DEFAULT_SESSION_SECONDS = 600
MIN_SESSION_SECONDS = 10
MAX_SESSION_SECONDS = 1800
GATEWAY_PORTS = (53, 80, 443)  # DNS primero: también lo atiende la zona Wi-Fi de un celular
PROBE_TIMEOUT = 1.0
MAX_FAILURES = 3
MAX_BPS = 10 ** 11  # 100 Gbps: más que eso es un contador que no cuadra

Probe = Callable[[str, int, float], Optional[float]]


def live_task_of(answer) -> Optional[dict]:
    """Lo único que el servidor puede pedir: medir cada ``sampleSeconds`` durante ``maxSeconds`` (números dentro de
    sus límites). Cualquier otra cosa se ignora."""
    if not isinstance(answer, dict) or answer.get("live") is not True:
        return None

    def number(name: str, default: int, low: int, high: int) -> int:
        value = answer.get(name)
        if isinstance(value, int) and not isinstance(value, bool):
            return max(low, min(value, high))
        return default

    return {"sampleSeconds": number("sampleSeconds", DEFAULT_SAMPLE_SECONDS, MIN_SAMPLE_SECONDS, MAX_SAMPLE_SECONDS),
            "maxSeconds": number("maxSeconds", DEFAULT_SESSION_SECONDS, MIN_SESSION_SECONDS, MAX_SESSION_SECONDS)}


def throughput(before: dict, after: dict, seconds: float) -> tuple[Optional[int], Optional[int]]:
    """Bits por segundo de bajada y de subida entre dos lecturas de los contadores. Un contador que retrocede (otra
    tarjeta, el computador se reinició) o un tiempo que no avanzó no dan un valor confiable: None."""
    if seconds <= 0:
        return None, None
    rates = []
    for name in ("bytes.in", "bytes.out"):
        if name not in before or name not in after or after[name] < before[name]:
            rates.append(None)
            continue
        bps = round((after[name] - before[name]) * 8 / seconds)
        rates.append(bps if bps <= MAX_BPS else None)
    return rates[0], rates[1]


def pick_gateway_port(gateway: Optional[str], probe: Probe) -> Optional[int]:
    """El primer puerto del router que contesta (un rechazo también contesta). Si ninguno contesta, la latencia al
    router no se puede medir así y queda desconocida: no se cuenta como pérdida."""
    if not gateway:
        return None
    for port in GATEWAY_PORTS:
        if probe(gateway, port, PROBE_TIMEOUT) is not None:
            return port
    return None


class LiveSampler:
    """Toma una muestra: tráfico desde la muestra anterior, latencias (en paralelo) y el enlace Wi-Fi."""

    def __init__(self, counters: Callable[[], dict], link: Callable[[], dict], probe: Probe,
                 gateway: Optional[str], internet: tuple[str, int], clock: Callable[[], float] = time.monotonic):
        self.counters, self.link, self.probe = counters, link, probe
        self.gateway, self.internet, self.clock = gateway, internet, clock
        self.gateway_port: Optional[int] = None
        self.previous: Optional[tuple[float, dict]] = None

    def start(self) -> None:
        self.gateway_port = pick_gateway_port(self.gateway, self.probe)
        self.previous = (self.clock(), self.counters())

    def sample(self) -> dict:
        if self.previous is None:
            self.start()
        results: dict = {}

        def timed(name: str, host: str, port: int) -> threading.Thread:
            def target():
                results[name] = self.probe(host, port, PROBE_TIMEOUT)
            thread = threading.Thread(target=target, daemon=True)
            thread.start()
            return thread

        threads = [timed("internet", *self.internet)]
        if self.gateway and self.gateway_port is not None:
            threads.append(timed("gateway", self.gateway, self.gateway_port))
        for thread in threads:
            thread.join(timeout=PROBE_TIMEOUT + 1)

        now, current = self.clock(), self.counters()
        before_at, before = self.previous
        self.previous = (now, current)
        down, up = throughput(before, current, now - before_at)

        sample: dict = {"intervalMs": max(0, round((now - before_at) * 1000))}
        if down is not None:
            sample["downloadBps"] = down
        if up is not None:
            sample["uploadBps"] = up
        internet = results.get("internet")
        if internet is None:
            sample["internetLost"] = True
        else:
            sample["internetMs"] = round(internet, 1)
        if self.gateway and self.gateway_port is not None:
            gateway = results.get("gateway")
            if gateway is None:
                sample["gatewayLost"] = True
            else:
                sample["gatewayMs"] = round(gateway, 1)
        try:
            link = self.link() or {}
        except Exception:  # sin datos del Wi-Fi la muestra sigue sirviendo
            link = {}
        for name in ("signalPercent", "rxRateMbps", "txRateMbps"):
            value = link.get(name)
            if isinstance(value, (int, float)) and not isinstance(value, bool) and value >= 0:
                sample[name] = int(value) if name == "signalPercent" else round(float(value), 1)
        return sample
