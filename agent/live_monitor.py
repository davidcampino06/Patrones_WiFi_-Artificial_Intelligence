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
