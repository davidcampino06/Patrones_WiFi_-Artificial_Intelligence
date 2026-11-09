"""Estadísticas de una captura: lo único que sale del computador.

Cuenta paquetes y bytes, entrada y salida, difusión y multidifusión, paquetes por protocolo, los servicios más usados
(por puerto conocido) y paquetes por segundo. Los equipos se cuentan (cuántos de la red local y cuántos de fuera), pero
sus direcciones se quedan en memoria y se olvidan al terminar: el resultado no tiene ningún campo para una IP, una MAC
o el contenido de un paquete (ver AgentCaptureResult en el backend, que además rechaza lo que no cuadre).

Los límites (segundos, paquetes, bytes) los decide quien pidió la captura y se respetan aquí: al alcanzar uno, la
captura se detiene y el resultado dice cuál fue (stopReason).
"""
from __future__ import annotations

import ipaddress
from collections import Counter
from dataclasses import dataclass, field
from typing import Iterable, Optional

try:  # el agente como paquete (pruebas) o como script suelto (PyInstaller)
    from agent.packet_parser import PROTOCOLS, PacketInfo
except ImportError:  # pragma: no cover
    from packet_parser import PROTOCOLS, PacketInfo

MAX_SECONDS_KEPT = 360  # el servidor acepta los segundos 0 a 360
MAX_PORTS = 20
SERVER_MAX_PACKETS = 100_000
SERVER_MAX_BYTES = 100 * 1024 * 1024


@dataclass(frozen=True)
class Limits:
    """Lo que el servidor pidió: nunca más de lo que él mismo acepta."""
    seconds: int
    packets: int
    bytes: int

    @staticmethod
    def of(task: dict) -> "Limits":
        def number(name: str, default: int, top: int) -> int:
            value = task.get(name)
            if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                return default
            return min(value, top)
        return Limits(number("maxSeconds", 30, 300), number("maxPackets", 5000, SERVER_MAX_PACKETS),
                      number("maxBytes", 20 * 1024 * 1024, SERVER_MAX_BYTES))
