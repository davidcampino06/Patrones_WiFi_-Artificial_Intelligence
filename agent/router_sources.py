"""Lo que el router sabe de los equipos de la red, por las vías que no necesitan su clave (agente 2.0.0).

Detectar el router no es administrarlo. La lista oficial de clientes, bloquear un equipo o cambiar la contraseña del
Wi-Fi necesitan entrar al router con su clave de administrador, y cada fabricante (y cada operador) lo hace distinto.
WiFiSense todavía no tiene una integración oficial con ningún modelo, así que esas operaciones no existen aquí y la
página explica cómo hacerlas en el propio router. Esta abstracción deja el lugar listo para agregarlas sin tocar el
resto del agente:

  * ``RouterSource`` (Strategy): lo que una fuente puede hacer. Hoy solo ``names``.
  * ``GatewayDnsSource`` (Adapter del protocolo DNS): muchos routers caseros (dnsmasq: TP-Link, ASUS, OpenWrt y varios
    de operador) guardan el nombre que cada equipo dijo al pedir dirección (DHCP) y lo responden si se les pregunta
    por la IP al revés (PTR). Es solo lectura, no usa clave, y se le pregunta directamente al router: el DNS que tenga
    configurado el computador puede ser el del operador, que no conoce los equipos de la casa.
  * ``source_for`` (Factory): elige la fuente según el fabricante y el modelo del router. Una integración futura
    (con autorización del dueño y por un mecanismo oficial del fabricante) sería otra clase aquí.

Nunca se guarda ni se envía la clave del router: hoy no se pide.
"""
from __future__ import annotations

import random
import socket
import struct
import time
from typing import Iterable, Optional, Protocol

DNS_PORT = 53
TYPE_PTR, CLASS_IN = 12, 1
MAX_QUERIES = 1024


class NotSupported(Exception):
    """La operación no existe para este router: no hay una integración oficial."""


class RouterSource(Protocol):
    code: str

    def names(self, ips: Iterable[str]) -> dict[str, str]:
        """IP -> nombre que el router conoce. Lo que no conozca, no aparece."""

    def clients(self) -> list[dict]:
        """La lista oficial de clientes del router (activos e históricos)."""

    def block(self, device: str) -> None:
        """Saca un equipo de la red en el router."""


def reverse_name(ip: str) -> str:
    return ".".join(reversed(ip.split("."))) + ".in-addr.arpa"


def encode_name(name: str) -> bytes:
    out = b""
    for label in name.strip(".").split("."):
        raw = label.encode("ascii")
        if not 0 < len(raw) < 64:
            raise ValueError("etiqueta DNS inválida")
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def ptr_query(ip: str, query_id: int) -> bytes:
    """Pregunta PTR estándar con recursión pedida (el router responde de su propia tabla)."""
    return struct.pack("!HHHHHH", query_id, 0x0100, 1, 0, 0, 0) + encode_name(reverse_name(ip)) + struct.pack(
        "!HH", TYPE_PTR, CLASS_IN)


def read_name(data: bytes, offset: int, depth: int = 0) -> tuple[str, int]:
    """Nombre DNS con compresión (punteros), protegido contra bucles y paquetes cortados."""
    if depth > 10:
        raise ValueError("demasiados punteros")
    labels = []
    while True:
        if offset >= len(data):
            raise ValueError("nombre cortado")
        length = data[offset]
        if length == 0:
            return ".".join(labels), offset + 1
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                raise ValueError("puntero cortado")
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            name, _ = read_name(data, pointer, depth + 1)
            labels.append(name)
            return ".".join(label for label in labels if label), offset + 2
        labels.append(data[offset + 1:offset + 1 + length].decode("utf-8", "replace"))
        offset += 1 + length


def parse_ptr_answer(data: bytes) -> tuple[int, Optional[str]]:
    """(id de la pregunta, nombre) de una respuesta PTR; nombre None si el router no lo conoce o la respuesta es rara."""
    if len(data) < 12:
        raise ValueError("respuesta corta")
    query_id, flags, questions, answers = struct.unpack("!HHHH", data[:8])
    if not flags & 0x8000 or flags & 0x000F:  # no es respuesta, o trae error (por ejemplo NXDOMAIN)
        return query_id, None
    offset = 12
    for _ in range(questions):
        _name, offset = read_name(data, offset)
        offset += 4
    for _ in range(answers):
        _name, offset = read_name(data, offset)
        if offset + 10 > len(data):
            raise ValueError("respuesta cortada")
        record_type, _cls, _ttl, length = struct.unpack("!HHIH", data[offset:offset + 10])
        offset += 10
        if record_type == TYPE_PTR:
            name, _ = read_name(data, offset)
            return query_id, name or None
        offset += length
    return query_id, None
