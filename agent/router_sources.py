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
