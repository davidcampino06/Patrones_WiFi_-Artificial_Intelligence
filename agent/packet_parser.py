"""Cabeceras de un paquete capturado -> qué protocolo es, de dónde a dónde y por qué puerto.

Captura mínima: solo se miran las cabeceras de enlace, IP y TCP/UDP (los primeros bytes del paquete). Nunca se lee
el contenido: ni nombres consultados por DNS, ni páginas, ni contraseñas, ni cookies. El protocolo de aplicación se
deduce solo del número de puerto (53 es DNS, 443 es HTTPS...), sin abrir el paquete.

Las direcciones IP y MAC solo existen aquí, en memoria, para contar entrada y salida y cuántos equipos distintos hubo;
capture_stats no las envía al servidor.

Tipos de enlace (LINKTYPE de tcpdump.org): 1 Ethernet (lo que entregan Npcap y pktmon en una tarjeta Wi-Fi normal),
101/228/229 IP sin enlace (sockets sin procesar), 113 y 276 Linux «cooked» (socket de paquetes en la interfaz "any").
"""
from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass
from typing import Optional

LINK_ETHERNET, LINK_RAW, LINK_IPV4, LINK_IPV6, LINK_LINUX_SLL, LINK_LINUX_SLL2 = 1, 101, 228, 229, 113, 276
ETHERTYPE_IPV4, ETHERTYPE_ARP, ETHERTYPE_IPV6, ETHERTYPE_VLAN, ETHERTYPE_QINQ = 0x0800, 0x0806, 0x86DD, 0x8100, 0x88A8
IPPROTO_ICMP, IPPROTO_IGMP, IPPROTO_TCP, IPPROTO_UDP, IPPROTO_ICMPV6 = 1, 2, 6, 17, 58
IPV6_EXTENSIONS = (0, 43, 44, 60)  # salto a salto, enrutamiento, fragmento, opciones de destino

# Puerto -> protocolo de aplicación (solo por el número, sin abrir el paquete).
UDP_SERVICES = {53: "DNS", 5353: "MDNS", 67: "DHCP", 68: "DHCP", 546: "DHCP", 547: "DHCP", 1900: "SSDP",
                137: "NETBIOS", 138: "NETBIOS", 5355: "LLMNR", 443: "QUIC", 123: "NTP"}
TCP_SERVICES = {53: "DNS", 139: "NETBIOS", 80: "HTTP", 8080: "HTTP", 443: "HTTPS", 5355: "LLMNR"}
EPHEMERAL_FROM = 49152  # los puertos desde aquí los elige el sistema al azar: no dicen qué servicio es

# Lo que acepta el servidor (AgentCaptureResult.Protocol): cualquier otra cosa sería rechazada.
PROTOCOLS = ("TCP", "UDP", "ICMP", "ICMPV6", "ARP", "IGMP", "DNS", "MDNS", "DHCP", "SSDP", "NETBIOS", "LLMNR",
             "HTTP", "HTTPS", "QUIC", "NTP", "IPV6_OTHER", "IPV4_OTHER", "OTHER")


@dataclass(frozen=True)
class PacketInfo:
    """Lo que se sabe de un paquete por sus cabeceras."""
    length: int                         # bytes originales del paquete (no solo los guardados)
    protocol: str                       # uno de PROTOCOLS
    transport: Optional[str] = None     # "TCP" o "UDP"
    service_port: Optional[int] = None  # el puerto conocido de la conversación (443, 53...), no el efímero
    source: Optional[str] = None        # IP de origen (solo en memoria)
    destination: Optional[str] = None   # IP de destino (solo en memoria)
    broadcast: bool = False             # para todos los equipos de la red (MAC ff:ff:ff:ff:ff:ff o IP de difusión)
    multicast: bool = False             # para un grupo (mDNS, SSDP, IPv6...)
    malformed: bool = False             # cabeceras cortadas o imposibles: se cuenta, no se interpreta


def parse(data: bytes, link_type: int, original_length: Optional[int] = None) -> PacketInfo:
    """Interpreta las cabeceras de un paquete. Nunca lanza excepciones: lo ilegible sale como malformed."""
    length = original_length if original_length is not None else len(data)
    try:
        return _parse(data, link_type, length)
    except (struct.error, IndexError, ValueError):
        return PacketInfo(length, "OTHER", malformed=True)
