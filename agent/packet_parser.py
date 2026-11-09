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


def _parse(data: bytes, link_type: int, length: int) -> PacketInfo:
    broadcast = multicast = False
    if link_type == LINK_ETHERNET:
        if len(data) < 14:
            return PacketInfo(length, "OTHER", malformed=True)
        destination_mac = data[0:6]
        broadcast = destination_mac == b"\xff" * 6
        multicast = not broadcast and bool(destination_mac[0] & 1)
        ethertype, offset = struct.unpack("!H", data[12:14])[0], 14
        while ethertype in (ETHERTYPE_VLAN, ETHERTYPE_QINQ):  # etiquetas de VLAN: 4 bytes cada una
            ethertype, offset = struct.unpack("!H", data[offset + 2:offset + 4])[0], offset + 4
    elif link_type == LINK_LINUX_SLL:
        packet_type = struct.unpack("!H", data[0:2])[0]
        broadcast, multicast = packet_type == 1, packet_type == 2
        ethertype, offset = struct.unpack("!H", data[14:16])[0], 16
    elif link_type == LINK_LINUX_SLL2:
        ethertype = struct.unpack("!H", data[0:2])[0]
        broadcast, multicast = data[10] == 1, data[10] == 2
        offset = 20
    elif link_type in (LINK_RAW, LINK_IPV4, LINK_IPV6):
        if not data:
            return PacketInfo(length, "OTHER", malformed=True)
        version = data[0] >> 4
        ethertype, offset = (ETHERTYPE_IPV4 if version == 4 else ETHERTYPE_IPV6 if version == 6 else 0), 0
    else:
        return PacketInfo(length, "OTHER")

    if ethertype == ETHERTYPE_ARP:
        return PacketInfo(length, "ARP", broadcast=broadcast, multicast=multicast)
    if ethertype == ETHERTYPE_IPV4:
        return _ipv4(data, offset, length, broadcast, multicast)
    if ethertype == ETHERTYPE_IPV6:
        return _ipv6(data, offset, length, broadcast, multicast)
    return PacketInfo(length, "OTHER", broadcast=broadcast, multicast=multicast)


def _ipv4(data: bytes, offset: int, length: int, broadcast: bool, multicast: bool) -> PacketInfo:
    if len(data) < offset + 20 or data[offset] >> 4 != 4:
        return PacketInfo(length, "IPV4_OTHER", broadcast=broadcast, multicast=multicast, malformed=True)
    header = (data[offset] & 0x0F) * 4
    if header < 20:
        return PacketInfo(length, "IPV4_OTHER", broadcast=broadcast, multicast=multicast, malformed=True)
    protocol = data[offset + 9]
    source = str(ipaddress.IPv4Address(data[offset + 12:offset + 16]))
    destination_ip = ipaddress.IPv4Address(data[offset + 16:offset + 20])
    destination = str(destination_ip)
    broadcast = broadcast or destination == "255.255.255.255"
    multicast = multicast or destination_ip.is_multicast
    fragment_offset = struct.unpack("!H", data[offset + 6:offset + 8])[0] & 0x1FFF
    common = dict(source=source, destination=destination, broadcast=broadcast, multicast=multicast)
    if protocol == IPPROTO_ICMP:
        return PacketInfo(length, "ICMP", **common)
    if protocol == IPPROTO_IGMP:
        return PacketInfo(length, "IGMP", **common)
    if protocol in (IPPROTO_TCP, IPPROTO_UDP):
        if fragment_offset:  # un fragmento que no es el primero no trae los puertos
            return PacketInfo(length, "TCP" if protocol == IPPROTO_TCP else "UDP",
                              transport="TCP" if protocol == IPPROTO_TCP else "UDP", **common)
        return _transport(data, offset + header, protocol, length, common)
    return PacketInfo(length, "IPV4_OTHER", **common)


def _ipv6(data: bytes, offset: int, length: int, broadcast: bool, multicast: bool) -> PacketInfo:
    if len(data) < offset + 40 or data[offset] >> 4 != 6:
        return PacketInfo(length, "IPV6_OTHER", broadcast=broadcast, multicast=multicast, malformed=True)
    next_header = data[offset + 6]
    source = str(ipaddress.IPv6Address(data[offset + 8:offset + 24]))
    destination_ip = ipaddress.IPv6Address(data[offset + 24:offset + 40])
    common = dict(source=source, destination=str(destination_ip), broadcast=broadcast,
                  multicast=multicast or destination_ip.is_multicast)
    position = offset + 40
    for _ in range(8):  # como mucho 8 extensiones; más sería un paquete fabricado
        if next_header not in IPV6_EXTENSIONS:
            break
        if len(data) < position + 8:
            return PacketInfo(length, "IPV6_OTHER", malformed=True, **common)
        if next_header == 44:  # fragmento: tamaño fijo; si no es el primero, no hay puertos
            if struct.unpack("!H", data[position + 2:position + 4])[0] >> 3:
                return PacketInfo(length, "IPV6_OTHER", **common)
            next_header, position = data[position], position + 8
        else:
            next_header, position = data[position], position + (data[position + 1] + 1) * 8
    if next_header == IPPROTO_ICMPV6:
        return PacketInfo(length, "ICMPV6", **common)
    if next_header in (IPPROTO_TCP, IPPROTO_UDP):
        return _transport(data, position, next_header, length, common)
    return PacketInfo(length, "IPV6_OTHER", **common)
