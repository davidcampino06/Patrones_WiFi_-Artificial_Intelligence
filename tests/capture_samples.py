"""Paquetes y archivos de captura sintéticos para las pruebas: se arman byte a byte, sin red real ni controladores.

Los contenidos llevan a propósito textos como "password=secreto" o "cookie": las pruebas comprueban que nada de eso
llega a las estadísticas.
"""
from __future__ import annotations

import ipaddress
import struct

OWN_MAC = bytes.fromhex("3c970e000003")
ROUTER_MAC = bytes.fromhex("50c7bf000002")
BROADCAST_MAC = b"\xff" * 6
MDNS_MAC = bytes.fromhex("01005e0000fb")
IPV6_MULTICAST_MAC = bytes.fromhex("333300000001")
SECRET = b"POST /login password=secreto cookie=sesion"


def ethernet(destination: bytes, source: bytes, ethertype: int, payload: bytes) -> bytes:
    return destination + source + struct.pack("!H", ethertype) + payload


def ipv4(source: str, destination: str, protocol: int, payload: bytes, fragment_offset: int = 0) -> bytes:
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 1, fragment_offset, 64, protocol, 0,
                         ipaddress.IPv4Address(source).packed, ipaddress.IPv4Address(destination).packed)
    return header + payload


def ipv6(source: str, destination: str, next_header: int, payload: bytes) -> bytes:
    header = struct.pack("!IHBB16s16s", 6 << 28, len(payload), next_header, 64,
                         ipaddress.IPv6Address(source).packed, ipaddress.IPv6Address(destination).packed)
    return header + payload


def tcp(source_port: int, destination_port: int, payload: bytes = b"") -> bytes:
    return struct.pack("!HHIIBBHHH", source_port, destination_port, 1, 0, 5 << 4, 0x18, 1024, 0, 0) + payload


def udp(source_port: int, destination_port: int, payload: bytes = b"") -> bytes:
    return struct.pack("!HHHH", source_port, destination_port, 8 + len(payload), 0) + payload


def arp_request() -> bytes:
    body = struct.pack("!HHBBH6s4s6s4s", 1, 0x0800, 6, 4, 1, OWN_MAC, ipaddress.IPv4Address("192.168.1.2").packed,
                       b"\x00" * 6, ipaddress.IPv4Address("192.168.1.1").packed)
    return ethernet(BROADCAST_MAC, OWN_MAC, 0x0806, body)


def https_out() -> bytes:
    return ethernet(ROUTER_MAC, OWN_MAC, 0x0800, ipv4("192.168.1.2", "142.250.78.14", 6, tcp(51234, 443, SECRET)))


def https_in() -> bytes:
    return ethernet(OWN_MAC, ROUTER_MAC, 0x0800, ipv4("142.250.78.14", "192.168.1.2", 6, tcp(443, 51234, SECRET)))


def dns_query() -> bytes:
    return ethernet(ROUTER_MAC, OWN_MAC, 0x0800, ipv4("192.168.1.2", "192.168.1.1", 17, udp(53000, 53, b"banco.com")))


def mdns() -> bytes:
    return ethernet(MDNS_MAC, ROUTER_MAC, 0x0800, ipv4("192.168.1.40", "224.0.0.251", 17, udp(5353, 5353)))


def dhcp_discover() -> bytes:
    return ethernet(BROADCAST_MAC, ROUTER_MAC, 0x0800, ipv4("0.0.0.0", "255.255.255.255", 17, udp(68, 67)))


def icmpv6_multicast() -> bytes:
    return ethernet(IPV6_MULTICAST_MAC, ROUTER_MAC, 0x86DD, ipv6("fe80::1", "ff02::1", 58, b"\x86\x00\x00\x00"))
