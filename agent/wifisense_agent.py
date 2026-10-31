#!/usr/bin/env python3
"""Agente WiFiSense: mide tu red Wi-Fi desde un computador de la casa y envía un reporte a WiFiSense.

Solo usa la biblioteca estándar de Python 3.9 o superior (no hay que instalar nada) y funciona en Windows y Linux.

    python wifisense_agent.py pair CODIGO  conecta el agente con el código de Mi Wi-Fi > Instalar agente
    python wifisense_agent.py setup        guarda la clave del agente (se crea en Mi Wi-Fi > Agente)
    python wifisense_agent.py scan         muestra lo que mediría, sin enviar nada
    python wifisense_agent.py run          envía un reporte cada 5 minutos (Ctrl + C para detener)
    python wifisense_agent.py run --once   envía un solo reporte

Qué mide y qué envía:
  * Datos del Wi-Fi que muestra el sistema (nombre, tipo de seguridad, señal, canal, banda) y cuántas redes vecinas
    usan cada canal, para recomendarte el canal con menos interferencia.
  * Latencia, variación (jitter) y pérdida hacia internet y hacia el router.
  * Cuántos equipos hay conectados y, de cada uno, el fabricante (según la MAC) y el nombre que anuncia en la red,
    para que los reconozcas como en el Bluetooth. Las direcciones MAC NO salen de tu computador: se envía una huella
    SHA-256 con una sal aleatoria propia de esta instalación.
  * Qué puertos de administración del router aceptan conexiones (solo se intenta conectar, no se envían datos).
  * El tráfico de este computador desde el reporte anterior (bytes y paquetes por protocolo TCP, UDP e ICMP), leído
    de los contadores del sistema. Solo se guarda cuando el agente es el sensor de una red del equipo WiFiSense.
"""
from __future__ import annotations

import argparse
import getpass
import hashlib
import ipaddress
import json
import os
import platform
import re
import secrets
import socket
import statistics
import struct
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Callable, Optional

AGENT_VERSION = "1.8.0"
DEFAULT_SERVER = "https://patroneswifibackend-production.up.railway.app"
REPORT_PATH = "/api/agent/reports"
PAIR_PATH = "/api/agent/pair"
SCANS_PATH = "/api/agent/scans"
NEXT_SCAN_PATH = "/api/agent/scans/next"
SCAN_POLL_SECONDS = 30  # entre reportes, cada cuánto se pregunta si el usuario pidió escanear
DEFAULT_INTERVAL = 300
MIN_INTERVAL = 60
ROUTER_PORTS = (21, 22, 23, 53, 80, 443, 445, 1900, 7547, 8080, 8443)
INTERNET_TARGET = ("1.1.1.1", 443)
SAMPLES = 10
MAX_DEVICES = 256
IS_WINDOWS = os.name == "nt"


# --------------------------------------------------------------------------------------------- comandos del sistema

def decode(raw: bytes) -> str:
    """netsh escribe en la página de códigos de la consola (cp850 en español); se prueba UTF-8 primero."""
    for encoding in ("utf-8", "oem", "cp850", "latin-1"):
        try:
            return raw.decode(encoding)
        except (UnicodeDecodeError, LookupError):
            continue
    return raw.decode("latin-1", errors="replace")


def run_command(args: list[str], timeout: float = 15) -> str:
    """Salida del comando, o cadena vacía si no existe o falla. Nunca usa el shell."""
    try:
        result = subprocess.run(args, capture_output=True, timeout=timeout,
                                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except (OSError, subprocess.SubprocessError):
        return ""
    return decode(result.stdout)


def read_file(path: str) -> str:
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


# ------------------------------------------------------------------------------------------------------- Wi-Fi

try:  # el agente como paquete (pruebas) o como script suelto (PyInstaller, python wifisense_agent.py)
    from agent.wifi_text import (authentication_of, band_of, cipher_of, first_number, key_values, normalize_key,
                                 split_nmcli, CIPHERS)
except ImportError:  # pragma: no cover
    from wifi_text import (authentication_of, band_of, cipher_of, first_number, key_values, normalize_key,
                           split_nmcli, CIPHERS)

# Prefijos de cada campo en inglés y en español (incluye cómo se ven si la consola dañó las tildes).
WIFI_KEYS = {
    "state": ("state", "estado"),
    "ssid": ("ssid",),
    "authentication": ("authentication", "autenticac"),
    "cipher": ("cipher", "cifrado"),
    "signal": ("signal", "senal", "seal"),
    "rssi": ("rssi",),
    "channel": ("channel", "canal"),
    "band": ("band",),
    "radio": ("radiotype", "tipoderadio"),
    "rx": ("receiverate", "velocidadderecep"),
    "tx": ("transmitrate", "velocidaddetrans"),
}


def field_of(key: str) -> Optional[str]:
    normalized = normalize_key(key)
    if normalized in ("bssid", "apbssid"):
        return None
    for field, prefixes in WIFI_KEYS.items():
        if field == "ssid":
            if normalized == "ssid":
                return field
        elif any(normalized.startswith(prefix) for prefix in prefixes):
            return field
    return None


def parse_netsh_interfaces(text: str) -> dict:
    """Interfaz Wi-Fi conectada en 'netsh wlan show interfaces' (Windows, en español o inglés)."""
    blocks, current = [], {}
    for key, value in key_values(text):
        if normalize_key(key) in ("name", "nombre") and current:
            blocks.append(current)
            current = {}
        field = field_of(key)
        if field and field not in current:
            current[field] = value
    if current:
        blocks.append(current)
    connected = [b for b in blocks if normalize_key(b.get("state", "")).startswith(("connected", "conectado"))]
    block = (connected or [b for b in blocks if b.get("ssid")] or [{}])[0]
    if not block.get("ssid"):
        return {}

    channel = first_number(block.get("channel", ""))
    signal_pct = first_number(block.get("signal", ""))
    rssi = first_number(block.get("rssi", ""))
    return {
        "ssid": block["ssid"][:64],
        "authentication": authentication_of(block.get("authentication", ""), block.get("cipher", "")),
        "cipher": cipher_of(block.get("cipher", "")),
        "signalPercent": int(signal_pct) if signal_pct is not None else None,
        "signalDbm": int(rssi) if rssi is not None else (int(signal_pct / 2 - 100) if signal_pct is not None else None),
        "channel": int(channel) if channel else None,
        "band": band_of(block.get("band", ""), int(channel) if channel else None),
        "radioType": block.get("radio") or None,
        "rxRateMbps": first_number(block.get("rx", "")),
        "txRateMbps": first_number(block.get("tx", "")),
    }


def parse_netsh_networks(text: str) -> list[tuple[str, int]]:
    """(nombre de red, canal) de cada punto de acceso en 'netsh wlan show networks mode=bssid'."""
    found, ssid = [], ""
    for key, value in key_values(text):
        normalized = normalize_key(key)
        if normalized == "ssid":  # "SSID 1 : Mi red" (los dígitos se quitan al normalizar)
            ssid = value
        elif field_of(key) == "channel":
            channel = first_number(value)
            if channel:
                found.append((ssid, int(channel)))
    return found


def parse_nmcli(text: str) -> tuple[dict, list[tuple[str, int]]]:
    """Salida de 'nmcli -t -f ACTIVE,SSID,CHAN,FREQ,SIGNAL,SECURITY,RATE dev wifi list' (Linux)."""
    info, networks = {}, []
    for line in text.splitlines():
        parts = split_nmcli(line)
        if len(parts) < 7:
            continue
        active, ssid, chan, freq, signal, security, rate = parts[:7]
        channel = int(chan) if chan.isdigit() else None
        if channel:
            networks.append((ssid, channel))
        if active.lower() in ("yes", "sí", "si") and not info:
            signal_pct = first_number(signal)
            freq_mhz = first_number(freq)
            info = {
                "ssid": ssid,
                "authentication": authentication_of(security or "OPEN"),
                "cipher": None,
                "signalPercent": int(signal_pct) if signal_pct is not None else None,
                "signalDbm": int(signal_pct / 2 - 100) if signal_pct is not None else None,
                "channel": channel,
                "band": band_of(f"{freq_mhz / 1000:.1f}" if freq_mhz else "", channel),
                "radioType": None,
                "rxRateMbps": first_number(rate),
                "txRateMbps": None,
            }
    return info, networks


def neighbors_on_channel(networks: list[tuple[str, int]], ssid: str, channel: Optional[int]) -> tuple[int, int]:
    """(redes vecinas en el mismo canal, redes vecinas en total); no cuenta los puntos de acceso de tu propia red."""
    others = [(name, ch) for name, ch in networks if name != ssid]
    return sum(1 for _, ch in others if ch == channel), len({name for name, _ in others})


MAX_CHANNELS = 60


def channel_counts(networks: list[tuple[str, int]], ssid: str) -> list[dict]:
    """Cuántos puntos de acceso vecinos (sin contar los de tu propia red) usa cada canal, de menor a mayor. Con esto la
    IA recomienda a qué canal mover el router para tener menos interferencia."""
    counts: dict[int, int] = {}
    for name, channel in networks:
        if name != ssid and 0 < channel <= 196:
            counts[channel] = counts.get(channel, 0) + 1
    return [{"channel": channel, "networks": count} for channel, count in sorted(counts.items())][:MAX_CHANNELS]


LOCATION_HINT = ("location", "ubicaci")


def wifi_info() -> dict:
    if IS_WINDOWS:
        text = run_command(["netsh", "wlan", "show", "interfaces"])
        info = parse_netsh_interfaces(text)
        if not info and any(hint in text.lower() for hint in LOCATION_HINT):
            info = {"note": "LOCATION_PERMISSION"}
        networks = parse_netsh_networks(run_command(["netsh", "wlan", "show", "networks", "mode=bssid"]))
    else:
        info, networks = parse_nmcli(run_command(
            ["nmcli", "-t", "-f", "ACTIVE,SSID,CHAN,FREQ,SIGNAL,SECURITY,RATE", "dev", "wifi", "list"]))
    if info.get("ssid"):
        same, total = neighbors_on_channel(networks, info["ssid"], info.get("channel"))
        info["neighborsSameChannel"], info["neighborsTotal"] = same, total
        info["channelCounts"] = channel_counts(networks, info["ssid"])
    return info


# ------------------------------------------------------------------------------------------------ red local

IPV4 = r"(\d{1,3}(?:\.\d{1,3}){3})"


def parse_route_print(text: str) -> Optional[str]:
    """Puerta de enlace con menor métrica en 'route print -4 0.0.0.0' (Windows)."""
    routes = re.findall(rf"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+{IPV4}\s+{IPV4}\s+(\d+)", text, re.MULTILINE)
    return min(routes, key=lambda r: int(r[2]))[0] if routes else None


def parse_proc_route(text: str) -> Optional[str]:
    """Puerta de enlace en /proc/net/route (Linux): destino 00000000, dirección en hexadecimal little-endian."""
    for line in text.splitlines()[1:]:
        parts = line.split()
        if len(parts) > 2 and parts[1] == "00000000" and parts[2] != "00000000":
            return socket.inet_ntoa(int(parts[2], 16).to_bytes(4, "little"))
    return None


def default_gateway() -> Optional[str]:
    if IS_WINDOWS:
        return parse_route_print(run_command(["route", "print", "-4", "0.0.0.0"]))
    return parse_proc_route(read_file("/proc/net/route"))


def local_ip() -> Optional[str]:
    """IP de este equipo en la red de la casa. Un socket UDP 'conectado' no envía ningún paquete."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        try:
            sock.connect(INTERNET_TARGET)
            return sock.getsockname()[0]
        except OSError:
            return None


MAC = r"((?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2})"


def parse_neighbors(text: str) -> dict[str, str]:
    """IP -> MAC de la tabla ARP ('arp -a' en Windows o /proc/net/arp en Linux)."""
    table = {}
    for line in text.splitlines():
        match = re.search(rf"{IPV4}\s+(?:\S+\s+){{0,2}}?{MAC}", line)
        if not match:
            continue
        ip, mac = match.group(1), match.group(2).lower().replace("-", ":")
        if mac == "00:00:00:00:00:00" or not is_unicast(mac):
            continue
        table[ip] = mac
    return table


def is_unicast(mac: str) -> bool:
    """Descarta difusión y multidifusión (el bit menos significativo del primer byte en 1)."""
    return not int(mac.split(":")[0], 16) & 1


def same_subnet(ips: dict[str, str], own_ip: str, prefix: int = 24) -> dict[str, str]:
    network = ipaddress.ip_network(f"{own_ip}/{prefix}", strict=False)
    return {ip: mac for ip, mac in ips.items()
            if ipaddress.ip_address(ip) in network and ipaddress.ip_address(ip) != network.broadcast_address}


# Hasta la 1.9 el agente suponía que la red era /24 (254 direcciones) y no veía a los equipos con una IP fuera de ese
# pedazo: en las redes grandes (universidades, empresas) dos portátiles juntos pueden tener 10.20.5.40 y 10.20.7.12.
# Desde la 2.0.0 se lee la máscara real; para no inundar una red enorme, se despiertan como mucho las 1022
# direcciones de alrededor (/22). Lo que ya está en la tabla ARP se acepta con la máscara real.
DEFAULT_PREFIX = 24
WIDEST_WAKE_PREFIX = 22


def parse_ipconfig_prefix(text: str, own_ip: str) -> Optional[int]:
    """Máscara de la interfaz con ``own_ip`` en 'ipconfig' (Windows, en cualquier idioma): la primera línea después
    de la IP cuyo valor es una máscara válida (255.x.x.x)."""
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if not re.search(rf"(?<![\d.]){re.escape(own_ip)}(?![\d.])", line):
            continue
        for following in lines[index + 1:index + 6]:
            value = following.split(":", 1)[-1].strip()
            if re.fullmatch(r"255\.\d{1,3}\.\d{1,3}\.\d{1,3}", value):
                try:
                    return ipaddress.IPv4Network(f"0.0.0.0/{value}").prefixlen
                except ValueError:
                    return None
        return None
    return None


def parse_ip_addr_prefix(text: str, own_ip: str) -> Optional[int]:
    """Prefijo de ``own_ip`` en 'ip -o -4 addr show' (Linux): 'inet 10.20.5.40/21 brd ...'."""
    match = re.search(rf"inet {re.escape(own_ip)}/(\d{{1,2}})\b", text)
    return int(match.group(1)) if match and 8 <= int(match.group(1)) <= 32 else None


def network_prefix(own_ip: Optional[str]) -> int:
    """El prefijo real de la red de este computador; /24 si el sistema no lo dice."""
    if not own_ip:
        return DEFAULT_PREFIX
    if IS_WINDOWS:
        found = parse_ipconfig_prefix(run_command(["ipconfig"]), own_ip)
    else:
        found = parse_ip_addr_prefix(run_command(["ip", "-o", "-4", "addr", "show"]), own_ip)
    return found if found and 8 <= found <= 30 else DEFAULT_PREFIX


def wake_neighbors(own_ip: str, prefix: int = DEFAULT_PREFIX) -> None:
    """Un datagrama vacío al puerto 9 (discard) de cada dirección de la red obliga al sistema a preguntar por ARP
    quién la tiene, y así la tabla ARP se llena con los equipos encendidos, aunque no respondan al ping. En una red
    más grande que /22 solo se despiertan las direcciones de alrededor (ver WIDEST_WAKE_PREFIX)."""
    network = ipaddress.ip_network(f"{own_ip}/{max(prefix, WIDEST_WAKE_PREFIX)}", strict=False)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        for host in network.hosts():
            try:
                sock.sendto(b"", (str(host), 9))
            except OSError:
                pass


# Fabricante según los primeros 3 bytes de la MAC (el OUI, que la IEEE asigna a cada fabricante). Sirve para que el
# usuario reconozca «un equipo Apple» o «un equipo Samsung» sin que la MAC salga del computador. Es una lista de los
# fabricantes más comunes en una casa; si el OUI no está, no se envía fabricante (queda "equipo sin identificar").
OUI_VENDORS = {
    "fcfbfb": "Apple", "a4c361": "Apple", "d0817a": "Apple", "f0d1a9": "Apple", "3c0754": "Apple", "a85c2c": "Apple",
    "ac1f74": "Apple", "88665a": "Apple", "f4f15a": "Apple", "9027e4": "Apple", "e0accb": "Apple", "dca904": "Apple",
    "a4b197": "Apple", "d49a20": "Apple", "7cd1c3": "Apple", "609217": "Apple", "8866a5": "Apple", "f0766f": "Apple",
    "c869cd": "Apple", "04d3cf": "Apple", "8c8590": "Apple", "a860b6": "Apple", "2c6134": "Apple",
    "ecfabc": "Samsung", "8425db": "Samsung", "f409d8": "Samsung", "5001bb": "Samsung", "bc1485": "Samsung",
    "e8508b": "Samsung", "a02bb8": "Samsung", "34231f": "Samsung", "c87e75": "Samsung", "d0667b": "Samsung",
    "8c7712": "Samsung", "1c62b8": "Samsung", "5056bf": "Samsung", "bc8ccd": "Samsung", "0023d7": "Samsung",
    "fcc734": "Samsung", "b8d9ce": "Samsung", "78f882": "Samsung",
    "286c07": "Xiaomi", "64b473": "Xiaomi", "f8a2d6": "Xiaomi", "acc1ee": "Xiaomi", "2082c0": "Xiaomi",
    "7c1dd9": "Xiaomi", "ac898c": "Xiaomi", "9c99a0": "Xiaomi", "3480b3": "Xiaomi", "d4970b": "Xiaomi",
    "50ec50": "Xiaomi", "a09f10": "Xiaomi", "fc64ba": "Xiaomi",
    "48e1e9": "Huawei", "70723c": "Huawei", "e8089f": "Huawei", "c40528": "Huawei", "00e0fc": "Huawei",
    "d8490b": "Huawei", "10b1f8": "Huawei", "ac4e91": "Huawei", "b4cd27": "Huawei", "24692a": "Huawei",
    "e0247f": "Honor", "80a359": "Honor",
    "f0d7aa": "Motorola", "ccc3ea": "Motorola", "40786a": "Motorola",
    "6c5697": "Lenovo", "70f087": "Lenovo",
    "c4f561": "Oppo", "d4a148": "Oppo",
    "94652d": "OnePlus", "64a2f9": "OnePlus",
    "3c28a6": "Vivo", "381d14": "Vivo",
    "10682b": "Realme",
    "f8a9d0": "LG", "d013fd": "LG", "a816b2": "LG", "00e091": "LG",
    "3c5ab4": "Google", "f4f5e8": "Google", "1c53f9": "Google", "d8eb97": "Google", "48d6d5": "Google",
    "1844e3": "Google", "6466b3": "Google", "9cfc01": "Google", "e4f042": "Google", "f4039a": "Google",
    "fc65de": "Amazon", "44650d": "Amazon", "68543d": "Amazon", "ac63be": "Amazon", "f0272d": "Amazon",
    "f8f005": "Amazon", "0c47c9": "Amazon", "40b4cd": "Amazon", "50dce7": "Amazon", "8871e5": "Amazon",
    "5c628b": "TP-Link", "f4ec38": "TP-Link", "c006c3": "TP-Link", "503eaa": "TP-Link", "d80d17": "TP-Link",
    "ec086b": "TP-Link", "a42bb0": "TP-Link", "9c5322": "TP-Link", "60a4b7": "TP-Link", "1c61b4": "TP-Link",
    "003192": "TP-Link",
    "c4e90a": "Mercusys",
    "d8070b": "Tenda", "c83a35": "Tenda",
    "ec2280": "D-Link", "1cbdb9": "D-Link",
    "9cd36d": "Netgear", "2cb05d": "Netgear",
    "04d9f5": "Asus", "88d7f6": "Asus", "2c4d54": "Asus",
    "788a20": "Ubiquiti", "fcecda": "Ubiquiti", "e063da": "Ubiquiti",
    "4c5e0c": "MikroTik", "cc2de0": "MikroTik",
    "002674": "ZTE", "4c09b4": "ZTE",
    "341513": "Technicolor",
    "84a8e4": "Sagemcom",
    "b827eb": "Raspberry Pi", "dca632": "Raspberry Pi", "e45f01": "Raspberry Pi",
    "001a11": "Intel", "3c970e": "Intel", "7c7a91": "Intel", "e4a471": "Intel", "a0a8cd": "Intel", "9cb6d0": "Intel",
    "a4c3f0": "Intel", "9c305b": "Intel",
    "f8e43b": "Dell", "f8bc12": "Dell",
    "3ca82a": "HP", "308d99": "HP",
    "001a4d": "Gigabyte",
    "d8bbc1": "Microsoft", "001ddf": "Microsoft", "582f40": "Microsoft", "7ced8d": "Microsoft",
    "c83f26": "Sony", "e89309": "Sony", "a8e3ee": "Sony", "fc0fe6": "Sony", "78c881": "Sony",
    "001315": "Nintendo", "0009bf": "Nintendo", "e0e751": "Nintendo",
    "cc6da0": "Roku", "b83e59": "Roku",
    "b8278a": "Sonos", "5cae8b": "Sonos",
    "a020a6": "Espressif", "246f28": "Espressif", "8caab5": "Espressif", "d8f15b": "Espressif",
    "bcff4d": "Espressif",
    "d4a651": "Tuya", "68572d": "Tuya",
    "4419b6": "Hikvision",
    "bc325f": "Dahua",
    "9c8ecd": "Reolink",
    "e84e06": "Realtek",
    "000c29": "VMware", "005056": "VMware",
    "080027": "VirtualBox",
    "70b3d5": "Cámara IP",
    "001788": "Philips Hue", "ecb5fa": "Philips Hue",
}


def vendor_of(mac: str) -> Optional[str]:
    """Fabricante del equipo según el OUI de su MAC, o None si no está en la lista."""
    oui = mac.lower().replace(":", "").replace("-", "")[:6]
    return OUI_VENDORS.get(oui)


def is_private_mac(mac: str) -> bool:
    """MAC «privada» o aleatoria: el bit de administración local (el segundo menos significativo del primer byte) en 1.
    Los celulares y tabletas modernos (iPhone desde iOS 14, Android desde la versión 10) usan una así en cada red
    Wi-Fi para que no los rastreen; por eso su fabricante no se puede saber, pero casi siempre es un celular o tableta."""
    return bool(int(mac.replace("-", ":").split(":")[0], 16) & 0b10)


# Sufijos que el router o el sistema le agregan al nombre y que no aportan nada al usuario.
NAME_SUFFIXES = (".lan", ".home", ".local", ".localdomain", ".home.arpa", ".gateway")


def clean_hostname(raw: Optional[str], ip: str) -> Optional[str]:
    """Deja el nombre del equipo legible ('iPhone-de-Ana'), o None si el sistema solo devolvió la IP o algo vacío."""
    if not raw:
        return None
    name = raw.strip().rstrip(".")
    lowered = name.lower()
    for suffix in NAME_SUFFIXES:
        if lowered.endswith(suffix):
            name = name[: -len(suffix)]
            break
    # Un nombre que es la propia IP (DNS inverso que devuelve la dirección) no dice nada.
    if not name or name == ip or re.fullmatch(r"[0-9.]+", name):
        return None
    return name[:63]


def hostname_of(ip: str, timeout: float = 1.0) -> Optional[str]:
    """Nombre que anuncia el equipo en la red (como lo muestran el Bluetooth o la zona Wi-Fi del celular). Se intenta
    por DNS inverso, en Windows por NetBIOS y por último por mDNS (lo usan iPhone, Mac, Chromecast, impresoras y
    muchos televisores); si nadie responde a tiempo, queda sin nombre."""
    previous = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        name = clean_hostname(socket.gethostbyaddr(ip)[0], ip)
        if name:
            return name
    except (OSError, UnicodeError):
        pass
    finally:
        socket.setdefaulttimeout(previous)
    if IS_WINDOWS:
        name = netbios_name(ip)
        if name:
            return name
    return mdns_name(ip, timeout)


MDNS_GROUP = ("224.0.0.251", 5353)
DNS_PTR = 12


def dns_name(name: str) -> bytes:
    """Nombre en el formato de DNS: cada parte con su longitud delante y un 0 al final."""
    return b"".join(bytes([len(part)]) + part.encode() for part in name.split(".") if part) + b"\0"


def mdns_query(ip: str) -> bytes:
    """Pregunta PTR por la IP al revés (4.3.2.1.in-addr.arpa) con el bit QU, para que el equipo responda directo."""
    reverse = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
    header = struct.pack("!HHHHHH", 0, 0, 1, 0, 0, 0)  # id 0, consulta normal, 1 pregunta
    return header + dns_name(reverse) + struct.pack("!HH", DNS_PTR, 0x8001)  # tipo PTR, clase IN con bit QU


def read_dns_name(data: bytes, offset: int, depth: int = 0) -> tuple[str, int]:
    """Lee un nombre de un paquete DNS (con los punteros de compresión) y devuelve (nombre, posición siguiente)."""
    parts, end = [], None
    while depth < 20:
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0 == 0xC0:  # puntero: el resto del nombre está en otra parte del paquete
            pointer = struct.unpack_from("!H", data, offset)[0] & 0x3FFF
            end = end if end is not None else offset + 2
            offset, depth = pointer, depth + 1
            continue
        parts.append(data[offset + 1: offset + 1 + length].decode("utf-8", "replace"))
        offset += 1 + length
    return ".".join(parts), end if end is not None else offset


def parse_mdns_ptr(data: bytes) -> Optional[str]:
    """Primer registro PTR de las respuestas de un paquete mDNS (el nombre .local del equipo), o None."""
    try:
        _, flags, questions, answers = struct.unpack_from("!HHHH", data, 0)
        if not flags & 0x8000:  # no es una respuesta
            return None
        offset = 12
        for _ in range(questions):
            offset = read_dns_name(data, offset)[1] + 4
        for _ in range(answers):
            offset = read_dns_name(data, offset)[1]
            rtype, _, _, length = struct.unpack_from("!HHIH", data, offset)
            offset += 10
            if rtype == DNS_PTR:
                return read_dns_name(data, offset)[0]
            offset += length
    except (struct.error, IndexError):
        pass
    return None


def mdns_name(ip: str, timeout: float = 1.0) -> Optional[str]:
    """Nombre del equipo por mDNS (Bonjour). Se envía desde un puerto cualquiera, así el equipo responde directo a
    este computador y no hace falta ocupar el puerto 5353."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(mdns_query(ip), MDNS_GROUP)
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                data, _ = sock.recvfrom(4096)
                name = parse_mdns_ptr(data)
                if name:
                    return clean_hostname(name, ip)
    except OSError:
        pass
    return None


def netbios_name(ip: str) -> Optional[str]:
    """Nombre NetBIOS en Windows ('nbtstat -A ip'): la primera entrada <20> o <00> de tipo UNIQUE es el del equipo."""
    for line in run_command(["nbtstat", "-A", ip], timeout=3).splitlines():
        match = re.match(r"\s*(\S.*?)\s+<(00|20)>\s+UNIQUE", line)
        if match:
            return clean_hostname(match.group(1), ip)
    return None


def mac_fingerprint(mac: str, salt: str) -> str:
    return hashlib.sha256(f"{salt}:{mac.lower()}".encode()).hexdigest()[:24]


def own_mac() -> Optional[str]:
    import uuid
    node = uuid.getnode()
    if node >> 40 & 1:  # uuid inventó un número al azar: no hay MAC
        return None
    return ":".join(f"{node >> shift & 0xff:02x}" for shift in range(40, -1, -8))


try:  # el agente como paquete (pruebas) o como script suelto (PyInstaller, python wifisense_agent.py)
    from agent import device_discovery as discovery
    from agent import wifi_scan
    from agent import router_sources
except ImportError:  # pragma: no cover
    import device_discovery as discovery
    import wifi_scan
    import router_sources

IDENTITY_MAX_AGE = 1800  # lo que anuncian los equipos y sus puertos cambia poco: se revisa cada 30 minutos
_identity_cache: dict = {"at": 0.0, "macs": frozenset(), "by_mac": {}}


def identities(by_ip: dict[str, str], own_ip: str, gateway: Optional[str], now: Optional[float] = None,
               identify=None) -> dict[str, dict]:
    """Nombre, modelo y tipo sugerido de cada MAC. Se vuelve a preguntar a la red cada 30 minutos o cuando aparece un
    equipo nuevo (en el modo de identificar el agente reporta cada minuto y no debe escanear cada vez)."""
    now = time.time() if now is None else now
    identify = identify or discovery.identify
    macs = frozenset(by_ip.values())
    cache = _identity_cache
    if now - cache["at"] > IDENTITY_MAX_AGE or not macs <= cache["macs"]:
        found = identify(list(by_ip), own_ip, gateway)
        cache.update(at=now, macs=macs, by_mac={mac: found.get(ip, {}) for ip, mac in by_ip.items()})
    return cache["by_mac"]


def devices(own_ip: Optional[str], salt: str, wait: float = 2.0, gateway: Optional[str] = None) -> list[dict]:
    """Equipos conectados a la red (incluido este), como {huella, fabricante, nombre}. La huella es SHA-256 con sal:
    la MAC no sale del computador. El fabricante viene del OUI de la MAC y el nombre del equipo (como en el Bluetooth
    o la zona Wi-Fi) de lo que anuncia, de su solicitud DHCP o de DNS inverso, NetBIOS o mDNS; cualquiera puede faltar. Si la MAC es
    privada (aleatoria) se marca, porque casi siempre es un celular o una tableta."""
    if not own_ip:
        return []
    prefix = network_prefix(own_ip)
    wake_neighbors(own_ip, prefix)
    time.sleep(wait)
    table = run_command(["arp", "-a"]) if IS_WINDOWS else read_file("/proc/net/arp")
    by_ip = same_subnet(parse_neighbors(table), own_ip, prefix)
    mine = own_mac()
    if mine:
        by_ip[own_ip] = mine
    own_name = clean_hostname(socket.gethostname(), own_ip)
    # Los nombres se resuelven en paralelo porque cada uno puede tardar hasta un segundo.
    with ThreadPoolExecutor(max_workers=min(len(by_ip), 32) or 1) as pool:
        names = dict(zip(by_ip, pool.map(hostname_of, by_ip)))
    # Lo que cada equipo dijo al pedir dirección (DHCP): se escucha desde el primer reporte y se acumula.
    discovery.DHCP.start()
    dhcp = discovery.DHCP.snapshot()
    try:
        announced = identities(by_ip, own_ip, gateway)
    except Exception as error:  # reconocer equipos es un extra: si falla, se envían como antes
        print(f"  aviso: no se pudo identificar los equipos: {error}", file=sys.stderr)
        announced = {}
    from_router = router_names(gateway, [ip for ip in by_ip if ip not in (own_ip, gateway)])
    found = []
    for ip, mac in sorted(by_ip.items(), key=lambda item: item[1]):
        found.append(describe_device(ip, mac, salt, own_ip, gateway, own_name if ip == own_ip else names.get(ip),
                                     announced.get(mac, {}), dhcp.get(mac, {}), from_router.get(ip)))
    return found[:MAX_DEVICES]


def router_names(gateway: Optional[str], ips: list[str], source_factory=None) -> dict[str, str]:
    """Nombres que el propio router conoce (su DNS, sin clave). Si el router no responde, no hay nombres de ahí."""
    if not gateway or not ips:
        return {}
    source = (source_factory or router_sources.source_for)(gateway)
    if source is None:
        return {}
    try:
        return {ip: name for ip, name in source.names(ips).items() if clean_hostname(name, ip)}
    except Exception as error:  # el router puede no tener DNS: es un extra
        print(f"  aviso: el router no respondió nombres: {error}", file=sys.stderr)
        return {}


def same_name(first: Optional[str], second: Optional[str]) -> bool:
    """«Portatil-de-Ana» y «portatil-de-ana.lan» son el mismo nombre."""
    def plain(name: Optional[str]) -> str:
        return re.sub(r"[^a-z0-9]", "", (name or "").lower().split(".")[0])
    return bool(plain(first)) and plain(first) == plain(second)


def describe_device(ip: str, mac: str, salt: str, own_ip: str, gateway: Optional[str], hostname: Optional[str],
                    announced: dict, dhcp: Optional[dict] = None, router_name: Optional[str] = None) -> dict:
    """Lo que se envía de un equipo: su huella (nunca la MAC), fabricante, nombre, modelo, tipo y papel. El nombre
    sale, en este orden, de lo que anuncia por mDNS o UPnP, de lo que dijo al pedir dirección (DHCP), del DNS del
    router o de la red (DNS inverso, NetBIOS o mDNS). Desde la 2.0.0 se dice de dónde salió (nameSource):
    ANNOUNCED (lo dijo el equipo), ROUTER (lo dijo el router), DNS (lo dijo la red) o CONFIRMED (el equipo y el
    router dicen lo mismo). El fabricante por la MAC es una estimación y nunca se presenta como el nombre."""
    dhcp = dhcp or {}
    device = {"id": mac_fingerprint(mac, salt)}
    vendor = vendor_of(mac)
    private = not vendor and is_private_mac(mac)
    if vendor:
        device["vendor"] = vendor
    elif private:
        device["privateMac"] = True  # casi siempre un celular o tableta con la MAC aleatoria activada
    # El nombre que el equipo anuncia por mDNS o UPnP ("iPhone de Ana", "Sala TV") es el que la persona le puso.
    own_name = announced.get("name") or clean_hostname(dhcp.get("name"), ip)
    from_router = clean_hostname(router_name, ip)
    name = own_name or from_router or hostname
    if name:
        device["name"] = name[:63]
        if own_name and from_router and same_name(own_name, from_router):
            device["nameSource"] = "CONFIRMED"
        elif own_name:
            device["nameSource"] = "ANNOUNCED"
        elif from_router:
            device["nameSource"] = "ROUTER"
        else:
            device["nameSource"] = "DNS"
    if announced.get("model"):
        device["model"] = announced["model"][:63]
    if ip == own_ip:
        device["role"], device["kind"] = "SELF", "COMPUTER"
    elif ip == gateway:
        device["role"] = "ROUTER"
    else:
        hints = announced.get("kinds", []) + [k for k in [discovery.dhcp_kind(dhcp.get("vendorClass"))] if k]
        kind = discovery.decide_kind(name, announced.get("model"), vendor, hints, private)
        if kind:
            device["kind"] = kind
    return device


# -------------------------------------------------------------------------------------------- latencia y puertos

def connect_time(host: str, port: int, timeout: float = 1.5) -> Optional[float]:
    """Milisegundos hasta que el destino responde a una conexión TCP. Un rechazo también es una respuesta (mide el
    viaje de ida y vuelta igual), solo el silencio cuenta como pérdida."""
    start = time.perf_counter()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        try:
            sock.connect((host, port))
        except ConnectionRefusedError:
            pass
        except OSError:
            return None
    return (time.perf_counter() - start) * 1000


def summarize(samples: list[Optional[float]]) -> dict:
    ok = [s for s in samples if s is not None]
    loss = round(100 * (len(samples) - len(ok)) / len(samples), 1) if samples else 100.0
    if not ok:
        return {"latencyMs": None, "jitterMs": None, "packetLossPct": loss}
    jitter = statistics.mean(abs(b - a) for a, b in zip(ok, ok[1:])) if len(ok) > 1 else 0.0
    return {"latencyMs": round(statistics.median(ok), 1), "jitterMs": round(jitter, 1), "packetLossPct": loss}


def measure(host: str, port: int, count: int = SAMPLES, pause: float = 0.2,
            probe: Callable[[str, int], Optional[float]] = connect_time) -> dict:
    samples = []
    for i in range(count):
        samples.append(probe(host, port))
        if i < count - 1:
            time.sleep(pause)
    return summarize(samples)


def open_ports(host: str, ports=ROUTER_PORTS, timeout: float = 0.8) -> list[int]:
    def is_open(port: int) -> bool:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            return sock.connect_ex((host, port)) == 0
    with ThreadPoolExecutor(max_workers=len(ports)) as pool:
        return [port for port, ok in zip(ports, pool.map(is_open, ports)) if ok]


# ------------------------------------------------------------------------------------------------------ tráfico
# Contadores del sistema operativo (sin programas de captura): bytes y paquetes de la tarjeta de red y paquetes por
# protocolo. El agente envía cuánto cambiaron desde el reporte anterior. Solo el sensor de una red del equipo los
# guarda; son el tráfico de ESTE computador, no el de toda la red (eso solo lo ve el router).
TRAFFIC_MAX_AGE = 3600          # si el reporte anterior es más viejo (equipo apagado), no se mezcla ese tiempo
WRAP_32 = 2 ** 32
SKIP_INTERFACES = ("lo", "docker", "veth", "br-", "virbr", "vmnet", "tun", "tailscale")


def parse_proc_net_dev(text: str) -> dict[str, int]:
    """Bytes y paquetes de /proc/net/dev (Linux), sumando las tarjetas reales (sin loopback ni puentes)."""
    totals = {"bytes.in": 0, "bytes.out": 0, "packets.in": 0, "packets.out": 0}
    found = False
    for line in text.splitlines()[2:]:
        if ":" not in line:
            continue
        name, data = line.split(":", 1)
        name = name.strip()
        values = data.split()
        if len(values) < 10 or name.startswith(SKIP_INTERFACES):
            continue
        found = True
        totals["bytes.in"] += int(values[0])
        totals["packets.in"] += int(values[1])
        totals["bytes.out"] += int(values[8])
        totals["packets.out"] += int(values[9])
    return totals if found else {}


def parse_proc_net_snmp(snmp: str, snmp6: str = "") -> dict[str, int]:
    """Paquetes por protocolo de /proc/net/snmp y /proc/net/snmp6 (Linux)."""
    wanted = {"Tcp": ("InSegs", "OutSegs", "TCP"), "Udp": ("InDatagrams", "OutDatagrams", "UDP"),
              "Icmp": ("InMsgs", "OutMsgs", "ICMP")}
    counters: dict[str, int] = {}
    lines = snmp.splitlines()
    for header, values in zip(lines, lines[1:]):
        prefix = header.split(":", 1)[0]
        if prefix not in wanted or not values.startswith(prefix + ":") or header == values:
            continue
        row = dict(zip(header.split()[1:], values.split()[1:]))
        received, sent, protocol = wanted[prefix]
        if received in row and sent in row and row[received].isdigit():
            counters[f"{protocol}.in4"] = int(row[received])
            counters[f"{protocol}.out4"] = int(row[sent])
    for line in snmp6.splitlines():
        parts = line.split()
        names = {"Udp6InDatagrams": "UDP.in6", "Udp6OutDatagrams": "UDP.out6",
                 "Icmp6InMsgs": "ICMP.in6", "Icmp6OutMsgs": "ICMP.out6"}
        if len(parts) == 2 and parts[0] in names and parts[1].isdigit():
            counters[names[parts[0]]] = int(parts[1])
    return counters


def linux_counters() -> dict[str, int]:
    counters = parse_proc_net_dev(read_file("/proc/net/dev"))
    counters.update(parse_proc_net_snmp(read_file("/proc/net/snmp"), read_file("/proc/net/snmp6")))
    return counters


def windows_counters() -> dict[str, int]:
    """Contadores de Windows con la API IP Helper (iphlpapi.dll), igual en cualquier idioma del sistema."""
    import ctypes
    from ctypes import wintypes

    u64, enum = ctypes.c_uint64, ctypes.c_int

    class MibIfRow2(ctypes.Structure):  # MIB_IF_ROW2 de netioapi.h: 1352 bytes
        _fields_ = [("InterfaceLuid", u64), ("InterfaceIndex", wintypes.ULONG), ("InterfaceGuid", ctypes.c_ubyte * 16),
                    ("Alias", ctypes.c_wchar * 257), ("Description", ctypes.c_wchar * 257),
                    ("PhysicalAddressLength", wintypes.ULONG), ("PhysicalAddress", ctypes.c_ubyte * 32),
                    ("PermanentPhysicalAddress", ctypes.c_ubyte * 32), ("Mtu", wintypes.ULONG),
                    ("Type", wintypes.ULONG), ("TunnelType", enum), ("MediaType", enum),
                    ("PhysicalMediumType", enum), ("AccessType", enum), ("DirectionType", enum),
                    ("Flags", ctypes.c_ubyte), ("OperStatus", enum), ("AdminStatus", enum),
                    ("MediaConnectState", enum), ("NetworkGuid", ctypes.c_ubyte * 16), ("ConnectionType", enum),
                    ("TransmitLinkSpeed", u64), ("ReceiveLinkSpeed", u64)]
        _fields_ += [(name, u64) for name in (
            "InOctets", "InUcastPkts", "InNUcastPkts", "InDiscards", "InErrors", "InUnknownProtos", "InUcastOctets",
            "InMulticastOctets", "InBroadcastOctets", "OutOctets", "OutUcastPkts", "OutNUcastPkts", "OutDiscards",
            "OutErrors", "OutUcastOctets", "OutMulticastOctets", "OutBroadcastOctets", "OutQLen")]

    class MibTcpStats(ctypes.Structure):
        _fields_ = [(name, wintypes.DWORD) for name in (
            "RtoAlgorithm", "RtoMin", "RtoMax", "MaxConn", "ActiveOpens", "PassiveOpens", "AttemptFails",
            "EstabResets", "CurrEstab", "InSegs", "OutSegs", "RetransSegs", "InErrs", "OutRsts", "NumConns")]

    class MibUdpStats(ctypes.Structure):
        _fields_ = [(name, wintypes.DWORD) for name in (
            "InDatagrams", "NoPorts", "InErrors", "OutDatagrams", "NumAddrs")]

    class MibIcmpStats(ctypes.Structure):
        _fields_ = [(name, wintypes.DWORD) for name in (
            "Msgs", "Errors", "DestUnreachs", "TimeExcds", "ParmProbs", "SrcQuenchs", "Redirects", "Echos",
            "EchoReps", "Timestamps", "TimestampReps", "AddrMasks", "AddrMaskReps")]

    class MibIcmp(ctypes.Structure):
        _fields_ = [("In", MibIcmpStats), ("Out", MibIcmpStats)]

    if ctypes.sizeof(MibIfRow2) != 1352:  # una estructura mal descrita leería basura: mejor no enviar nada
        return {}
    api = ctypes.WinDLL("iphlpapi.dll")
    counters: dict[str, int] = {}

    table = ctypes.c_void_p()
    if api.GetIfTable2(ctypes.byref(table)) == 0:
        try:
            count = ctypes.cast(table, ctypes.POINTER(wintypes.ULONG))[0]
            rows = ctypes.cast(table.value + 8, ctypes.POINTER(MibIfRow2 * count)).contents
            # Tarjetas físicas conectadas (no filtros ni virtuales); el Wi-Fi si lo hay, si no la de cable.
            physical = [row for row in rows if row.Flags & 1 and not row.Flags & 2 and row.OperStatus == 1]
            chosen = [row for row in physical if row.Type == 71] or [row for row in physical if row.Type == 6]
            if chosen:
                counters["bytes.in"] = sum(row.InOctets for row in chosen)
                counters["bytes.out"] = sum(row.OutOctets for row in chosen)
                counters["packets.in"] = sum(row.InUcastPkts + row.InNUcastPkts for row in chosen)
                counters["packets.out"] = sum(row.OutUcastPkts + row.OutNUcastPkts for row in chosen)
        finally:
            api.FreeMibTable(table)

    for family, suffix in ((2, "4"), (23, "6")):  # AF_INET, AF_INET6; estos contadores son de 32 bits
        tcp, udp = MibTcpStats(), MibUdpStats()
        if api.GetTcpStatisticsEx(ctypes.byref(tcp), family) == 0:
            counters[f"TCP.in{suffix}"], counters[f"TCP.out{suffix}"] = tcp.InSegs, tcp.OutSegs
        if api.GetUdpStatisticsEx(ctypes.byref(udp), family) == 0:
            counters[f"UDP.in{suffix}"], counters[f"UDP.out{suffix}"] = udp.InDatagrams, udp.OutDatagrams
    icmp = MibIcmp()
    if api.GetIcmpStatistics(ctypes.byref(icmp)) == 0:
        counters["ICMP.in4"], counters["ICMP.out4"] = icmp.In.Msgs, icmp.Out.Msgs
    return counters


def traffic_counters() -> dict[str, int]:
    """Contadores actuales; vacío si el sistema no los entrega (entonces el reporte va sin tráfico)."""
    try:
        return windows_counters() if IS_WINDOWS else linux_counters()
    except (OSError, AttributeError, ValueError) as error:
        print(f"  aviso: no se pudo leer el tráfico: {error}", file=sys.stderr)
        return {}


def counter_delta(now: int, before: int, name: str) -> Optional[int]:
    """Cuánto avanzó un contador. Los de protocolos de Windows son de 32 bits y dan la vuelta; un contador que
    retrocede de verdad (el computador se reinició) no da un valor confiable."""
    if now >= before:
        return now - before
    if not name.startswith("bytes") and not name.startswith("packets") and before - now > WRAP_32 // 2:
        return now + WRAP_32 - before
    return None


def traffic_fields(previous: Optional[dict], current: dict, now: Optional[float] = None) -> dict:
    """Campos del reporte con el tráfico desde el reporte anterior; vacío la primera vez o si algo no cuadra."""
    now = time.time() if now is None else now
    if not previous or not current or now - previous.get("at", 0) > TRAFFIC_MAX_AGE:
        return {}
    counters = previous.get("counters", {})
    deltas: dict[str, int] = {}
    for name, value in current.items():
        if name in counters:
            delta = counter_delta(value, counters[name], name)
            if delta is None:
                return {}
            deltas[name] = delta
    fields: dict = {}
    if all(f"{kind}.{way}" in deltas for kind in ("bytes", "packets") for way in ("in", "out")):
        fields["trafficBytes"] = min(deltas["bytes.in"] + deltas["bytes.out"], 10 ** 13)
        fields["trafficPackets"] = min(deltas["packets.in"] + deltas["packets.out"], 10 ** 11)
    protocols = []
    for protocol in ("TCP", "UDP", "ICMP"):
        values = [value for name, value in deltas.items() if name.startswith(protocol + ".")]
        if values:
            protocols.append({"protocol": protocol, "packets": min(sum(values), 10 ** 11)})
    if protocols:
        fields["protocolPackets"] = protocols
    return fields


def traffic_state_path() -> Path:
    return config_path().with_name("traffic.json")


def load_traffic_state(path: Optional[Path] = None) -> Optional[dict]:
    try:
        return json.loads((path or traffic_state_path()).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def save_traffic_state(counters: dict, path: Optional[Path] = None, now: Optional[float] = None,
                       network: Optional[str] = None) -> None:
    """Guarda los contadores del último reporte enviado. Si un envío falla no se guardan, y el siguiente reporte
    incluye también ese intervalo. ``network`` (el inicio de la clave) evita mezclar el tráfico de dos redes cuando
    el computador cambia de Wi-Fi."""
    path = path or traffic_state_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"at": time.time() if now is None else now, "counters": counters,
                                    "network": network}), encoding="utf-8")
    except OSError as error:
        print(f"  aviso: no se pudo guardar el tráfico: {error}", file=sys.stderr)


# ------------------------------------------------------------------------------------------------------ reporte

def collect(salt: str) -> dict:
    """Mide todo en paralelo (unos 5 segundos) y arma el reporte que se envía."""
    own_ip, gateway = local_ip(), default_gateway()
    results: dict = {}

    def task(name: str, fn: Callable[[], object]) -> threading.Thread:
        def target():
            try:
                results[name] = fn()
            except Exception as error:  # una medición que falla no debe impedir enviar las demás
                results[name] = None
                print(f"  aviso: no se pudo medir {name}: {error}", file=sys.stderr)
        thread = threading.Thread(target=target, daemon=True)
        thread.start()
        return thread

    threads = [task("wifi", wifi_info), task("internet", lambda: measure(*INTERNET_TARGET)),
               task("devices", lambda: devices(own_ip, salt, gateway=gateway))]
    if gateway:
        threads += [task("router", lambda: measure(gateway, 80, count=5)), task("ports", lambda: open_ports(gateway))]
    for thread in threads:
        thread.join(timeout=60)
    return build_report(results.get("wifi") or {}, results.get("internet") or summarize([]),
                        results.get("router"), results.get("devices") or [], results.get("ports") or [])


def build_report(wifi: dict, internet: dict, router: Optional[dict], found_devices: list[dict],
                 ports: list[int]) -> dict:
    # Compatibilidad: deviceHashes (lista) la entiende el backend anterior; devices (con fabricante) la nueva versión.
    device_hashes = [device["id"] for device in found_devices]
    report = {
        "agentVersion": AGENT_VERSION,
        "platform": platform.system()[:20] or "desconocido",
        "ssid": wifi.get("ssid"),
        "authentication": wifi.get("authentication", "UNKNOWN"),
        "cipher": wifi.get("cipher"),
        "band": wifi.get("band"),
        "channel": wifi.get("channel"),
        "signalDbm": wifi.get("signalDbm"),
        "signalPercent": wifi.get("signalPercent"),
        "rxRateMbps": wifi.get("rxRateMbps"),
        "txRateMbps": wifi.get("txRateMbps"),
        "neighborsSameChannel": wifi.get("neighborsSameChannel"),
        "neighborsTotal": wifi.get("neighborsTotal"),
        "channelCounts": wifi.get("channelCounts") or None,
        "wifiNote": wifi.get("note"),
        "latencyMs": internet.get("latencyMs"),
        "jitterMs": internet.get("jitterMs"),
        "packetLossPct": internet.get("packetLossPct"),
        "gatewayLatencyMs": (router or {}).get("latencyMs"),
        "deviceCount": len(device_hashes),
        "deviceHashes": device_hashes,
        "devices": found_devices or None,
        "openPorts": ports,
    }
    return {key: value for key, value in report.items() if value is not None}


# ------------------------------------------------------------------------------------------------- configuración

def config_path() -> Path:
    base = os.environ.get("APPDATA") if IS_WINDOWS else os.environ.get("XDG_CONFIG_HOME")
    return Path(base or Path.home() / ".config") / "WiFiSense" / "agent.json"


def load_config(path: Optional[Path] = None) -> dict:
    path = path or config_path()
    try:
        config = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        config = {}
    if os.environ.get("WIFISENSE_AGENT_KEY"):
        config["key"] = os.environ["WIFISENSE_AGENT_KEY"]
    if os.environ.get("WIFISENSE_SERVER"):
        config["server"] = os.environ["WIFISENSE_SERVER"]
    config.setdefault("server", DEFAULT_SERVER)
    return config


def save_config(config: dict, path: Optional[Path] = None) -> Path:
    """Guarda la configuración solo para el usuario actual (permisos 600 en Linux; en Windows la carpeta
    %APPDATA% ya es privada de cada usuario)."""
    path = path or config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as file:
        json.dump(config, file, indent=2)
    if not IS_WINDOWS:
        os.chmod(path, 0o600)
    return path


KEY_PATTERN = re.compile(r"^wsa_[A-Za-z0-9_-]{32,64}$")


def validate_server(url: str) -> str:
    """Solo HTTPS, salvo en el propio computador (pruebas locales): la clave no debe viajar sin cifrar."""
    parsed = urllib.parse.urlparse(url.strip())
    local = parsed.hostname in ("localhost", "127.0.0.1", "::1")
    if parsed.scheme != "https" and not (parsed.scheme == "http" and local):
        raise ValueError("el servidor debe usar https://")
    if not parsed.hostname:
        raise ValueError("dirección del servidor inválida")
    return f"{parsed.scheme}://{parsed.netloc}"


# ------------------------------------------------------------------------------------------------------- envío

class SendError(Exception):
    def __init__(self, message: str, retry_after: Optional[int] = None, fatal: bool = False):
        super().__init__(message)
        self.retry_after = retry_after
        self.fatal = fatal


def server_detail(error: urllib.error.HTTPError) -> str:
    """El motivo que da el servidor (y el campo rechazado, si lo hay), para saber qué corregir."""
    try:
        problem = json.loads(error.read() or b"{}")
    except (OSError, ValueError):
        return ""
    if not isinstance(problem, dict):
        return ""
    parts = [str(problem.get("detail") or "").strip()]
    errors = problem.get("errors")
    if isinstance(errors, dict):
        parts += [f"{field}: {message}" for field, message in errors.items()]
    elif isinstance(errors, list):
        parts += [str(message) for message in errors]
    text = " | ".join(part for part in parts if part)
    return f": {text[:300]}" if text else ""


def send(report: dict, server: str, key: str, opener=urllib.request.urlopen) -> dict:
    request = urllib.request.Request(
        validate_server(server) + REPORT_PATH, data=json.dumps(report).encode(), method="POST",
        headers={"Content-Type": "application/json", "X-Agent-Key": key,
                 "User-Agent": f"WiFiSense-Agent/{AGENT_VERSION}"})
    try:
        with opener(request, timeout=30) as response:
            return json.loads(response.read() or b"{}")
    except urllib.error.HTTPError as error:
        if error.code == 401:
            raise SendError("la clave del agente no es válida o fue revocada; crea una nueva en Mi Wi-Fi > Agente "
                            "y ejecuta 'setup' otra vez", fatal=True)
        if error.code == 429:
            retry = error.headers.get("Retry-After") if error.headers else None
            raise SendError("demasiados reportes seguidos", retry_after=int(retry) if retry and retry.isdigit() else 60)
        raise SendError(f"el servidor respondió {error.code}{server_detail(error)}")
    except (urllib.error.URLError, OSError) as error:
        raise SendError(f"no se pudo conectar con el servidor ({getattr(error, 'reason', error)})")


# ------------------------------------------------------------------------------------- redes cercanas (1.9.0)

class ScansUnavailable(Exception):
    """El servidor no ofrece escaneos a esta clave (un backend anterior, o la clave es del sensor de una red del
    equipo): se deja de preguntar hasta el próximo reporte."""


def agent_call(method: str, path: str, server: str, key: str, body: Optional[dict] = None,
               opener=urllib.request.urlopen) -> tuple[int, dict]:
    """Llamada del agente al servidor con su clave; (código, respuesta). Los errores salen como SendError."""
    request = urllib.request.Request(
        validate_server(server) + path, method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Content-Type": "application/json", "X-Agent-Key": key,
                 "User-Agent": f"WiFiSense-Agent/{AGENT_VERSION}"})
    try:
        with opener(request, timeout=30) as response:
            status = getattr(response, "status", 200)
            raw = response.read() or b"{}"
            return status, json.loads(raw) if status != 204 else {}
    except urllib.error.HTTPError as error:
        if error.code in (401, 403, 404, 405):
            raise ScansUnavailable(str(error.code))
        if error.code == 429:
            retry = error.headers.get("Retry-After") if error.headers else None
            raise SendError("demasiadas consultas seguidas", retry_after=int(retry) if retry and retry.isdigit() else 30)
        raise SendError(f"el servidor respondió {error.code}{server_detail(error)}")
    except (urllib.error.URLError, OSError, ValueError) as error:
        raise SendError(f"no se pudo conectar con el servidor ({getattr(error, 'reason', error)})")


def next_scan(server: str, key: str, opener=urllib.request.urlopen) -> Optional[int]:
    """El número del escaneo que el usuario pidió en Mi Wi-Fi, o None si no hay ninguno. El servidor solo puede pedir
    un escaneo: el agente nunca ejecuta órdenes que lleguen del servidor."""
    status, answer = agent_call("GET", NEXT_SCAN_PATH, server, key, opener=opener)
    return scan_id_of(answer) if status == 200 else None


def scan_id_of(answer) -> Optional[int]:
    scan_id = answer.get("scanId") if isinstance(answer, dict) else None
    return scan_id if isinstance(scan_id, int) and not isinstance(scan_id, bool) and scan_id > 0 else None


def run_scan(scan_id: int, server: str, key: str, salt: str, opener=urllib.request.urlopen, scanner=None) -> dict:
    """Escanea las redes cercanas y entrega el resultado al escaneo ``scan_id``."""
    result = wifi_scan.scan(scan_id, AGENT_VERSION, lambda mac: mac_fingerprint(mac, salt), vendor_of, scanner)
    print(f"  {wifi_scan.summary(result)}")
    try:
        agent_call("POST", SCANS_PATH, server, key, result, opener=opener)
    except (SendError, ScansUnavailable) as error:
        print(f"  No se entregó el escaneo: {error}")
    return result


CODE_PATTERN = re.compile(r"^[A-HJKMNP-Z2-9]{8}$")


def normalize_code(text: str) -> Optional[str]:
    """'k7qm 4rzd' o 'K7QM-4RZD' -> 'K7QM-4RZD'; None si no puede ser un código."""
    code = re.sub(r"[\s-]", "", text or "").upper()
    return f"{code[:4]}-{code[4:]}" if CODE_PATTERN.match(code) else None


def pair(code: str, server: str, opener=urllib.request.urlopen) -> dict:
    """Cambia el código corto de Mi Wi-Fi por la clave del agente. Devuelve {key, prefix, networkName}."""
    normalized = normalize_code(code)
    if not normalized:
        raise SendError("el código tiene 8 letras y números, por ejemplo K7QM-4RZD", fatal=True)
    request = urllib.request.Request(
        validate_server(server) + PAIR_PATH, data=json.dumps({"code": normalized}).encode(), method="POST",
        headers={"Content-Type": "application/json", "User-Agent": f"WiFiSense-Agent/{AGENT_VERSION}"})
    try:
        with opener(request, timeout=30) as response:
            answer = json.loads(response.read() or b"{}")
    except urllib.error.HTTPError as error:
        if error.code == 429:
            raise SendError("demasiados intentos; espera unos minutos", retry_after=600)
        raise SendError(f"el servidor respondió {error.code}{server_detail(error)}", fatal=error.code == 400)
    except (urllib.error.URLError, OSError) as error:
        raise SendError(f"no se pudo conectar con el servidor ({getattr(error, 'reason', error)})")
    if not KEY_PATTERN.match(str(answer.get("key", ""))):
        raise SendError("el servidor no devolvió una clave válida")
    return answer


# ------------------------------------------------------------------------------------------- varias redes (1.6.0)
#
# Un computador puede tener el código de varias redes (por ejemplo los dos Wi-Fi de una casa, o el de la casa y el de
# la universidad). Cada clave queda ligada al Wi-Fi al que estaba conectado el computador cuando se usó el código, y en
# cada reporte el agente usa la clave del Wi-Fi en el que está: si cambias de Wi-Fi, el agente cambia de red solo. En
# un Wi-Fi sin código no envía nada, para no guardar sus mediciones como si fueran de otra red.

def config_networks(config: dict) -> list[dict]:
    """Las redes de este computador: [{key, network, ssid}]. Lee también la configuración de antes de 1.6.0 (una sola
    clave, sin Wi-Fi) y la clave de la variable de entorno WIFISENSE_AGENT_KEY (desarrollo)."""
    if os.environ.get("WIFISENSE_AGENT_KEY"):
        return [{"key": os.environ["WIFISENSE_AGENT_KEY"], "network": None, "ssid": None}]
    networks = config.get("networks")
    if isinstance(networks, list):
        return [n for n in networks if isinstance(n, dict) and n.get("key")]
    if config.get("key"):
        return [{"key": config["key"], "network": config.get("network"), "ssid": config.get("ssid")}]
    return []


def choose_network(networks: list[dict], ssid: Optional[str]) -> Optional[dict]:
    """La red a la que pertenece el Wi-Fi actual. Una clave sin Wi-Fi conocido (instalada antes de 1.6.0, o sin
    permiso de ubicación) sirve para cualquier Wi-Fi que no tenga su propia clave, y lo aprende la primera vez (ver
    learn_ssid). Sin poder leer el Wi-Fi (cable o permiso) solo se envía si no hay duda de cuál red es."""
    if ssid:
        for network in networks:
            if network.get("ssid") == ssid:
                return network
    wildcards = [n for n in networks if not n.get("ssid")]
    if len(wildcards) == 1:
        return wildcards[0]
    if not ssid and len(networks) == 1:
        return networks[0]
    return None


def store_networks(networks: list[dict], path: Optional[Path] = None, server: Optional[str] = None) -> Path:
    """Escribe las redes (y quita las claves sueltas del formato anterior)."""
    path = path or config_path()
    try:
        config = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        config = {}
    for old in ("key", "network", "ssid"):
        config.pop(old, None)
    if server:
        config["server"] = validate_server(server)
    config["networks"] = [{"key": n["key"], "network": n.get("network"), "ssid": n.get("ssid")} for n in networks]
    config.setdefault("salt", secrets.token_hex(16))
    return save_config(config, path)


def learn_ssid(network: dict, ssid: Optional[str], path: Optional[Path] = None) -> None:
    """Una clave sin Wi-Fi queda ligada al primer Wi-Fi en que se usa (el de su red, en una instalación anterior)."""
    if not ssid or network.get("ssid") or os.environ.get("WIFISENSE_AGENT_KEY"):
        return
    networks = config_networks(load_config(path))
    for stored in networks:
        if stored["key"] == network["key"]:
            stored["ssid"] = network["ssid"] = ssid
    store_networks(networks, path)


def forget_network(network: dict, path: Optional[Path] = None) -> list[dict]:
    """Quita una clave revocada (por ejemplo, la red se desconectó desde la página); devuelve las que quedan."""
    networks = [n for n in config_networks(load_config(path)) if n["key"] != network["key"]]
    if not os.environ.get("WIFISENSE_AGENT_KEY"):
        store_networks(networks, path)
    return networks


def current_ssid() -> Optional[str]:
    """El Wi-Fi al que está conectado este computador ahora; None si no se puede leer (cable o permiso)."""
    try:
        return wifi_info().get("ssid")
    except Exception:  # leer el Wi-Fi nunca debe impedir instalar
        return None


def save_pairing(answer: dict, server: str, path: Optional[Path] = None, ssid: Optional[str] = None) -> Path:
    """Agrega la clave recibida a las redes de este computador, ligada al Wi-Fi actual (``ssid``). Un código nuevo
    para el mismo Wi-Fi reemplaza la clave anterior de ese Wi-Fi; las de otros Wi-Fi se conservan."""
    path = path or config_path()
    try:
        config = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        config = {}
    networks = [n for n in config_networks(config) if n.get("ssid") != ssid]
    networks.append({"key": answer["key"], "network": answer.get("networkName"), "ssid": ssid})
    return store_networks(networks, path, server)


def describe_networks(networks: list[dict]) -> str:
    """'«Casa» en Casa-5G; «Laboratorio» en Lab-Redes' para mostrar qué mide este computador."""
    parts = [f"«{n.get('network') or 'sin nombre'}» " + (f"en {n['ssid']}" if n.get("ssid") else "en cualquier Wi-Fi")
             for n in networks]
    return "; ".join(parts) if parts else "ninguna red"


# ---------------------------------------------------------------------------------------------- línea de comandos

KIND_LABELS = {"PHONE": "celular o tableta", "COMPUTER": "computador", "TV": "televisor", "PRINTER": "impresora",
               "CAMERA": "cámara", "SPEAKER": "parlante", "CONSOLE": "consola", "IOT": "casa inteligente"}


def describe(report: dict) -> str:
    lines = [f"  Red: {report.get('ssid', 'sin Wi-Fi (¿cable?)')}  seguridad {report.get('authentication')}"
             f"  banda {report.get('band', '?')} GHz  canal {report.get('channel', '?')}"
             f"  señal {report.get('signalDbm', '?')} dBm",
             f"  Internet: {report.get('latencyMs', '?')} ms, jitter {report.get('jitterMs', '?')} ms, "
             f"pérdida {report.get('packetLossPct', '?')} %   Router: {report.get('gatewayLatencyMs', '?')} ms",
             f"  Equipos conectados: {report['deviceCount']}   Puertos abiertos en el router: "
             f"{', '.join(map(str, report['openPorts'])) or 'ninguno de los revisados'}"]
    if "trafficBytes" in report:
        protocols = ", ".join(f"{p['protocol']} {p['packets']}" for p in report.get("protocolPackets", []))
        lines.append(f"  Tráfico de este computador desde el reporte anterior: "
                     f"{report['trafficBytes'] / 1048576:.1f} MB, {report['trafficPackets']} paquetes"
                     + (f" ({protocols})" if protocols else ""))
    known = [d for d in report.get("devices") or [] if d.get("name") or d.get("kind")]
    if known:
        lines.append("  Equipos reconocidos: " + ", ".join(
            (d.get("name") or "sin nombre") + (f" ({KIND_LABELS[d['kind']]})" if d.get("kind") in KIND_LABELS else "")
            for d in known[:12]))
    if report.get("wifiNote") == "LOCATION_PERMISSION":
        lines.append("  Windows no deja leer el Wi-Fi: Configuración > Privacidad > Ubicación > activa "
                     "'Permitir que las aplicaciones de escritorio accedan a tu ubicación'.")
    return "\n".join(lines)


def command_setup(_args) -> int:
    config = load_config()
    print("Configuración del agente WiFiSense")
    server = input(f"Servidor [{config['server']}]: ").strip() or config["server"]
    key = getpass.getpass("Clave del agente (no se muestra al escribir): ").strip()
    try:
        server = validate_server(server)
    except ValueError as error:
        print(f"Error: {error}")
        return 2
    if not KEY_PATTERN.match(key):
        print("Error: la clave debe empezar por 'wsa_'. Cópiala completa desde Mi Wi-Fi > Agente.")
        return 2
    config.update(server=server, key=key)
    config.setdefault("salt", secrets.token_hex(16))
    print(f"Guardado en {save_config(config)}")
    print("Ahora ejecuta: python wifisense_agent.py run")
    return 0


def command_pair(args) -> int:
    config = load_config()
    code = args.code or input("Código de instalación (Mi Wi-Fi > Agente WiFiSense, o Redes > Sensor): ")
    try:
        answer = pair(code, config["server"])
    except SendError as error:
        print(f"Error: {error}")
        return 1
    ssid = current_ssid()
    saved = save_pairing(answer, config["server"], ssid=ssid)
    where = f" cuando este computador esté en «{ssid}»" if ssid else ""
    print(f"Conectado con la red «{answer.get('networkName', '')}»{where}. Guardado en {saved}")
    print("Ahora ejecuta: python wifisense_agent.py run")
    return 0


def ensure_salt(config: dict, path: Optional[Path] = None) -> str:
    """La sal se guarda en el archivo de configuración; la clave que llega por variable de entorno no se escribe."""
    if not config.get("salt"):
        try:
            stored = json.loads((path or config_path()).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            stored = {}
        stored["salt"] = config["salt"] = secrets.token_hex(16)
        save_config(stored, path)
    return config["salt"]


def command_scan(_args) -> int:
    config = load_config()
    print("Midiendo (unos segundos)...")
    report = collect(config.get("salt") or secrets.token_hex(16))
    print(describe(report))
    print("\nEsto es lo que se enviaría:")
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 0


def next_wait(answer: dict, interval: int) -> int:
    """Mientras alguien identifica un equipo en la página, el servidor pide reportar cada minuto; nunca más seguido que
    MIN_INTERVAL ni más lento que el intervalo normal."""
    asked = answer.get("nextReportSeconds") if isinstance(answer, dict) else None
    if isinstance(asked, (int, float)) and asked > 0:
        return int(max(MIN_INTERVAL, min(asked, interval)))
    return interval


def command_run(args) -> int:
    config = load_config()
    if not config_networks(config):
        print("Primero ejecuta: python wifisense_agent.py pair CODIGO")
        return 2
    salt = ensure_salt(config)
    interval = max(args.interval, MIN_INTERVAL)
    while True:
        config = load_config()  # un código nuevo (otra red) se usa sin reiniciar el agente
        networks = config_networks(config)
        print(time.strftime("[%H:%M:%S] Midiendo..."))
        report = collect(salt)
        ssid = report.get("ssid")
        network = choose_network(networks, ssid)
        wait, sent = interval, False
        if network is None:
            print(f"  No se envió: este computador está en «{ssid}», que no tiene código aquí. Mide: "
                  f"{describe_networks(networks)}." if ssid else
                  "  No se envió: no se pudo leer el Wi-Fi y este computador tiene códigos de varias redes.")
        else:
            learn_ssid(network, ssid)
            tag = network["key"][:12]
            counters = traffic_counters()
            previous = load_traffic_state()
            if previous and previous.get("network") not in (None, tag):
                previous = None  # el reporte anterior fue de otra red: su tráfico no es de esta
            report.update(traffic_fields(previous, counters))
            print(describe(report))
            try:
                answer = send(report, config["server"], network["key"])
                sent = True
                wait = next_wait(answer, interval)
                if counters:
                    save_traffic_state(counters, network=tag)
                print(f"  Enviado a «{network.get('network') or 'tu red'}». {answer.get('summary', '')}".rstrip())
            except SendError as error:
                print(f"  No se envió: {error}")
                if error.fatal:
                    if not forget_network(network):
                        return 1
                    print("  Se quitó esa red de este computador; las demás siguen.")
                wait = max(interval, error.retry_after or 0)
        if args.once:
            return 0 if sent else 1
        time.sleep(wait)


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Agente WiFiSense: mide tu red Wi-Fi y la envía a WiFiSense.")
    commands = parser.add_subparsers(dest="command", required=True)
    pair_parser = commands.add_parser("pair", help="conectar con el código de Mi Wi-Fi")
    pair_parser.add_argument("code", nargs="?", help="código de 8 caracteres, por ejemplo K7QM-4RZD")
    pair_parser.set_defaults(handler=command_pair)
    commands.add_parser("setup", help="guardar la clave del agente").set_defaults(handler=command_setup)
    commands.add_parser("scan", help="medir y mostrar sin enviar").set_defaults(handler=command_scan)
    run = commands.add_parser("run", help="medir y enviar periódicamente")
    run.add_argument("--once", action="store_true", help="enviar un solo reporte y salir")
    run.add_argument("--interval", type=int, default=DEFAULT_INTERVAL, help="segundos entre reportes (mínimo 60)")
    run.set_defaults(handler=command_run)
    args = parser.parse_args(argv)
    try:
        return args.handler(args)
    except KeyboardInterrupt:
        print("\nAgente detenido.")
        return 0


if __name__ == "__main__":
    sys.exit(main())
