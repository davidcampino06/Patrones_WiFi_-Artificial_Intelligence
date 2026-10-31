"""Cómo leer lo que el sistema dice del Wi-Fi: claves de netsh en español o en inglés, números, tipo de seguridad,
cifrado, banda y las columnas de nmcli. Lo usan la medición del agente (wifisense_agent.py) y el escaneo de redes
cercanas (wifi_scan.py), para que las dos lean el sistema de la misma manera.

Solo usa la biblioteca estándar.
"""
from __future__ import annotations

import re
import unicodedata
from typing import Optional


def normalize_key(key: str) -> str:
    """Clave de netsh en minúsculas, sin tildes ni espacios ('Autenticación' -> 'autenticacion')."""
    ascii_key = unicodedata.normalize("NFKD", key.lower())
    return "".join(c for c in ascii_key if "a" <= c <= "z")

def key_values(text: str) -> list[tuple[str, str]]:
    pairs = []
    for line in text.splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            pairs.append((key.strip(), value.strip()))
    return pairs


def first_number(text: str) -> Optional[float]:
    match = re.search(r"-?\d+(?:[.,]\d+)?", text or "")
    return float(match.group().replace(",", ".")) if match else None


def authentication_of(auth: str, cipher: str = "") -> str:
    """Texto del sistema -> OPEN, WEP, WPA, WPA2, WPA3 o UNKNOWN (lo que entiende la auditoría de la IA)."""
    auth_u, cipher_u = (auth or "").upper(), (cipher or "").upper()
    if "WPA3" in auth_u or "SAE" in auth_u or "OWE" in auth_u:
        return "WPA3"
    if "WPA2" in auth_u or "RSN" in auth_u:
        return "WPA2"
    if "WPA" in auth_u:
        return "WPA"
    if "WEP" in cipher_u or "WEP" in auth_u or "SHARED" in auth_u or "COMPARTIDA" in auth_u:
        return "WEP"
    if auth_u.startswith(("OPEN", "ABIERT")) or auth_u in ("--", "NONE"):
        return "OPEN"
    return "UNKNOWN"

CIPHERS = (("GCMP-256", "GCMP-256"), ("GCMP", "GCMP"), ("CCMP", "CCMP"), ("AES", "CCMP"), ("TKIP", "TKIP"),
           ("WEP", "WEP"), ("NINGUN", "NONE"), ("NONE", "NONE"))


def cipher_of(text: str) -> Optional[str]:
    """Nombre corto del cifrado. Algunas versiones de Windows escriben una descripción larga (por ejemplo varios
    cifrados o el nombre del proveedor); el servidor solo acepta hasta 20 caracteres."""
    upper = (text or "").upper()
    for token, name in CIPHERS:
        if token in upper:
            return name
    return (text or "").strip()[:20] or None


def band_of(band_text: str, channel: Optional[int]) -> Optional[str]:
    number = first_number(band_text or "")
    if number is not None:
        return "2.4" if number < 3 else "5" if number < 5.9 else "6"
    if channel:
        return "2.4" if channel <= 14 else "5"
    return None

def split_nmcli(line: str) -> list[str]:
    """nmcli -t separa con ':' y escapa los ':' de los valores con '\\:'."""
    return [part.replace("\\:", ":") for part in re.split(r"(?<!\\):", line)]
