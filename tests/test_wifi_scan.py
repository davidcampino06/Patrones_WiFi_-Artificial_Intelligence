"""Escaneo de redes Wi-Fi cercanas del agente (1.9.0). Corre también en Windows real (GitHub Actions, sin conftest):
ahí además se prueba la llamada real a WlanScan y a netsh."""
import ctypes
import json
import os

import pytest

from agent import wifi_scan
from agent.wifi_scan import CommandResult

SALT = "sal-de-prueba"

WINDOWS_10_EN = """
Interface name : Wi-Fi
There are 3 networks currently visible.

SSID 1 : Casa-5G
    Network type            : Infrastructure
    Authentication          : WPA2-Personal
    Encryption              : CCMP
    BSSID 1                 : a4:2b:b0:12:34:56
         Signal             : 88%
         Radio type         : 802.11ac
         Channel            : 44
         Basic rates (Mbps) : 6 12 24
         Other rates (Mbps) : 9 18 36 48 54
    BSSID 2                 : a4:2b:b0:12:34:57
         Signal             : 61%
         Radio type         : 802.11n
         Channel            : 6
         Basic rates (Mbps) : 1 2 5.5 11

SSID 2 :
    Network type            : Infrastructure
    Authentication          : WPA2-Personal
    Encryption              : CCMP
    BSSID 1                 : 06:2b:b0:aa:bb:cc
         Signal             : 40%
         Radio type         : 802.11n
         Channel            : 11

SSID 3 : Cafe libre
    Network type            : Infrastructure
    Authentication          : Open
    Encryption              : None
    BSSID 1                 : 9c:a2:f4:00:00:02
         Signal             : 15%
         Radio type         : 802.11g
         Channel            : 1
"""

# Windows 11 en español: banda, carga del punto de acceso ('Utilización del canal' no es el canal) y WPA3.
WINDOWS_11_ES = """
Nombre de la interfaz : Wi-Fi 2
Hay 2 redes visibles actualmente.

SSID 1 : Café ☕ "Vecino" <script>
    Tipo de red             : Infraestructura
    Autenticación           : WPA3-Personal
    Cifrado                 : CCMP
    BSSID 1                 : 50:c7:bf:01:02:03
         Señal              : 72%
         Tipo de radio      : 802.11ax
         Banda              : 6 GHz
         Canal              : 37
         Carga de BSS:
             Estaciones conectadas:        3
             Utilización del canal:        12 (4 %)
             Capacidad disponible del medio: 31250 (1000000 us/s)
         Velocidades básicas (Mbps) : 6 12 24

SSID 2 : Biblioteca
    Tipo de red             : Infraestructura
    Autenticación           : WPA2-Enterprise
    Cifrado                 : CCMP
    BSSID 1                 : 00:1a:2b:3c:4d:5e
         Señal              : 35%
         Tipo de radio      : 802.11n
         Banda              : 2,4 GHz
         Canal              : 11
"""

INTERFACES_CONNECTED = """
There is 1 interface on the system:

    Name                   : Wi-Fi
    Description            : Intel(R) Wi-Fi 6 AX201 160MHz
    State                  : connected
    SSID                   : Casa-5G
    AP BSSID               : a4:2b:b0:12:34:56
    Radio status           : Hardware On
                             Software On
"""

INTERFACES_RADIO_OFF = """
Hay 1 interfaz en el sistema:

    Nombre                 : Wi-Fi
    Estado                 : desconectado
    Estado de radio        : Hardware encendido
                             Software apagado
"""

LOCATION = ("Network shell commands need location permission to access WLAN information. Turn on Location services "
            "on the Location page in Privacy & security settings.")


def fake_runner(outputs: dict):
    """netsh falso: cada comando responde lo que diga el diccionario (por la última palabra del comando)."""
    def runner(args):
        answer = outputs.get(args[-1], CommandResult(0, ""))
        return answer if isinstance(answer, CommandResult) else CommandResult(0, answer)
    return runner


def fingerprint(mac):
    import hashlib
    return hashlib.sha256(f"{SALT}:{mac}".encode()).hexdigest()[:24]


def scan_with(outputs, fresh=True, **kwargs):
    scanner = wifi_scan.NetshScanner(fake_runner(outputs), fresh=lambda: fresh)
    return wifi_scan.scan(12, "1.9.0", fingerprint, lambda mac: "TP-Link" if mac.startswith("a4") else None,
                          scanner, **kwargs)


# ----------------------------------------------------------------------------------------------- lectura de netsh

def test_several_networks_with_several_access_points_in_english():
    interface, access_points = wifi_scan.parse_netsh_scan(WINDOWS_10_EN)

    assert interface == "Wi-Fi"
    assert [ap["ssid"] for ap in access_points] == ["Casa-5G", "Casa-5G", None, "Cafe libre"]
    casa = access_points[0]
    assert casa["signalPercent"] == 88 and casa["channel"] == 44 and casa["band"] == "5"
    assert casa["authentication"] == "WPA2" and casa["securityLabel"] == "WPA2-Personal" and casa["cipher"] == "CCMP"
    assert casa["radioType"] == "802.11ac"
    assert access_points[1]["band"] == "2.4"  # Windows 10 does not say the band: it follows from channel 6
    assert access_points[3]["authentication"] == "OPEN" and access_points[3]["cipher"] == "NONE"
