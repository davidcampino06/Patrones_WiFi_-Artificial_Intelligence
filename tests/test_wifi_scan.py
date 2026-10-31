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


def test_spanish_windows_11_with_band_load_and_special_characters():
    interface, access_points = wifi_scan.parse_netsh_scan(WINDOWS_11_ES)

    assert interface == "Wi-Fi 2"
    vecino, biblioteca = access_points
    assert vecino["ssid"] == 'Café ☕ "Vecino" <script>'  # kept as it is: the page escapes it
    assert vecino["channel"] == 37  # not the 12 of "Utilización del canal"
    assert vecino["band"] == "6" and vecino["authentication"] == "WPA3"
    assert biblioteca["band"] == "2.4" and biblioteca["authentication"] == "WPA2"
    assert biblioteca["securityLabel"] == "WPA2-Enterprise"


def test_a_console_that_damaged_the_accents_is_still_read():
    damaged = WINDOWS_11_ES.replace("Señal", "Se¤al").replace("Autenticación", "Autenticaci¢n")
    _, access_points = wifi_scan.parse_netsh_scan(damaged)

    assert access_points[0]["signalPercent"] == 72
    assert access_points[0]["authentication"] == "WPA3"


def test_what_the_system_did_not_say_stays_unknown():
    text = """Interface name : Wi-Fi
SSID 1 : Minima
    BSSID 1                 : 10:20:30:40:50:60
"""
    _, (ap,) = wifi_scan.parse_netsh_scan(text)

    assert ap["signalPercent"] is None and ap["signalDbm"] is None
    assert ap["channel"] is None and ap["band"] is None and ap["radioType"] is None
    assert ap["authentication"] == "UNKNOWN" and ap["securityLabel"] is None and ap["cipher"] is None


def test_values_out_of_range_and_malformed_bssids_are_dropped():
    text = """Interface name : Wi-Fi
SSID 1 : Rara
    Authentication          : WPA2-Personal
    BSSID 1                 : no-es-una-mac
         Signal             : 88%
    BSSID 2                 : 10:20:30:40:50:61
         Signal             : 140%
         Channel            : 999
"""
    _, access_points = wifi_scan.parse_netsh_scan(text)

    assert len(access_points) == 1
    assert access_points[0]["signalPercent"] is None and access_points[0]["channel"] is None


def test_control_characters_in_a_name_are_removed():
    assert wifi_scan.clean_ssid("Red\x00\x1b[31m roja\t") == "Red[31m roja"
    assert wifi_scan.clean_ssid("   ") is None
    assert len(wifi_scan.clean_ssid("x" * 100)) == 64


def test_the_access_point_this_computer_is_connected_to():
    assert wifi_scan.connected_bssid(INTERFACES_CONNECTED) == "a4:2b:b0:12:34:56"
    assert wifi_scan.connected_bssid(INTERFACES_RADIO_OFF) is None
    windows_10 = INTERFACES_CONNECTED.replace("AP BSSID", "BSSID")
    assert wifi_scan.connected_bssid(windows_10) == "a4:2b:b0:12:34:56"


# -------------------------------------------------------------------------------------------------- resultado

def test_a_completed_scan_never_sends_a_mac():
    result = scan_with({"mode=bssid": WINDOWS_10_EN, "interfaces": INTERFACES_CONNECTED})

    assert result["status"] == "COMPLETED" and result["scanId"] == 12 and result["scanTool"] == "NETSH"
    assert result["fresh"] is True and result["interfaceName"] == "Wi-Fi"
    text = json.dumps(result)
    for mac in ("a4:2b:b0:12:34:56", "a42bb0123456", "06:2b:b0:aa:bb:cc", "9c:a2:f4:00:00:02"):
        assert mac not in text.lower()
    first = result["accessPoints"][0]
    assert first["bssid"] == fingerprint("a4:2b:b0:12:34:56") and len(first["bssid"]) == 24
    assert first["bssidSuffix"] == "56"
    assert first["connected"] is True and first["vendor"] == "TP-Link"
    assert [ap["connected"] for ap in result["accessPoints"]].count(True) == 1


def test_the_strongest_access_points_come_first_and_a_local_bssid_has_no_maker():
    result = scan_with({"mode=bssid": WINDOWS_10_EN, "interfaces": INTERFACES_CONNECTED})

    assert [ap["signalPercent"] for ap in result["accessPoints"]] == [88, 61, 40, 15]
    hidden = result["accessPoints"][2]
    assert "ssid" not in hidden or hidden["ssid"] is None
    assert hidden["vendor"] is None  # 06:... is a locally administered BSSID: its maker cannot be known


def test_a_bssid_repeated_by_the_system_is_sent_once():
    twice = WINDOWS_10_EN.replace("a4:2b:b0:12:34:57", "a4:2b:b0:12:34:56")
    result = scan_with({"mode=bssid": twice, "interfaces": ""})

    assert len(result["accessPoints"]) == 3
    assert result["accessPoints"][0]["signalPercent"] == 88


def test_no_networks_in_range_is_a_completed_scan():
    result = scan_with({"mode=bssid": "Interface name : Wi-Fi\nThere are 0 networks currently visible.\n",
                        "interfaces": INTERFACES_CONNECTED})

    assert result["status"] == "COMPLETED" and result["accessPoints"] == []


def test_the_list_windows_already_had_is_marked_as_not_fresh():
    result = scan_with({"mode=bssid": WINDOWS_10_EN, "interfaces": ""}, fresh=False)

    assert result["fresh"] is False
    assert "lista que ya tenía el sistema" in wifi_scan.summary(result)


@pytest.mark.parametrize("answer, reason", [
    ("There is no wireless interface on the system.", "NO_ADAPTER"),
    ("No hay ninguna interfaz inalámbrica en el sistema.", "NO_ADAPTER"),
    ("The Wireless AutoConfig Service (wlansvc) is not running.", "SERVICE_OFF"),
    ("El Servicio de configuración automática de WLAN (wlansvc) no se está ejecutando.", "SERVICE_OFF"),
    (LOCATION, "LOCATION_PERMISSION"),
    ("Los comandos de shell de red necesitan permiso de ubicación para acceder a la información de WLAN.",
     "LOCATION_PERMISSION"),
])
def test_each_windows_error_becomes_its_reason(answer, reason):
    result = scan_with({"mode=bssid": CommandResult(1, answer)})

    assert result["status"] == "FAILED" and result["failureReason"] == reason
    assert result["accessPoints"] == []


def test_a_wifi_turned_off_is_a_failure_not_an_empty_neighborhood():
    result = scan_with({"mode=bssid": "Nombre de la interfaz : Wi-Fi\nHay 0 redes visibles actualmente.\n",
                        "interfaces": INTERFACES_RADIO_OFF})

    assert result["status"] == "FAILED" and result["failureReason"] == "ADAPTER_OFF"
    assert result["interfaceName"] == "Wi-Fi"


def test_a_command_that_takes_too_long_or_does_not_exist():
    assert scan_with({"mode=bssid": CommandResult(None, "", timed_out=True)})["failureReason"] == "TIMEOUT"
    assert scan_with({"mode=bssid": CommandResult(None, "", missing=True)})["failureReason"] == "COMMAND_FAILED"


def test_an_answer_that_is_not_the_list_is_unreadable():
    assert scan_with({"mode=bssid": "Something unexpected"})["failureReason"] == "UNREADABLE_OUTPUT"
    assert scan_with({"mode=bssid": CommandResult(5, "Error 0x5")})["failureReason"] == "COMMAND_FAILED"


def test_a_scanner_that_crashes_does_not_take_the_agent_down(capsys):
    class Broken:
        tool = "NETSH"

        def scan(self):
            raise OSError("driver")

    result = wifi_scan.scan(3, "1.9.0", fingerprint, lambda mac: None, Broken())

    assert result["status"] == "FAILED" and result["failureReason"] == "COMMAND_FAILED"
    assert "driver" in capsys.readouterr().err


def test_a_system_without_a_known_tool_says_so(monkeypatch):
    assert wifi_scan.scanner_for("darwin") is None
    assert isinstance(wifi_scan.scanner_for("win32"), wifi_scan.NetshScanner)
    assert isinstance(wifi_scan.scanner_for("linux"), wifi_scan.NmcliScanner)
    monkeypatch.setattr(wifi_scan, "scanner_for", lambda: None)

    result = wifi_scan.scan(3, "1.9.0", fingerprint, lambda mac: None)

    assert result["status"] == "FAILED" and result["failureReason"] == "UNSUPPORTED_OS"


def test_the_duration_is_measured():
    ticks = iter([10.0, 14.25])
    result = scan_with({"mode=bssid": WINDOWS_10_EN, "interfaces": ""}, clock=lambda: next(ticks))

    assert result["durationMs"] == 4250


def test_commands_are_run_without_a_shell(monkeypatch):
    seen = {}

    def fake_run(args, **kwargs):
        seen.update(args=args, **kwargs)

        class Done:
            returncode, stdout, stderr = 0, "Interface name : Wi-Fi".encode(), b""
        return Done()

    monkeypatch.setattr(wifi_scan.subprocess, "run", fake_run)
    wifi_scan.run(["netsh", "wlan", "show", "networks", "mode=bssid"])

    assert seen["args"] == ["netsh", "wlan", "show", "networks", "mode=bssid"]
    assert "shell" not in seen and seen["timeout"] == wifi_scan.COMMAND_TIMEOUT


# ------------------------------------------------------------------------------------------------------- nmcli

NMCLI = (" :AA\\:BB\\:CC\\:DD\\:EE\\:01:Casa\\: 2.4:6:2437 MHz:70:WPA2\n"
         "*:AA\\:BB\\:CC\\:DD\\:EE\\:02:Casa 5G:44:5220 MHz:91:WPA2 WPA3\n"
         " :12\\:34\\:56\\:78\\:9A\\:BC::1:2412 MHz:20:--\n")
