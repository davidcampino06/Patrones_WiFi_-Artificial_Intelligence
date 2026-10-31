"""Escaneo de las redes Wi-Fi cercanas: las que alcanza a ver la antena Wi-Fi de este computador.

Cómo funciona:
  * En Windows se le pide al sistema un escaneo nuevo (WlanScan, de wlanapi.dll, sin permisos de administrador) y,
    unos segundos después, se lee la lista con ``netsh wlan show networks mode=bssid``. Si no se pudo pedir el
    escaneo nuevo se lee la última lista que tenga Windows, y el resultado lo dice (``fresh`` = False).
  * En Linux se usa ``nmcli dev wifi list --rescan yes`` (y, si no deja volver a escanear tan seguido, la última lista).
  * Cada punto de acceso (BSSID) sale como un diccionario con lo que el sistema dijo de él. Lo que el sistema no dijo
    queda en None: nada se inventa (por ejemplo, Windows da la señal en %, así que la señal en dBm queda vacía).
  * El BSSID nunca sale del computador: se envía su huella con la sal de esta instalación (como los equipos de la
    red) y solo su último byte, para que el usuario reconozca su propio router por la etiqueta.
  * Nunca se leen ni se exportan las contraseñas de los perfiles Wi-Fi.

Que una red aparezca no quiere decir que sea del usuario ni que pueda conectarse a ella: solo que la antena la vio.
Tampoco es la lista de todas las redes que existen: solo las que este adaptador alcanzó a oír en ese momento.

Hay dos herramientas (Strategy): ``NetshScanner`` y ``NmcliScanner``; ``scanner_for`` elige la del sistema
(Factory). Las dos devuelven el mismo resultado (Adapter), así que el resto del agente no sabe cuál se usó.
"""
from __future__ import annotations

import ctypes
import os
import re
import subprocess
import sys
import time
from typing import Callable, Optional

try:  # el agente como paquete (pruebas) o como script suelto (PyInstaller, python wifisense_agent.py)
    from agent.wifi_text import authentication_of, band_of, cipher_of, first_number, key_values, normalize_key, \
        split_nmcli
except ImportError:  # pragma: no cover
    from wifi_text import authentication_of, band_of, cipher_of, first_number, key_values, normalize_key, \
        split_nmcli

COMMAND_TIMEOUT = 20      # segundos que puede tardar netsh o nmcli antes de cancelarlo
FRESH_SCAN_WAIT = 4.0     # segundos que Windows necesita para terminar el escaneo que se le pidió
MAX_ACCESS_POINTS = 300   # el servidor no acepta más en un solo escaneo
FAILURES = ("NO_ADAPTER", "ADAPTER_OFF", "SERVICE_OFF", "LOCATION_PERMISSION", "COMMAND_FAILED", "TIMEOUT",
            "UNREADABLE_OUTPUT", "UNSUPPORTED_OS")
MAC = re.compile(r"^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$")

# --------------------------------------------------------------------------------------------- comando del sistema


class CommandResult:
    """Lo que respondió un comando: su código de salida, su texto y si se canceló por tiempo o no existe."""

    def __init__(self, code: Optional[int], text: str, timed_out: bool = False, missing: bool = False):
        self.code, self.text, self.timed_out, self.missing = code, text, timed_out, missing


def decode(raw: bytes) -> str:
    """netsh escribe en la página de códigos de la consola (cp850 en español); se prueba UTF-8 primero."""
    for encoding in ("utf-8", "oem", "cp850", "latin-1"):
        try:
            return raw.decode(encoding)
        except (UnicodeDecodeError, LookupError):
            continue
    return raw.decode("latin-1", errors="replace")  # pragma: no cover (latin-1 siempre decodifica)


def run(args: list[str], timeout: float = COMMAND_TIMEOUT) -> CommandResult:
    """Ejecuta un comando con sus argumentos por separado (nunca con el shell, así un nombre de red no puede inyectar
    nada) y con tiempo límite."""
    try:
        done = subprocess.run(args, capture_output=True, timeout=timeout,
                              creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except subprocess.TimeoutExpired:
        return CommandResult(None, "", timed_out=True)
    except FileNotFoundError:
        return CommandResult(None, "", missing=True)
    except (OSError, subprocess.SubprocessError) as error:
        return CommandResult(None, str(error))
    return CommandResult(done.returncode, decode(done.stdout) + decode(done.stderr))


# ------------------------------------------------------------------------------------------- errores de Windows

# Lo que netsh responde (en español o en inglés) cuando no puede escanear, y el motivo que se le envía al servidor.
# Se revisan en este orden: el permiso de ubicación también menciona la interfaz, por ejemplo.
FAILURE_HINTS = (
    ("LOCATION_PERMISSION", ("location permission", "location services", "permiso de ubicaci", "servicios de ubicaci")),
    ("SERVICE_OFF", ("wlansvc", "autoconfig service", "configuracion automatica de wlan",
                     "configuración automática de wlan")),
    ("NO_ADAPTER", ("no wireless interface", "ninguna interfaz inal", "no hay interfaces inal")),
)
RADIO_OFF = ("software off", "hardware off", "software apagado", "hardware apagado", "software desactivado",
             "hardware desactivado")


def failure_of(text: str) -> Optional[str]:
    """El motivo por el que netsh no pudo escanear, según su mensaje; None si el mensaje no es de error."""
    lower = (text or "").lower()
    for reason, hints in FAILURE_HINTS:
        if any(hint in lower for hint in hints):
            return reason
    return None


def radio_off(interfaces_text: str) -> bool:
    """El Wi-Fi está apagado (con el botón del teclado, el modo avión o en Configuración) según
    'netsh wlan show interfaces'."""
    lower = (interfaces_text or "").lower()
    return any(hint in lower for hint in RADIO_OFF)


# ------------------------------------------------------------------------------------------------- lectura (netsh)

# Claves exactas de 'netsh wlan show networks mode=bssid' ya normalizadas (sin tildes, espacios ni números), en
# inglés y en español, incluso cuando la consola dañó la tilde ('Se¤al' -> 'seal'). Son exactas a propósito:
# Windows 11 agrega 'Channel Utilization', que no es el canal.
SCAN_KEYS = {
    "interface": {"interfacename", "nombredelainterfaz", "nombredeinterfaz"},
    "ssid": {"ssid"},
    "bssid": {"bssid"},
    "authentication": {"authentication", "autenticacion", "autenticacin"},
    "cipher": {"encryption", "cipher", "cifrado"},
    "signal": {"signal", "senal", "seal"},
    "radio": {"radiotype", "tipoderadio"},
    "band": {"band", "banda"},
    "channel": {"channel", "canal"},
}


def scan_key(key: str) -> Optional[str]:
    normalized = normalize_key(key)
    for field, names in SCAN_KEYS.items():
        if normalized in names:
            return field
    return None


def clean_ssid(value: Optional[str]) -> Optional[str]:
    """El nombre tal como lo anuncia la red (tildes, emoji y comillas incluidos), sin caracteres de control; vacío es
    una red oculta."""
    if value is None:
        return None
    visible = "".join(c for c in value if c.isprintable())
    return visible[:64] if visible.strip() else None


def parse_netsh_scan(text: str) -> tuple[Optional[str], list[dict]]:
    """(adaptador, puntos de acceso) de 'netsh wlan show networks mode=bssid'. Cada punto de acceso trae la MAC
    todavía: ``describe`` la cambia por su huella antes de que salga del computador."""
    interface, found = None, []
    network: dict = {}
    current: Optional[dict] = None
    for key, value in key_values(text):
        field = scan_key(key)
        if field == "interface" and interface is None:
            interface = value or None
        elif field == "ssid":
            network = {"ssid": clean_ssid(value), "authentication": None, "cipher": None}
            current = None
        elif field in ("authentication", "cipher") and current is None:
            network[field] = value or None
        elif field == "bssid":
            mac = value.strip().lower().replace("-", ":")
            current = {"mac": mac, **network} if MAC.match(mac) else None
            if current is not None:
                found.append(current)
        elif current is not None and field in ("signal", "radio", "band", "channel"):
            current[field] = value or None
    return interface, [access_point(ap) for ap in found]


def access_point(raw: dict) -> dict:
    """Un punto de acceso con los nombres y unidades que espera el servidor. Lo que falte queda en None."""
    channel = first_number(raw.get("channel") or "")
    channel = int(channel) if channel and 1 <= channel <= 233 else None
    signal = first_number(raw.get("signal") or "")
    auth = raw.get("authentication")
    return {
        "mac": raw["mac"],
        "ssid": raw.get("ssid"),
        "signalPercent": int(signal) if signal is not None and 0 <= signal <= 100 else None,
        "signalDbm": None,  # netsh solo da el porcentaje: no se calcula
        "channel": channel,
        "band": band_of(raw.get("band") or "", channel) if raw.get("band") or channel else None,
        "radioType": (raw.get("radio") or "")[:20] or None,
        "authentication": authentication_of(auth or "", raw.get("cipher") or "") if auth else "UNKNOWN",
        "securityLabel": (auth or "")[:40] or None,
        "cipher": cipher_of(raw.get("cipher") or "") if raw.get("cipher") else None,
    }


def connected_bssid(interfaces_text: str) -> Optional[str]:
    """La MAC del punto de acceso al que está conectado este computador, según 'netsh wlan show interfaces'
    ('BSSID' en Windows 10 y 'AP BSSID' en Windows 11), o None si no está conectado."""
    state, bssid = None, None
    for key, value in key_values(interfaces_text or ""):
        normalized = normalize_key(key)
        if normalized in ("name", "nombre"):
            if state and bssid:
                break
            state, bssid = None, None
        elif normalized in ("state", "estado"):
            state = normalize_key(value).startswith(("connected", "conectado"))
        elif normalized in ("bssid", "apbssid"):
            mac = value.strip().lower().replace("-", ":")
            bssid = mac if MAC.match(mac) else None
    return bssid if state and bssid else None


# ------------------------------------------------------------------------------------------------- lectura (nmcli)

NMCLI_FIELDS = "IN-USE,BSSID,SSID,CHAN,FREQ,SIGNAL,SECURITY"


def parse_nmcli_scan(text: str) -> list[dict]:
    """Puntos de acceso de 'nmcli -t -f IN-USE,BSSID,SSID,CHAN,FREQ,SIGNAL,SECURITY dev wifi list'."""
    found = []
    for line in (text or "").splitlines():
        parts = split_nmcli(line)
        if len(parts) < 7:
            continue
        in_use, mac, ssid, chan, freq, signal, security = parts[:7]
        mac = mac.strip().lower()
        if not MAC.match(mac):
            continue
        freq_mhz = first_number(freq)
        security = security.strip()
        ap = access_point({"mac": mac, "ssid": clean_ssid(ssid), "channel": chan, "signal": signal,
                           "band": f"{freq_mhz / 1000:.1f}" if freq_mhz else "",
                           "authentication": security if security and security != "--" else "OPEN"})
        ap["securityLabel"] = security[:40] if security and security != "--" else None
        ap["connected"] = in_use.strip() == "*"
        found.append(ap)
    return found


# ---------------------------------------------------------------------------------- escaneo nuevo en Windows (API)

WLAN_INTERFACE_INFO_SIZE = 532  # GUID (16) + WCHAR[256] (512) + WLAN_INTERFACE_STATE (4)


def request_fresh_scan(library=None, sleep: Callable[[float], None] = time.sleep,
                       wait: float = FRESH_SCAN_WAIT) -> bool:
    """Le pide a Windows que vuelva a buscar redes con cada adaptador Wi-Fi (WlanScan) y espera a que termine. No
    pide permisos de administrador ni instala nada. False si no se pudo pedir (otro sistema, sin adaptador, servicio
    detenido o sin permiso): entonces se lee la última lista que tenga Windows."""
    if library is None:
        if os.name != "nt":
            return False
        try:
            library = ctypes.windll.wlanapi
        except (AttributeError, OSError):
            return False
    handle, version = ctypes.c_void_p(), ctypes.c_uint32()
    if library.WlanOpenHandle(2, None, ctypes.byref(version), ctypes.byref(handle)) != 0:
        return False
    asked = False
    try:
        interfaces = ctypes.c_void_p()
        if library.WlanEnumInterfaces(handle, None, ctypes.byref(interfaces)) != 0 or not interfaces.value:
            return False
        try:
            count = ctypes.c_uint32.from_address(interfaces.value).value
            first = interfaces.value + 8  # dwNumberOfItems y dwIndex van antes de la lista
            for index in range(min(count, 16)):
                guid = ctypes.c_void_p(first + index * WLAN_INTERFACE_INFO_SIZE)
                asked = library.WlanScan(handle, guid, None, None, None) == 0 or asked
        finally:
            library.WlanFreeMemory(interfaces)
    finally:
        library.WlanCloseHandle(handle, None)
    if asked:
        sleep(wait)
    return asked
