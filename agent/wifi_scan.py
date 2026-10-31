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
