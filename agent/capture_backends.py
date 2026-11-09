"""Herramientas de captura que el agente sabe usar (patrón Strategy, con un Adapter para Npcap).

Problema: en Windows hay varias formas de capturar, cada una con sus requisitos (Npcap lo instala el usuario y no
necesita administrador; pktmon viene con Windows pero sí lo necesita; el socket sin procesar solo ve IP) y en Linux
otra distinta. Solución: cada herramienta es una clase con la misma interfaz (``check`` y ``capture``) y
``choose_backend`` elige la primera que funcione en este computador, en orden de preferencia. Agregar otra herramienta
es agregar una clase, sin tocar el resto del agente.

Captura mínima en todas: sin modo promiscuo (solo el tráfico de este computador y la difusión de la red), como mucho
SNAPLEN bytes por paquete (las cabeceras) y siempre dentro de los límites de la captura. Ninguna instala nada ni
cambia la configuración del sistema: si falta una herramienta o un permiso, se informa y la captura no se hace.

Lo que NO puede hacer ninguna (y se dice en la página): ver lo que los demás equipos del Wi-Fi envían a Internet. En
Wi-Fi cada equipo habla con el punto de acceso; para eso haría falta modo monitor (escenario C), que el agente no activa.
"""
from __future__ import annotations

import ctypes
import os
import re
import shutil
import socket
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Optional

try:  # el agente como paquete (pruebas) o como script suelto (PyInstaller)
    from agent import packet_parser, pcap_files
    from agent.capture_stats import CaptureStats
    from agent.capture_files import TempCapture
except ImportError:  # pragma: no cover
    import packet_parser
    import pcap_files
    from capture_stats import CaptureStats
    from capture_files import TempCapture

IS_WINDOWS = os.name == "nt"
SNAPLEN = 128          # bytes guardados por paquete: alcanzan para las cabeceras, no para el contenido
READ_TIMEOUT_MS = 500  # cada cuánto se revisa si hay que detenerse aunque no lleguen paquetes
COMMAND_TIMEOUT = 60


class CaptureFailed(Exception):
    """La captura no se pudo hacer. ``reason`` es uno de los motivos que entiende el servidor."""

    def __init__(self, reason: str, detail: str = ""):
        super().__init__(detail or reason)
        self.reason = reason
        self.detail = detail


@dataclass
class Check:
    """Si una herramienta se puede usar ahora en este computador, y si no, por qué."""
    usable: bool
    present: bool
    reason: Optional[str] = None  # NO_CAPTURE_TOOL, PERMISSION_DENIED, NO_INTERFACE, UNSUPPORTED_OS
    detail: str = ""
    interfaces: int = 0
    monitor_mode: Optional[bool] = None  # None: no se sabe


@dataclass
class Run:
    """Lo que la herramienta dice de la captura además de los paquetes."""
    interface_name: Optional[str]
    dropped_by_tool: Optional[int] = None  # None cuando la herramienta no lo informa (nunca se inventa un 0)
    damaged_file: bool = False


@dataclass
class Session:
    """Lo que una herramienta necesita para capturar: dónde contar, cuándo parar y dónde dejar temporales."""
    stats: CaptureStats
    should_stop: Callable[[], bool]
    temp: Optional[TempCapture] = None
    own_ip: Optional[str] = None
    clock: Callable[[], float] = time.monotonic
    wall: Callable[[], float] = time.time
    sleep: Callable[[float], None] = time.sleep

    def over(self, started: float) -> bool:
        """True cuando hay que dejar de capturar: se pidió parar, se alcanzó un límite o se acabó el tiempo."""
        if self.stats.full():
            return True
        if self.should_stop():
            self.stats.stop_reason = self.stats.stop_reason or "CANCELLED"
            return True
        if self.clock() - started >= self.stats.limits.seconds:
            self.stats.stop_reason = self.stats.stop_reason or "DURATION"
            return True
        return False


def is_elevated() -> bool:
    """True si el agente corre como administrador (Windows) o root (Linux)."""
    try:
        if IS_WINDOWS:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
        return os.geteuid() == 0
    except (AttributeError, OSError):
        return False
