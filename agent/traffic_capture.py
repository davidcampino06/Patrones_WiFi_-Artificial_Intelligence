"""Capturas técnicas autorizadas (agente 2.0.0, solo el sensor de una red del equipo). Patrón Facade.

Problema: una captura toca muchas piezas (el permiso local, la herramienta disponible, los límites, la carpeta
temporal, la consulta "¿me detengo?", el conteo y el envío) y cualquiera puede fallar. Solución: ``run_capture`` es
la única entrada; el resto del agente no conoce las herramientas ni los archivos.

Reglas que se cumplen siempre:
  1. Solo se captura si quien administra ESTE computador lo permitió (``capture-consent on``). Pedirlo desde la
     página no basta: el servidor no puede encender la captura por su cuenta.
  2. El servidor solo envía el número de la captura y sus límites; nunca un comando. El agente decide la herramienta.
  3. Sin modo promiscuo, como mucho 128 bytes por paquete, y dentro de los límites (segundos, paquetes, bytes).
  4. Al servidor solo van conteos (capture_stats). El archivo temporal se borra al terminar, salga bien o mal.
  5. Se informa en la consola qué se está capturando, y queda una línea en el registro local (sin secretos).
  6. Si no se puede capturar, se dice el motivo real (sin herramienta, sin permiso...), nunca un resultado inventado.
"""
from __future__ import annotations

import json
import os
import socket
import threading
import time
from pathlib import Path
from typing import Callable, Optional

try:  # el agente como paquete (pruebas) o como script suelto (PyInstaller)
    from agent import capture_backends as backends_module
    from agent import capture_files
    from agent.capture_stats import CaptureStats, Limits, failure, local_networks
except ImportError:  # pragma: no cover
    import capture_backends as backends_module
    import capture_files
    from capture_stats import CaptureStats, Limits, failure, local_networks

STATE_POLL_SECONDS = 5  # cada cuánto se pregunta al servidor si un administrador pidió detener la captura
CONSENT_KEY = "captureConsent"


# ------------------------------------------------------------------------------------------------ consentimiento

def consent_given(config: dict) -> bool:
    """El permiso local: solo True si alguien lo activó explícitamente en este computador."""
    return config.get(CONSENT_KEY) is True


def set_consent(config: dict, allowed: bool) -> dict:
    updated = dict(config)
    updated[CONSENT_KEY] = bool(allowed)
    return updated
