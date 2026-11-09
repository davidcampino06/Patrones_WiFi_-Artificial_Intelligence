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


# ------------------------------------------------------------------------------------------------- capacidades

def capabilities(config: dict, own_ip: Optional[str], backends: Optional[list] = None,
                 elevated: Optional[Callable[[], bool]] = None, monitor_hint: Optional[bool] = None) -> dict:
    """Lo que este computador puede hacer, para el reporte (AgentReportRequest.Capabilities). Se revisa de verdad:
    una herramienta que existe pero no se puede usar (falta administrador) se informa como no disponible."""
    backends = backends_module.all_backends() if backends is None else backends
    elevated = elevated or backends_module.is_elevated
    _chosen, checks = backends_module.choose_all(backends, own_ip)
    usable = {code: check.usable for code, check in checks.items()}
    monitor = next((check.monitor_mode for check in checks.values() if check.monitor_mode is not None), monitor_hint)
    return {
        "elevated": bool(elevated()),
        "captureConsent": consent_given(config),
        "npcap": usable.get("NPCAP", False),
        "pktmon": usable.get("PKTMON", False),
        "rawSocket": usable.get("RAW_SOCKET", False),
        "packetSocket": usable.get("PACKET_SOCKET", False),
        "monitorMode": "UNKNOWN" if monitor is None else "SUPPORTED" if monitor else "UNSUPPORTED",
        "captureInterfaces": max((check.interfaces for check in checks.values() if check.usable), default=0),
    }


def describe_capabilities(caps: dict, checks: Optional[dict] = None) -> str:
    """Texto para la consola (comando capture-check)."""
    tools = [name for name, key in (("Npcap", "npcap"), ("pktmon", "pktmon"), ("socket de Windows", "rawSocket"),
                                    ("socket de paquetes", "packetSocket")) if caps.get(key)]
    lines = [
        f"Capturas permitidas en este computador: {'sí' if caps['captureConsent'] else 'no (capture-consent on)'}",
        f"Corre como administrador: {'sí' if caps['elevated'] else 'no'}",
        f"Herramientas que se pueden usar ahora: {', '.join(tools) if tools else 'ninguna'}",
        "Modo monitor de la tarjeta Wi-Fi: " + {"SUPPORTED": "la tarjeta lo declara (el agente no lo activa)",
                                                "UNSUPPORTED": "no lo tiene",
                                                "UNKNOWN": "no se sabe"}[caps["monitorMode"]],
    ]
    for code, check in (checks or {}).items():
        if not check.usable and check.detail:
            lines.append(f"  {code}: {check.detail}")
    return "\n".join(lines)
