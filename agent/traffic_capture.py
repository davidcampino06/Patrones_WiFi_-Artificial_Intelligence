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


# ---------------------------------------------------------------------------------------------- una captura

class StopWatcher:
    """Pregunta al servidor cada pocos segundos si hay que detenerse, en un hilo aparte (la captura no se bloquea)."""

    def __init__(self, ask: Callable[[], bool], every: float = STATE_POLL_SECONDS):
        self.ask, self.every = ask, every
        self.flag = threading.Event()
        self._done = threading.Event()
        self._thread = threading.Thread(target=self._loop, daemon=True)

    def __enter__(self) -> "StopWatcher":
        self._thread.start()
        return self

    def _loop(self) -> None:
        while not self._done.wait(self.every):
            try:
                if self.ask():
                    self.flag.set()
                    return
            except Exception:  # sin conexión no se detiene: los límites de la captura siguen valiendo
                continue

    def __exit__(self, *_exc) -> None:
        self._done.set()
        self._thread.join(timeout=2)

    def __call__(self) -> bool:
        return self.flag.is_set()


def own_addresses(own_ip: Optional[str]) -> frozenset:
    found = {own_ip} if own_ip else set()
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            found.add(info[4][0].split("%")[0])
    except OSError:
        pass
    return frozenset(found)


def run_capture(task: dict, config: dict, agent_version: str, deliver: Callable[[dict], None],
                ask_stop: Callable[[], bool], own_ip: Optional[str], prefixes: list[str],
                backends: Optional[list] = None, temp_root: Optional[Path] = None,
                log: Callable[[str], None] = print, watcher_every: float = STATE_POLL_SECONDS,
                clock: Callable[[], float] = time.monotonic, sleep: Callable[[float], None] = time.sleep) -> dict:
    """Hace la captura ``task`` (lo que respondió el servidor) y entrega el resultado con ``deliver``. Devuelve lo
    entregado. Nunca lanza: cualquier problema termina en un resultado FAILED con su motivo."""
    capture_id = task.get("captureId")
    if not isinstance(capture_id, int) or isinstance(capture_id, bool) or capture_id <= 0:
        return {}
    limits = Limits.of(task)
    if not consent_given(config):
        log(f"  Captura técnica #{capture_id} rechazada: en este computador no se han permitido las capturas "
            "(capture-consent on).")
        return _deliver(deliver, failure(capture_id, "NO_CONSENT", agent_version), log)

    backends = backends_module.all_backends() if backends is None else backends
    backend, checks = backends_module.choose_backend(backends, own_ip)
    if backend is None:
        reason = backends_module.failure_without_tool(checks)
        log(f"  Captura técnica #{capture_id}: no hay herramienta de captura utilizable ({reason}).")
        return _deliver(deliver, failure(capture_id, reason, agent_version), log)

    log(f"  Captura técnica #{capture_id} con {backend.code}: hasta {limits.seconds} s, {limits.packets} paquetes. "
        "Solo cabeceras de este computador y de la difusión de la red; no se guarda el contenido.")
    stats = CaptureStats(limits, own_addresses(own_ip), local_networks(prefixes))
    folder = capture_files.captures_dir(temp_root)
    capture_files.purge_old(folder)
    started = clock()
    try:
        with capture_files.TempCapture(folder) as temp, StopWatcher(ask_stop, watcher_every) as stop:
            session = backends_module.Session(stats, stop, temp, own_ip, clock=clock, sleep=sleep)
            run = backend.capture(session)
        result = stats.result(capture_id, backend.code, run.interface_name, agent_version,
                              int((clock() - started) * 1000), run.dropped_by_tool)
        if run.damaged_file:
            result["malformedPackets"] = min(result.get("malformedPackets", 0) + 1, result["packetCount"])
    except backends_module.CaptureFailed as failed:
        log(f"  Captura técnica #{capture_id} falló: {failed.detail or failed.reason}")
        result = failure(capture_id, failed.reason, agent_version, backend.code)
    except Exception as error:  # una falla inesperada también se informa, sin datos parciales
        log(f"  Captura técnica #{capture_id} falló: {error}")
        result = failure(capture_id, "CAPTURE_ERROR", agent_version, backend.code)
    finally:
        stats.forget_addresses()
    if result.get("status") == "COMPLETED":
        log(f"  Captura técnica #{capture_id}: {result['packetCount']} paquetes, {result['byteCount']} bytes "
            f"({result['stopReason']}). El archivo temporal se borró.")
    return _deliver(deliver, result, log)


def _deliver(deliver: Callable[[dict], None], result: dict, log: Callable[[str], None]) -> dict:
    try:
        deliver(result)
    except Exception as error:
        log(f"  No se entregó la captura: {error}")
    append_log(result)
    return result
