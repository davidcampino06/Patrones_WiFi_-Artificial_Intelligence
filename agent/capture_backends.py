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


# ------------------------------------------------------------------------------------------------------- Npcap

@dataclass
class NpcapDevice:
    name: str
    description: str
    addresses: list = field(default_factory=list)
    loopback: bool = False


class NpcapLibrary:
    """Adapter: la API en C de Npcap (wpcap.dll, la misma de libpcap) vista como métodos de Python.

    Solo se usa lo necesario para capturar cabeceras sin modo promiscuo. Las pruebas reemplazan esta clase por una
    falsa con los mismos métodos, sin tocar ningún controlador."""

    PCAP_IF_LOOPBACK = 0x1
    ERRBUF_SIZE = 256

    class _Header(ctypes.Structure):
        _fields_ = [("tv_sec", ctypes.c_long), ("tv_usec", ctypes.c_long), ("caplen", ctypes.c_uint32),
                    ("len", ctypes.c_uint32)]

    class _Stat(ctypes.Structure):
        _fields_ = [("ps_recv", ctypes.c_uint), ("ps_drop", ctypes.c_uint), ("ps_ifdrop", ctypes.c_uint)]

    def __init__(self, dll: object):
        self.dll = dll
        dll.pcap_open_live.restype = ctypes.c_void_p
        dll.pcap_create.restype = ctypes.c_void_p
        dll.pcap_geterr.restype = ctypes.c_char_p
        for name in ("pcap_next_ex", "pcap_datalink", "pcap_stats", "pcap_can_set_rfmon"):
            getattr(dll, name).argtypes = None
        dll.pcap_close.argtypes = [ctypes.c_void_p]

    @staticmethod
    def load() -> Optional["NpcapLibrary"]:
        """La biblioteca de Npcap si está instalada; None si no (WiFiSense nunca la instala)."""
        if not IS_WINDOWS:
            return None
        folder = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "Npcap"
        if not (folder / "wpcap.dll").exists():
            return None
        try:
            os.add_dll_directory(str(folder))  # Packet.dll está en la misma carpeta
            return NpcapLibrary(ctypes.CDLL(str(folder / "wpcap.dll")))
        except OSError:
            return None

    def devices(self) -> list[NpcapDevice]:
        class Sockaddr(ctypes.Structure):
            _fields_ = [("family", ctypes.c_ushort), ("data", ctypes.c_ubyte * 14)]

        class Addr(ctypes.Structure):
            pass
        Addr._fields_ = [("next", ctypes.POINTER(Addr)), ("addr", ctypes.POINTER(Sockaddr)),
                         ("netmask", ctypes.POINTER(Sockaddr)), ("broadaddr", ctypes.POINTER(Sockaddr)),
                         ("dstaddr", ctypes.POINTER(Sockaddr))]

        class Interface(ctypes.Structure):
            pass
        Interface._fields_ = [("next", ctypes.POINTER(Interface)), ("name", ctypes.c_char_p),
                              ("description", ctypes.c_char_p), ("addresses", ctypes.POINTER(Addr)),
                              ("flags", ctypes.c_uint)]

        first = ctypes.POINTER(Interface)()
        errbuf = ctypes.create_string_buffer(self.ERRBUF_SIZE)
        if self.dll.pcap_findalldevs(ctypes.byref(first), errbuf) != 0:
            raise CaptureFailed(_failure_of(errbuf.value), _text(errbuf.value))
        found, node = [], first
        try:
            while node:
                item = node.contents
                addresses, address = [], item.addresses
                while address:
                    sockaddr = address.contents.addr
                    if sockaddr and sockaddr.contents.family == socket.AF_INET:
                        addresses.append(socket.inet_ntoa(bytes(sockaddr.contents.data[2:6])))
                    address = address.contents.next
                found.append(NpcapDevice(_text(item.name), _text(item.description), addresses,
                                         bool(item.flags & self.PCAP_IF_LOOPBACK)))
                node = item.next
        finally:
            self.dll.pcap_freealldevs(first)
        return found

    def open(self, name: str) -> int:
        errbuf = ctypes.create_string_buffer(self.ERRBUF_SIZE)
        handle = self.dll.pcap_open_live(name.encode(), SNAPLEN, 0, READ_TIMEOUT_MS, errbuf)  # 0: sin promiscuo
        if not handle:
            raise CaptureFailed(_failure_of(errbuf.value), _text(errbuf.value))
        return handle

    def datalink(self, handle: int) -> int:
        return self.dll.pcap_datalink(ctypes.c_void_p(handle))

    def next(self, handle: int) -> tuple[int, float, bytes, int]:
        """(1 paquete | 0 nada todavía | -1 error, momento, bytes guardados, largo original)."""
        header = ctypes.POINTER(self._Header)()
        data = ctypes.POINTER(ctypes.c_ubyte)()
        status = self.dll.pcap_next_ex(ctypes.c_void_p(handle), ctypes.byref(header), ctypes.byref(data))
        if status != 1:
            return status, 0.0, b"", 0
        h = header.contents
        return 1, h.tv_sec + h.tv_usec / 1e6, ctypes.string_at(data, min(h.caplen, SNAPLEN)), h.len

    def error(self, handle: int) -> str:
        return _text(self.dll.pcap_geterr(ctypes.c_void_p(handle)))

    def dropped(self, handle: int) -> Optional[int]:
        stat = self._Stat()
        if self.dll.pcap_stats(ctypes.c_void_p(handle), ctypes.byref(stat)) != 0:
            return None
        return int(stat.ps_drop) + int(stat.ps_ifdrop)

    def close(self, handle: int) -> None:
        self.dll.pcap_close(ctypes.c_void_p(handle))

    def can_monitor(self, name: str) -> Optional[bool]:
        """Si la tarjeta declara modo monitor (solo se pregunta; nunca se activa)."""
        errbuf = ctypes.create_string_buffer(self.ERRBUF_SIZE)
        handle = self.dll.pcap_create(name.encode(), errbuf)
        if not handle:
            return None
        try:
            answer = self.dll.pcap_can_set_rfmon(ctypes.c_void_p(handle))
            return None if answer < 0 else bool(answer)
        finally:
            self.dll.pcap_close(ctypes.c_void_p(handle))


def _text(raw) -> str:
    if raw is None:
        return ""
    return raw.decode("utf-8", "replace") if isinstance(raw, bytes) else str(raw)


def _failure_of(message) -> str:
    text = _text(message).lower()
    if any(word in text for word in ("denied", "denegado", "permission", "permiso", "administrator")):
        return "PERMISSION_DENIED"
    if any(word in text for word in ("no such device", "no interfaces", "not found")):
        return "NO_INTERFACE"
    return "CAPTURE_ERROR"


class NpcapBackend:
    """Npcap (npcap.com), si el usuario lo instaló (por ejemplo con Wireshark). Por defecto no necesita administrador."""
    code = "NPCAP"

    def __init__(self, library_loader: Callable[[], Optional[NpcapLibrary]] = NpcapLibrary.load):
        self._loader = library_loader
        self._library: Optional[NpcapLibrary] = None

    def library(self) -> Optional[NpcapLibrary]:
        if self._library is None:
            self._library = self._loader()
        return self._library

    def check(self, own_ip: Optional[str] = None) -> Check:
        library = self.library()
        if library is None:
            return Check(False, False, "NO_CAPTURE_TOOL", "Npcap no está instalado.")
        try:
            devices = [d for d in library.devices() if not d.loopback]
        except CaptureFailed as failure:
            return Check(False, True, failure.reason, failure.detail)
        if not devices:
            return Check(False, True, "NO_INTERFACE", "Npcap no ve ninguna interfaz de red.")
        device = self.pick(devices, own_ip)
        return Check(True, True, interfaces=len(devices), monitor_mode=library.can_monitor(device.name))

    @staticmethod
    def pick(devices: list[NpcapDevice], own_ip: Optional[str]) -> NpcapDevice:
        """La interfaz por la que este computador sale a la red (la que tiene su IP); si no, la primera."""
        for device in devices:
            if own_ip and own_ip in device.addresses:
                return device
        with_address = [d for d in devices if d.addresses]
        return (with_address or devices)[0]

    def capture(self, session: Session) -> Run:
        library = self.library()
        if library is None:
            raise CaptureFailed("NO_CAPTURE_TOOL", "Npcap no está instalado.")
        devices = [d for d in library.devices() if not d.loopback]
        if not devices:
            raise CaptureFailed("NO_INTERFACE", "Npcap no ve ninguna interfaz de red.")
        device = self.pick(devices, session.own_ip)
        handle = library.open(device.name)
        try:
            link_type = library.datalink(handle)
            started = session.clock()
            while not session.over(started):
                status, timestamp, data, original = library.next(handle)
                if status == 1:
                    session.stats.add(packet_parser.parse(data, link_type, original), timestamp)
                elif status < 0:
                    raise CaptureFailed("CAPTURE_ERROR", library.error(handle))
            return Run(device.description or device.name, library.dropped(handle))
        finally:
            library.close(handle)


# ------------------------------------------------------------------------------------------------------ pktmon

Runner = Callable[[list[str], float], "subprocess.CompletedProcess"]


def run(args: list[str], timeout: float = COMMAND_TIMEOUT) -> subprocess.CompletedProcess:
    """Ejecuta una herramienta del sistema con sus argumentos separados (nunca a través de una consola)."""
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    return subprocess.run(args, capture_output=True, timeout=timeout, creationflags=flags, check=False)


LOST_EVENTS = re.compile(r"(?i)(?:lost events|eventos perdidos)\D{0,20}(\d+)")


class PktmonBackend:
    """pktmon, el monitor de paquetes que viene con Windows 10 (versión 1809 o posterior) y 11. Necesita que el
    agente corra como administrador. Escribe un .etl temporal que se convierte a .pcapng para contarlo; ambos se
    borran al terminar (capture_files.TempCapture)."""
    code = "PKTMON"

    def __init__(self, runner: Runner = run, which: Callable[[str], Optional[str]] = shutil.which,
                 elevated: Callable[[], bool] = is_elevated, windows: bool = IS_WINDOWS):
        self.runner, self.which, self.elevated, self.windows = runner, which, elevated, windows

    def check(self, own_ip: Optional[str] = None) -> Check:
        if not self.windows:
            return Check(False, False, "UNSUPPORTED_OS", "pktmon solo existe en Windows.")
        if not self.which("pktmon"):
            return Check(False, False, "NO_CAPTURE_TOOL", "Esta versión de Windows no trae pktmon.")
        if not self.elevated():
            return Check(False, True, "PERMISSION_DENIED", "pktmon necesita que el agente corra como administrador.")
        return Check(True, True, interfaces=1)

    def capture(self, session: Session) -> Run:
        if session.temp is None:
            raise CaptureFailed("CAPTURE_ERROR", "pktmon necesita una carpeta temporal.")
        etl, pcapng = session.temp.file("captura.etl"), session.temp.file("captura.pcapng")
        self._start(etl)
        started = session.clock()
        stopped = None
        try:
            while not session.over(started):
                session.sleep(1)
        finally:
            stopped = self._command(["pktmon", "stop"])
        if not etl.exists():
            raise CaptureFailed("CAPTURE_ERROR", "pktmon no escribió el archivo de la captura.")
        self._convert(etl, pcapng)
        # el archivo se lee después de detener pktmon: el motivo de la parada se guarda y se lee todo lo capturado,
        # salvo que al contar se alcance el límite de paquetes o de bytes
        why_stopped, session.stats.stop_reason = session.stats.stop_reason, None
        summary = pcap_files.FileSummary()
        try:
            with open(pcapng, "rb") as stream:
                for frame in pcap_files.read_frames(stream, summary):
                    info = packet_parser.parse(frame.data, frame.link_type, frame.original_length)
                    if not session.stats.add(info, frame.timestamp or None):
                        break
        except pcap_files.CaptureFileError as error:
            raise CaptureFailed("CAPTURE_ERROR", str(error))
        session.stats.stop_reason = session.stats.stop_reason or why_stopped
        lost = LOST_EVENTS.search(_text(stopped.stdout) if stopped else "")
        dropped = int(lost.group(1)) if lost else summary.dropped_by_tool
        return Run("pktmon (tarjetas de red)", dropped, summary.damaged)

    def _start(self, etl: Path) -> None:
        modern = ["pktmon", "start", "--capture", "--comp", "nics", "--pkt-size", str(SNAPLEN), "--file-name",
                  str(etl), "--file-size", "64"]
        answer = self._command(modern)
        if answer.returncode == 0:
            return
        legacy = ["pktmon", "start", "--etw", "-p", str(SNAPLEN), "-f", str(etl)]  # Windows 10 1809 a 1909
        retry = self._command(legacy)
        if retry.returncode != 0:
            message = (_text(answer.stderr) or _text(answer.stdout)).strip()[:200]
            raise CaptureFailed(_failure_of(message), message or "pktmon no pudo iniciar la captura.")

    def _convert(self, etl: Path, pcapng: Path) -> None:
        for args in (["pktmon", "etl2pcap", str(etl), "--out", str(pcapng)],
                     ["pktmon", "pcapng", str(etl), "-o", str(pcapng)]):
            if self._command(args).returncode == 0 and pcapng.exists():
                return
        raise CaptureFailed("CAPTURE_ERROR", "pktmon no pudo convertir la captura a pcapng.")

    def _command(self, args: list[str]) -> subprocess.CompletedProcess:
        try:
            return self.runner(args, COMMAND_TIMEOUT)
        except subprocess.TimeoutExpired:
            raise CaptureFailed("CAPTURE_ERROR", f"{' '.join(args[:2])} no respondió a tiempo.")
        except OSError as error:
            raise CaptureFailed("CAPTURE_ERROR", f"No se pudo ejecutar pktmon: {error}")
