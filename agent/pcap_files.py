"""Lectura de archivos de captura pcap y pcapng (los que escribe pktmon de Windows al convertir su .etl).

Solo se leen las cabeceras de los bloques y los primeros bytes de cada paquete (el agente pide a la herramienta que
guarde como mucho 128 bytes por paquete). Un archivo dañado o truncado no rompe el agente: se detiene la lectura y
se cuenta el resto como dañado. Nada de esto sale del computador: packet_parser y capture_stats lo convierten en
conteos y el archivo se borra (capture_files).

Formatos (https://www.ietf.org/archive/id/draft-ietf-opsawg-pcap-03.html y draft-ietf-opsawg-pcapng):
  * pcap: cabecera de 24 bytes (número mágico, versión, tamaño máximo, tipo de enlace) y cada paquete con 16 bytes
    de cabecera (segundos, micro o nanosegundos, bytes guardados, bytes originales).
  * pcapng: bloques (tipo, largo, cuerpo, largo). SHB abre una sección (y dice el orden de los bytes), IDB describe
    una interfaz (tipo de enlace y resolución del tiempo), EPB y SPB traen paquetes, ISB trae estadísticas de la
    interfaz (paquetes que la herramienta perdió).
"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import BinaryIO, Iterator, Optional

PCAP_MAGIC_US = 0xA1B2C3D4
PCAP_MAGIC_NS = 0xA1B23C4D
PCAPNG_SHB = 0x0A0D0D0A
PCAPNG_BYTE_ORDER = 0x1A2B3C4D
BLOCK_IDB, BLOCK_SPB, BLOCK_ISB, BLOCK_EPB, BLOCK_OPB = 1, 3, 5, 6, 2
OPTION_END, OPTION_IF_TSRESOL, OPTION_ISB_IFDROP = 0, 9, 5
MAX_BLOCK = 1 << 20  # un bloque de más de 1 MB no es de una captura de cabeceras: el archivo está dañado


class CaptureFileError(Exception):
    """El archivo no es pcap ni pcapng."""


@dataclass(frozen=True)
class Frame:
    """Un paquete leído del archivo: momento (segundos), tipo de enlace, bytes guardados y largo original."""
    timestamp: float
    link_type: int
    data: bytes
    original_length: int


@dataclass
class FileSummary:
    """Lo que el archivo dice de sí mismo además de los paquetes."""
    dropped_by_tool: Optional[int] = None  # suma de isb_ifdrop de pcapng; None si la herramienta no lo dijo
    damaged: bool = False                  # la lectura se detuvo en un bloque dañado o truncado


def read_frames(stream: BinaryIO, summary: Optional[FileSummary] = None) -> Iterator[Frame]:
    """Los paquetes de un archivo pcap o pcapng, en orden."""
    summary = summary if summary is not None else FileSummary()
    head = stream.read(4)
    if len(head) < 4:
        raise CaptureFileError("El archivo de captura está vacío.")
    if struct.unpack("<I", head)[0] == PCAPNG_SHB:
        yield from _pcapng(stream, head, summary)
        return
    for order in ("<", ">"):
        magic = struct.unpack(order + "I", head)[0]
        if magic in (PCAP_MAGIC_US, PCAP_MAGIC_NS):
            yield from _pcap(stream, order, magic == PCAP_MAGIC_NS, summary)
            return
    raise CaptureFileError("El archivo no es una captura pcap ni pcapng.")


def _pcap(stream: BinaryIO, order: str, nanoseconds: bool, summary: FileSummary) -> Iterator[Frame]:
    header = stream.read(20)
    if len(header) < 20:
        summary.damaged = True
        return
    link_type = struct.unpack(order + "HHiIII", header)[5] & 0x0FFFFFFF
    divisor = 1e9 if nanoseconds else 1e6
    while True:
        record = stream.read(16)
        if not record:
            return
        if len(record) < 16:
            summary.damaged = True
            return
        seconds, fraction, saved, original = struct.unpack(order + "IIII", record)
        if saved > MAX_BLOCK:
            summary.damaged = True
            return
        data = stream.read(saved)
        if len(data) < saved:
            summary.damaged = True
            return
        yield Frame(seconds + fraction / divisor, link_type, data, original)
