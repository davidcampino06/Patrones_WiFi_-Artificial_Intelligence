"""Archivos temporales de las capturas y su política de retención.

pktmon escribe lo que captura en un archivo (.etl) que luego se convierte a .pcapng para contarlo. Esos archivos:
  * viven en una carpeta propia del usuario que ejecuta el agente (en Windows dentro de %LOCALAPPDATA%, que ya es
    privada de cada usuario; en Linux con permisos 700), nunca en una carpeta compartida;
  * guardan como mucho 128 bytes de cada paquete (cabeceras, no contenido);
  * se borran apenas termina el conteo, haya salido bien o mal (TempCapture es un administrador de contexto);
  * si el agente se cerró a mitad de una captura, los restos de más de una hora se borran al iniciar (purge_old).
Nunca se envían al servidor ni se pueden descargar desde la página: el servidor solo recibe los conteos.
"""
from __future__ import annotations

import os
import secrets
import shutil
import time
from pathlib import Path
from typing import Optional

RETENTION_SECONDS = 3600
IS_WINDOWS = os.name == "nt"


def captures_dir(base: Optional[Path] = None) -> Path:
    """Carpeta de las capturas temporales, creada solo para este usuario."""
    if base is None:
        root = os.environ.get("LOCALAPPDATA") if IS_WINDOWS else os.environ.get("XDG_CACHE_HOME")
        base = Path(root or Path.home() / ".cache") / "WiFiSense"
    folder = base / "capturas"
    folder.mkdir(parents=True, exist_ok=True)
    if not IS_WINDOWS:
        os.chmod(folder, 0o700)
    return folder


def purge_old(folder: Path, now: Optional[float] = None, max_age: int = RETENTION_SECONDS) -> int:
    """Borra lo que quedó de capturas interrumpidas (más viejo que ``max_age`` segundos). Devuelve cuántos borró."""
    now = time.time() if now is None else now
    removed = 0
    for entry in folder.iterdir() if folder.exists() else ():
        try:
            if now - entry.stat().st_mtime < max_age:
                continue
            if entry.is_dir():
                shutil.rmtree(entry, ignore_errors=True)
            else:
                entry.unlink()
            removed += 1
        except OSError:
            continue
    return removed


class TempCapture:
    """Una carpeta para una sola captura, que se borra entera al salir del bloque ``with``, incluso con un error."""

    def __init__(self, folder: Path):
        self.path = folder / f"captura-{int(time.time())}-{secrets.token_hex(4)}"

    def __enter__(self) -> "TempCapture":
        self.path.mkdir(mode=0o700)
        return self

    def file(self, name: str) -> Path:
        return self.path / name

    def __exit__(self, *_exc) -> None:
        shutil.rmtree(self.path, ignore_errors=True)

    @property
    def removed(self) -> bool:
        return not self.path.exists()
