"""Los archivos temporales de una captura: carpeta privada, borrado al terminar y limpieza de restos."""
import os
import stat

import pytest

from agent import capture_files


def test_the_folder_is_private_to_the_user(tmp_path):
    folder = capture_files.captures_dir(tmp_path)

    assert folder.exists()
    if os.name != "nt":
        assert stat.S_IMODE(folder.stat().st_mode) == 0o700


def test_a_capture_folder_is_deleted_even_when_the_capture_fails(tmp_path):
    folder = capture_files.captures_dir(tmp_path)
    with pytest.raises(RuntimeError):
        with capture_files.TempCapture(folder) as temp:
            temp.file("captura.etl").write_bytes(b"datos")
            raise RuntimeError("falló a mitad")

    assert temp.removed
    assert list(folder.iterdir()) == []


def test_leftovers_older_than_an_hour_are_purged_and_recent_ones_kept(tmp_path):
    folder = capture_files.captures_dir(tmp_path)
    old, recent = folder / "captura-vieja", folder / "captura-nueva.pcapng"
    old.mkdir()
    (old / "captura.etl").write_bytes(b"x")
    recent.write_bytes(b"x")
    now = recent.stat().st_mtime
    os.utime(old, (now - 7200, now - 7200))

    assert capture_files.purge_old(folder, now=now) == 1
    assert not old.exists() and recent.exists()
