"""The CI script that builds the Railway image retries a registry hiccup but still fails on a real error.

A fake `docker` on the PATH plays the registry: it fails the first N builds and then succeeds (or never succeeds).
"""
import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / ".github" / "scripts" / "construir-imagen.sh"

pytestmark = pytest.mark.skipif(shutil.which("bash") is None or os.name == "nt", reason="the script runs on Linux CI")


def run_script(tmp_path: Path, failures: int) -> subprocess.CompletedProcess:
    counter = tmp_path / "builds"
    fake = tmp_path / "bin" / "docker"
    fake.parent.mkdir()
    fake.write_text(
        "#!/usr/bin/env bash\n"
        f"n=$(( $(cat {counter} 2>/dev/null || echo 0) + 1 )); echo $n > {counter}\n"
        f"if [ $n -le {failures} ]; then\n"
        "  echo '#2 [internal] load metadata for public.ecr.aws/docker/library/python:3.13-slim'\n"
        "  echo 'ERROR: failed to do request: Head \"https://public.ecr.aws/v2/...\": 429 Too Many Requests'\n"
        "  exit 1\n"
        "fi\n"
        "echo 'naming to docker.io/library/wifisense-ai done'\n")
    fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
    env = {**os.environ, "PATH": f"{fake.parent}{os.pathsep}{os.environ['PATH']}", "WAIT_SECONDS": "0"}
    return subprocess.run(["bash", str(SCRIPT)], cwd=tmp_path, env=env, capture_output=True, text=True, timeout=30)


def test_a_registry_hiccup_is_retried_and_reported(tmp_path):
    result = run_script(tmp_path, failures=2)

    assert result.returncode == 0
    warnings = [line for line in result.stdout.splitlines() if line.startswith("::warning")]
    assert len(warnings) == 2
    assert "429 Too Many Requests" in warnings[0]
    assert "intento 3 de 3" in result.stdout


def test_a_real_error_still_fails_with_its_cause(tmp_path):
    result = run_script(tmp_path, failures=99)

    assert result.returncode == 1
    error = [line for line in result.stdout.splitlines() if line.startswith("::error")]
    assert len(error) == 1
    assert "Fallo en los 3 intentos" in error[0]
    assert "429 Too Many Requests" in error[0]
    assert (tmp_path / "builds").read_text().strip() == "3"
