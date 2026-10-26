"""The CI script that builds the Railway image survives a registry that refuses downloads, but not a real error.

A fake `docker` on the PATH plays the registries: public.ecr.aws answers "429 Data limit exceeded" (what really
happened on GitHub) and Google's mirror works, or every registry fails.
"""
import os
import re
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / ".github" / "scripts" / "construir-imagen.sh"
ECR_429 = ("ERROR: failed to copy: httpReadSeeker: failed open: unexpected status code "
           "https://public.ecr.aws/v2/docker/library/python/manifests/sha256:d98c: 429 Too Many Requests - "
           "Server message: toomanyrequests: Data limit exceeded")

linux_only = pytest.mark.skipif(shutil.which("bash") is None or os.name == "nt", reason="the script runs on Linux CI")


def run_script(tmp_path: Path, failing: str) -> tuple[subprocess.CompletedProcess, list[str]]:
    """Runs the script; every build whose arguments match the regex `failing` fails like the ECR limit."""
    (tmp_path / "Dockerfile").write_text((ROOT / "Dockerfile").read_text())
    calls = tmp_path / "calls"
    fake = tmp_path / "bin" / "docker"
    fake.parent.mkdir()
    fake.write_text(
        "#!/usr/bin/env bash\n"
        f'echo "$*" >> {calls}\n'
        f'if [[ "$*" =~ {failing} ]]; then echo \'#2 {ECR_429}\'; exit 1; fi\n'
        "echo 'naming to docker.io/library/wifisense-ai done'\n")
    fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
    env = {**os.environ, "PATH": f"{fake.parent}{os.pathsep}{os.environ['PATH']}", "WAIT_SECONDS": "0"}
    result = subprocess.run(["bash", str(SCRIPT)], cwd=tmp_path, env=env, capture_output=True, text=True, timeout=30)
    return result, calls.read_text().splitlines()


@linux_only
def test_the_check_takes_the_official_image_from_the_mirror_first(tmp_path):
    result, calls = run_script(tmp_path, failing="public\\.ecr\\.aws")

    assert result.returncode == 0
    assert calls == ["build --build-arg PYTHON_IMAGE=mirror.gcr.io/library/python:3.13-slim -t wifisense-ai ."]


@linux_only
def test_it_falls_back_to_public_ecr_and_reports_each_refusal(tmp_path):
    result, calls = run_script(tmp_path, failing="mirror\\.gcr\\.io")

    assert result.returncode == 0
    assert calls[-1].endswith("PYTHON_IMAGE=public.ecr.aws/docker/library/python:3.13-slim -t wifisense-ai .")
    assert [line for line in result.stdout.splitlines() if line.startswith("::warning")] != []


@linux_only
def test_a_real_error_still_fails_with_its_cause(tmp_path):
    result, calls = run_script(tmp_path, failing=".")

    assert result.returncode == 1
    assert len(calls) == 6  # 3 rounds x 2 registries
    error = [line for line in result.stdout.splitlines() if line.startswith("::error")]
    assert len(error) == 1 and "Data limit exceeded" in error[0]


def test_railway_and_the_tests_use_the_same_python():
    image = re.search(r"^ARG PYTHON_IMAGE=(\S+)$", (ROOT / "Dockerfile").read_text(), re.M).group(1)
    workflow = (ROOT / ".github" / "workflows" / "servicio-ia.yml").read_text()

    assert image.startswith("public.ecr.aws/docker/library/python:")
    version = re.search(r"python:(\d+\.\d+)-slim$", image).group(1)
    assert f'python-version: "{version}"' in workflow
    assert re.search(r"^FROM \$\{PYTHON_IMAGE\}$", (ROOT / "Dockerfile").read_text(), re.M)
