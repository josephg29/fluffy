"""Spec §3 acceptance against the BUILT WHEEL in a clean venv (FLUF-5).

Scripted end-to-end: build the wheel, create a fresh venv, install the wheel
into it, then run the four spec flows (tests/e2e/flows.py) with the venv's
python — secret grep, $50-vs-$25 block, delete confirmation loop via
``Guard.challenge_phrase``, permission approve flow — plus the ``fluffy``
console script. Marked ``e2e`` (excluded from the fast suite): run with
``uv run pytest -m e2e``.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import venv
from pathlib import Path

import pytest

import fluffy

pytestmark = pytest.mark.e2e

REPO_ROOT = Path(__file__).resolve().parents[2]
FLOWS = Path(__file__).with_name("flows.py")


def _run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=600,
        **kwargs,  # type: ignore[arg-type]
    )


@pytest.fixture(scope="module")
def wheel(tmp_path_factory: pytest.TempPathFactory) -> Path:
    if shutil.which("uv") is None:
        pytest.skip("uv is required to build the wheel for the e2e run")
    dist = tmp_path_factory.mktemp("dist")
    proc = _run(["uv", "build", "--wheel", "--out-dir", str(dist)], cwd=REPO_ROOT)
    assert proc.returncode == 0, f"uv build failed:\n{proc.stdout}\n{proc.stderr}"
    wheels = list(dist.glob("fluffy-*.whl"))
    assert len(wheels) == 1, f"expected exactly one wheel in a fresh out-dir, got {wheels}"
    return wheels[0]


@pytest.fixture(scope="module")
def clean_venv(wheel: Path, tmp_path_factory: pytest.TempPathFactory) -> Path:
    """A fresh venv (no pip) with only the fluffy wheel installed, via uv."""
    env_dir = tmp_path_factory.mktemp("venv") / "env"
    venv.create(env_dir)
    bin_dir = env_dir / ("Scripts" if sys.platform == "win32" else "bin")
    python = bin_dir / "python"
    proc = _run(["uv", "pip", "install", "--python", str(python), str(wheel)])
    assert proc.returncode == 0, f"uv pip install failed:\n{proc.stdout}\n{proc.stderr}"
    return bin_dir


def test_installed_version_matches_repo(clean_venv: Path) -> None:
    """The wheel installs exactly the version the repo source declares."""
    proc = _run([str(clean_venv / "python"), "-c", "import fluffy; print(fluffy.__version__)"])
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == fluffy.__version__


def test_spec_flows_pass_against_built_wheel(clean_venv: Path, tmp_path: Path) -> None:
    workdir = tmp_path / "flows"
    workdir.mkdir()
    proc = _run(
        [str(clean_venv / "python"), str(FLOWS), str(workdir)],
        cwd=workdir,  # not the repo: fluffy must import from the wheel, not src/
    )
    assert proc.returncode == 0, f"flows failed:\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
    for marker in (
        "PASS secret_grep",
        "PASS spend_block",
        "PASS delete_confirmation",
        "PASS permission_approve",
        "ALL FLOWS PASSED",
    ):
        assert marker in proc.stdout

    # The audit CLI installed by the wheel reads the same state the flows wrote.
    cli = _run(
        [
            str(clean_venv / "fluffy"),
            "audit",
            "tail",
            "-n",
            "50",
            "--db",
            str(workdir / "flow2.db"),
        ]
    )
    assert cli.returncode == 0, cli.stderr
    assert "spend_denied" in cli.stdout and "spend_settled" in cli.stdout

    grep = _run(
        [str(clean_venv / "fluffy"), "audit", "grep", "denied", "--db", str(workdir / "flow2.db")]
    )
    assert grep.returncode == 0 and "spend_denied" in grep.stdout
