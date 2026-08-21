from __future__ import annotations

import shutil
import subprocess
import tarfile
import tomllib
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
REQUIRED_SDIST_EXCLUSIONS = {
    "/.cache",
    "/.cache/**",
    "/.mypy_cache",
    "/.mypy_cache/**",
    "/.pytest_cache",
    "/.pytest_cache/**",
    "/.ruff_cache",
    "/.ruff_cache/**",
    "/.tox",
    "/.tox/**",
    "/.venv",
    "/.venv/**",
    "/dist",
    "/dist/**",
    "/runs",
    "/runs/**",
    "/tmp",  # noqa: S108 -- literal Hatch exclusion, never used as a writable path.
    "/tmp/**",  # noqa: S108 -- literal Hatch exclusion, never used as a writable path.
    "**/__pycache__",
    "**/__pycache__/**",
    "**/*.pyc",
    "**/*.pyo",
}
FORBIDDEN_ROOT_DIRECTORIES = {"dist", "runs", "tmp"}
FORBIDDEN_CACHE_DIRECTORIES = {
    ".cache",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".venv",
    "__pycache__",
}


def test_sdist_excludes_workspace_artifacts_and_caches(tmp_path: Path) -> None:
    config = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    exclusions = set(config["tool"]["hatch"]["build"]["targets"]["sdist"]["exclude"])
    assert REQUIRED_SDIST_EXCLUSIONS <= exclusions

    uv = shutil.which("uv")
    assert uv is not None, "uv is required to exercise the repository's documented build path"
    subprocess.run(  # noqa: S603 -- resolved uv executable and repository-owned build configuration.
        [uv, "build", "--sdist", "--no-build-logs", "--out-dir", str(tmp_path), str(ROOT)],
        check=True,
        capture_output=True,
        text=True,
    )

    distributions = list(tmp_path.glob("*.tar.gz"))
    assert len(distributions) == 1
    with tarfile.open(distributions[0], mode="r:gz") as archive:
        members = archive.getmembers()

    forbidden: list[str] = []
    for member in members:
        parts = PurePosixPath(member.name).parts
        relative_parts = parts[1:]
        if not relative_parts:
            continue
        if relative_parts[0] in FORBIDDEN_ROOT_DIRECTORIES:
            forbidden.append(member.name)
            continue
        if any(part in FORBIDDEN_CACHE_DIRECTORIES for part in relative_parts):
            forbidden.append(member.name)
            continue
        if PurePosixPath(member.name).suffix in {".pyc", ".pyo"}:
            forbidden.append(member.name)

    assert forbidden == []
