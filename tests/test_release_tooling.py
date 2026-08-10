from __future__ import annotations

import json
import runpy
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CHECK_RELEASE = ROOT / "scripts/check_release.py"
GENERATE_SBOM = ROOT / "scripts/generate_sbom.py"
GENERATE_PROVENANCE = ROOT / "scripts/generate_provenance.py"
CHECK_DISTRIBUTION = ROOT / "scripts/check_distribution.py"


def _run(script: Path, *arguments: str, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 -- resolved repository script and fixed interpreter.
        [sys.executable, str(script), *arguments], cwd=cwd, check=False, capture_output=True, text=True
    )


def _git(cwd: Path, *arguments: str) -> None:
    executable = shutil.which("git")
    assert executable is not None
    subprocess.run([executable, *arguments], cwd=cwd, check=True)  # noqa: S603 -- resolved executable and test arguments.


def _release_tree(root: Path) -> None:
    (root / "src/cavada_eval").mkdir(parents=True)
    (root / "docs").mkdir()
    (root / "pyproject.toml").write_text('[project]\nversion = "1.2.3"\n', encoding="utf-8")
    (root / "src/cavada_eval/__init__.py").write_text('__version__ = "1.2.3"\n', encoding="utf-8")
    (root / "src/cavada_eval/cli.py").write_text(
        'root.add_argument("--version", action="version", version="cavadalabs-evals 1.2.3")\n', encoding="utf-8"
    )
    (root / "CITATION.cff").write_text("version: 1.2.3\ndate-released: 2026-08-07\n", encoding="utf-8")
    (root / "CHANGELOG.md").write_text("# Changelog\n\n## Unreleased\n\n## 1.2.3 - 2026-08-07\n\n- Release.\n", encoding="utf-8")
    (root / "docs/PUBLICATION_INVENTORY.md").write_text(
        """# Publication inventory

| Material | Current declaration | Decision | Condition |
| --- | --- | --- | --- |
| `suites/cavada-core-assistant-text-v1` | Rights approved | ready | Evidence retained. |
| `suites/memo4345-v1` | Rights approved | ready | Evidence retained. |
| `suites/security-privacy-smoke-v1` | Rights approved | ready | Evidence retained. |
| `suites/template` | Rights approved | ready | Evidence retained. |
| Repository organization approval | Retained approval | ready | Evidence retained. |
| Historical Git author email disclosure | Authorized disclosure | ready | Evidence retained. |
""",
        encoding="utf-8",
    )


def test_release_gate_is_exact_and_fail_closed(tmp_path: Path) -> None:
    _release_tree(tmp_path)
    assert _run(CHECK_RELEASE, "--root", str(tmp_path), "--release", "--tag", "v1.2.3").returncode == 0

    inventory = tmp_path / "docs/PUBLICATION_INVENTORY.md"
    inventory.write_text(inventory.read_text(encoding="utf-8").replace("| ready |", "| approved |", 1), encoding="utf-8")
    result = _run(CHECK_RELEASE, "--root", str(tmp_path), "--release", "--tag", "v1.2.3")
    assert result.returncode == 1 and "unknown decision" in result.stdout


def test_release_gate_rejects_blockers_versions_and_unreleased_work(tmp_path: Path) -> None:
    _release_tree(tmp_path)
    path = tmp_path / "docs/PUBLICATION_INVENTORY.md"
    path.write_text(path.read_text(encoding="utf-8").replace("| ready |", "| blocked |", 1), encoding="utf-8")
    (tmp_path / "CHANGELOG.md").write_text(
        "# Changelog\n\n## Unreleased\n\n- Pending.\n\n## 1.2.3 - 2026-08-07\n\n- Release.\n", encoding="utf-8"
    )
    (tmp_path / "CITATION.cff").write_text("version: 1.2.2\ndate-released: 2026-08-07\n", encoding="utf-8")
    result = _run(CHECK_RELEASE, "--root", str(tmp_path), "--release", "--tag", "v1.2.2")
    assert result.returncode == 1
    assert "version mismatch" in result.stdout
    assert "Unreleased must be empty" in result.stdout
    assert "release tag must be v1.2.3" in result.stdout
    assert "publication inventory remains blocked" in result.stdout

    citation_tree = tmp_path / "citation"
    _release_tree(citation_tree)
    (citation_tree / "CITATION.cff").write_text("version: 1.2.3\ndate-released: 2026-08-06\n", encoding="utf-8")
    result = _run(CHECK_RELEASE, "--root", str(citation_tree), "--release", "--tag", "v1.2.3")
    assert result.returncode == 1 and "date-released" in result.stdout

    (citation_tree / "CITATION.cff").write_text("version: 1.2.3\ndate-released: 2026-99-99\n", encoding="utf-8")
    (citation_tree / "CHANGELOG.md").write_text(
        "# Changelog\n\n## Unreleased\n\n## 1.2.3 - 2026-99-99\n\n- Release.\n", encoding="utf-8"
    )
    result = _run(CHECK_RELEASE, "--root", str(citation_tree), "--release", "--tag", "v1.2.3")
    assert result.returncode == 1 and "real calendar date" in result.stdout

    _release_tree(tmp_path / "excluded")
    inventory = tmp_path / "excluded/docs/PUBLICATION_INVENTORY.md"
    inventory.write_text(inventory.read_text(encoding="utf-8").replace("| ready |", "| excluded |", 1), encoding="utf-8")
    result = _run(CHECK_RELEASE, "--root", str(tmp_path / "excluded"), "--release", "--tag", "v1.2.3")
    assert result.returncode == 1 and "publication inventory remains blocked" in result.stdout


def test_sbom_uses_wheel_metadata_not_the_environment(tmp_path: Path) -> None:
    wheel = tmp_path / "example-1.2.3-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr(
            "example-1.2.3.dist-info/METADATA",
            """Metadata-Version: 2.4
Name: example
Version: 1.2.3
Provides-Extra: deepeval
Requires-Dist: deepeval<4,>=3; extra == 'deepeval'

""",
        )
    lock = tmp_path / "uv.lock"
    lock.write_text("version = 1\n", encoding="utf-8")
    output = tmp_path / "sbom.json"
    result = _run(GENERATE_SBOM, "--wheel", str(wheel), "--lock", str(lock), "--output", str(output))
    assert result.returncode == 0, result.stderr
    document = json.loads(output.read_text(encoding="utf-8"))
    assert document["metadata"]["component"]["version"] == "1.2.3"
    assert [(item["name"], item["scope"]) for item in document["components"]] == [("deepeval", "optional")]
    assert all(item["name"] != "pytest" for item in document["components"])


def test_provenance_records_uv_and_build_backend(tmp_path: Path) -> None:
    (tmp_path / "dist").mkdir()
    (tmp_path / "dist/example-1.2.3-py3-none-any.whl").write_bytes(b"wheel")
    (tmp_path / "uv.lock").write_text("version = 1\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(
        '''[project]
version = "1.2.3"
[build-system]
requires = ["hatchling==1.31.0"]
build-backend = "hatchling.build"
''',
        encoding="utf-8",
    )
    result = _run(GENERATE_PROVENANCE, cwd=tmp_path)
    assert result.returncode == 0, result.stderr
    document = json.loads((tmp_path / "dist/build-provenance.json").read_text(encoding="utf-8"))
    parameters = document["predicate"]["buildDefinition"]["externalParameters"]
    assert parameters["uv"].startswith("uv ")
    assert parameters["buildBackend"] == "hatchling.build"
    assert parameters["buildRequirements"] == ["hatchling==1.31.0"]
    assert parameters["sourceCommit"] is None
    assert parameters["sourceTreeState"] == "unavailable"


def test_release_provenance_requires_a_clean_identified_tree(tmp_path: Path) -> None:
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "config", "user.name", "Test")
    _git(tmp_path, "config", "user.email", "test@example.invalid")
    (tmp_path / "uv.lock").write_text("version = 1\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nversion = "1.2.3"\n[build-system]\nrequires = ["hatchling==1.31.0"]\nbuild-backend = "hatchling.build"\n',
        encoding="utf-8",
    )
    _git(tmp_path, "add", "uv.lock", "pyproject.toml")
    _git(tmp_path, "commit", "-qm", "fixture")
    (tmp_path / "dist").mkdir()
    (tmp_path / "dist/example-1.2.3-py3-none-any.whl").write_bytes(b"wheel")

    assert _run(GENERATE_PROVENANCE, "--require-clean", cwd=tmp_path).returncode == 0
    (tmp_path / "uv.lock").write_text("version = 2\n", encoding="utf-8")
    result = _run(GENERATE_PROVENANCE, "--require-clean", cwd=tmp_path)
    assert result.returncode == 1 and "clean, identified Git source tree" in result.stderr

    unborn = tmp_path / "unborn"
    unborn.mkdir()
    _git(unborn, "init", "-q")
    (unborn / ".gitignore").write_text("*\n", encoding="utf-8")
    (unborn / "uv.lock").write_text("version = 1\n", encoding="utf-8")
    (unborn / "pyproject.toml").write_text(
        '[project]\nversion = "1.2.3"\n[build-system]\nrequires = []\nbuild-backend = "example"\n', encoding="utf-8"
    )
    (unborn / "dist").mkdir()
    (unborn / "dist/example-1.2.3-py3-none-any.whl").write_bytes(b"wheel")
    result = _run(GENERATE_PROVENANCE, "--require-clean", cwd=unborn)
    assert result.returncode == 1 and "clean, identified Git source tree" in result.stderr


def test_registry_history_checks_use_trusted_base_revisions() -> None:
    ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    release = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
    assert "fetch-depth: 0" in ci and "github.event.pull_request.base.sha" in ci and "github.event.before" in ci
    assert 'git cat-file -e "$REGISTRY_BASE_SHA:results/registry.json"' in ci
    assert ci.count("--initial-empty") == 2
    assert "fetch-depth: 0" in release and "git describe --tags" in release
    assert 'git cat-file -e "$previous_tag:results/registry.json"' in release
    assert "--initial-empty" in release
    assert "generate_provenance.py --require-clean" in release
    assert "HEAD^:results/registry.json" not in ci + release


def test_distribution_inventory_requires_versioned_open_loop_contracts() -> None:
    inventory = runpy.run_path(str(CHECK_DISTRIBUTION))
    wheel = inventory["REQUIRED_WHEEL"]
    sdist = inventory["REQUIRED_SDIST_SUFFIXES"]
    required = {
        "PERFORMANCE_PROTOCOL_V1_1.md",
        "PERFORMANCE_PROTOCOL_V2.md",
        "performance/VERSION_PROVENANCE.md",
        "schemas/performance-plan-1.1.0.schema.json",
        "schemas/performance-manifest-1.1.0.schema.json",
        "schemas/performance-plan-2.0.0.schema.json",
        "schemas/performance-manifest-2.0.0.schema.json",
        "schemas/performance-publication-2.0.0.schema.json",
        "schemas/results-registry-2.0.0.schema.json",
    }
    assert {f"cavada_eval/_resources/{path}" for path in required} <= wheel
    assert {f"/{path}" for path in required} <= sdist
