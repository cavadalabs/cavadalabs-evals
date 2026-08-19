from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

SCRIPT = Path(__file__).parents[1] / "scripts" / "check_released_assets.py"
GIT = shutil.which("git")


def _git(root: Path, *arguments: str) -> None:
    assert GIT is not None
    subprocess.run([GIT, "-C", str(root), *arguments], check=True, capture_output=True)  # noqa: S603


def _suite(root: Path, directory: str = "demo-v1", version: str = "1.0.0") -> Path:
    suite = root / "suites" / directory
    suite.mkdir(parents=True)
    (suite / "suite.toml").write_text(
        f'''name = "demo"
version = "{version}"
dataset = "dataset.jsonl"
rubric = "rubric.md"
''',
        encoding="utf-8",
    )
    (suite / "dataset.jsonl").write_text('{"id":"one"}\n', encoding="utf-8")
    (suite / "rubric.md").write_text("Original rubric.\n", encoding="utf-8")
    return suite


def _released_repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init", "-b", "main")
    _git(root, "config", "user.email", "test@example.invalid")
    _git(root, "config", "user.name", "Test")
    _suite(root)
    schemas = root / "schemas"
    schemas.mkdir()
    (schemas / "example.schema.json").write_text(
        json.dumps({"$id": "https://schemas.example/evals/example/1.0.0", "type": "object"}, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    plans = root / "performance" / "plans"
    workloads = root / "performance" / "workloads"
    plans.mkdir(parents=True)
    workloads.mkdir()
    (plans / "serving-v1.toml").write_text(
        '''plan_version = "1.0.0"
revision = "1.0.0"
name = "serving"

[workload]
path = "../workloads/workload-v1.jsonl"
''',
        encoding="utf-8",
    )
    (workloads / "workload-v1.jsonl").write_text('{"id":"one"}\n', encoding="utf-8")
    (root / "PROTOCOL.md").write_text("# CavadaLabs Evaluation Protocol 1.0.0\n", encoding="utf-8")
    _git(root, "add", ".")
    _git(root, "commit", "-m", "release")
    _git(root, "tag", "v1.0.0")
    return root


def _check(root: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 -- fixed local interpreter and script.
        [sys.executable, str(SCRIPT), "--root", str(root)],
        check=False,
        capture_output=True,
        text=True,
    )


def test_unchanged_and_version_bumped_suite_pass(tmp_path: Path) -> None:
    root = _released_repo(tmp_path)
    assert _check(root).returncode == 0

    suite = _suite(root, directory="demo-v1.1", version="1.1.0")
    (suite / "rubric.md").write_text("New rubric.\n", encoding="utf-8")
    assert _check(root).returncode == 0


def test_suite_change_and_deletion_without_new_version_fail(tmp_path: Path) -> None:
    root = _released_repo(tmp_path)
    suite = root / "suites" / "demo-v1"
    (suite / "rubric.md").write_text("Mutated rubric.\n", encoding="utf-8")
    changed = _check(root)
    assert changed.returncode == 1
    assert "without a new semantic version" in changed.stdout

    shutil.rmtree(suite)
    removed = _check(root)
    assert removed.returncode == 1
    assert "historical assets must remain byte-identical" in removed.stdout


def test_removed_suite_still_fails_when_a_higher_version_exists(tmp_path: Path) -> None:
    root = _released_repo(tmp_path)
    shutil.rmtree(root / "suites" / "demo-v1")
    _suite(root, directory="demo-v2", version="2.0.0")
    result = _check(root)
    assert result.returncode == 1
    assert "historical assets must remain byte-identical" in result.stdout


def test_duplicate_schema_id_with_different_bytes_fails(tmp_path: Path) -> None:
    root = _released_repo(tmp_path)
    (root / "schemas" / "duplicate.schema.json").write_text(
        json.dumps({"$id": "https://schemas.example/evals/example/1.0.0", "type": "string"}, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    result = _check(root)
    assert result.returncode == 1
    assert "schema $id https://schemas.example/evals/example/1.0.0 has duplicate identity with different bytes" in result.stdout


def test_schema_id_cannot_change_between_release_tags(tmp_path: Path) -> None:
    root = _released_repo(tmp_path)
    (root / "schemas" / "example.schema.json").write_text(
        json.dumps({"$id": "https://schemas.example/evals/example/1.0.0", "type": "string"}, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    _git(root, "add", ".")
    _git(root, "commit", "-m", "mutate schema")
    _git(root, "tag", "v1.1.0")
    result = _check(root)
    assert result.returncode == 1
    assert "across semantic release tags" in result.stdout


def test_performance_plan_closure_requires_revision_bump(tmp_path: Path) -> None:
    root = _released_repo(tmp_path)
    (root / "performance" / "workloads" / "workload-v1.jsonl").write_text('{"id":"changed"}\n', encoding="utf-8")
    changed = _check(root)
    assert changed.returncode == 1
    assert "performance-plan serving@1.0.0 differs" in changed.stdout

    plan = root / "performance" / "plans" / "serving-v1.toml"
    successor = plan.with_name("serving-v1.1.toml")
    successor.write_text(plan.read_text(encoding="utf-8").replace('revision = "1.0.0"', 'revision = "1.1.0"'), encoding="utf-8")
    (root / "performance" / "workloads" / "workload-v1.jsonl").write_text('{"id":"one"}\n', encoding="utf-8")
    (root / "performance" / "workloads" / "workload-v1.1.jsonl").write_text('{"id":"changed"}\n', encoding="utf-8")
    successor.write_text(successor.read_text(encoding="utf-8").replace("workload-v1.jsonl", "workload-v1.1.jsonl"), encoding="utf-8")
    assert _check(root).returncode == 0
