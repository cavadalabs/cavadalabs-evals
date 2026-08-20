from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from cavada_eval.protocol import ProtocolError
from cavada_eval.source_proof import (
    MAX_PACK_BYTES,
    _object_format,
    _pack_objects,
    _proof_layout,
    build_source_commit_proof,
    verify_source_commit_proof,
)

GIT = shutil.which("git")
pytestmark = pytest.mark.skipif(GIT is None, reason="Git is required")


def _git(repo: Path, *arguments: str, input_bytes: bytes | None = None) -> bytes:
    assert GIT is not None
    completed = subprocess.run(  # noqa: S603 -- resolved Git executable and fixed test arguments.
        [GIT, "-C", str(repo), *arguments],
        input=input_bytes,
        capture_output=True,
        check=True,
        timeout=10,
    )
    return completed.stdout


def _repository(tmp_path: Path, algorithm: str) -> tuple[Path, str, dict[str, bytes], str]:
    root = tmp_path / f"repository-{algorithm}"
    assert GIT is not None
    subprocess.run(  # noqa: S603 -- resolved Git executable and fixed test arguments.
        [GIT, "init", "--quiet", f"--object-format={algorithm}", str(root)],
        check=True,
        capture_output=True,
        timeout=10,
    )
    _git(root, "config", "user.name", "Source Proof Test")
    _git(root, "config", "user.email", "source-proof@example.invalid")
    package = root / "src" / "cavada_eval"
    (package / "nested").mkdir(parents=True)
    implementation = {
        "__init__.py": b'VERSION = "test"\n',
        "nested/module.py": b"def answer() -> int:\n    return 42\n",
    }
    for relative, raw in implementation.items():
        path = package / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
    (package / "ignored.json").write_text('{"not": "in the pack"}\n', encoding="utf-8")
    (root / "pyproject.toml").write_text('[project]\nname = "source-proof-test"\n', encoding="utf-8")
    lock = b"version = 1\n"
    (root / "uv.lock").write_bytes(lock)
    (root / "README.md").write_text("not included\n", encoding="utf-8")
    _git(root, "add", ".")
    _git(root, "commit", "--quiet", "-m", "source proof fixture")
    commit = _git(root, "rev-parse", "HEAD").decode("ascii").strip()
    return root, commit, implementation, hashlib.sha256(lock).hexdigest()


@pytest.mark.parametrize("algorithm", ["sha1", "sha256"])
def test_source_commit_proof_round_trips_exact_sha_formats(tmp_path: Path, algorithm: str) -> None:
    root, commit, implementation, lock_sha256 = _repository(tmp_path, algorithm)

    pack = build_source_commit_proof(root, commit)

    assert pack.startswith(b"PACK")
    assert len(pack) <= MAX_PACK_BYTES
    assert verify_source_commit_proof(pack, commit, implementation, lock_sha256) == []


def test_source_commit_proof_rejects_tamper_wrong_bindings_and_extra_object(tmp_path: Path) -> None:
    root, commit, implementation, lock_sha256 = _repository(tmp_path, "sha1")
    pack = build_source_commit_proof(root, commit)

    tampered = bytearray(pack)
    tampered[-1] ^= 1
    assert verify_source_commit_proof(bytes(tampered), commit, implementation, lock_sha256)
    assert verify_source_commit_proof(pack, "0" * 40, implementation, lock_sha256) == [
        "source proof does not contain the declared commit"
    ]
    changed = {**implementation, "nested/module.py": b"def answer() -> int:\n    return 0\n"}
    assert any(
        "Python blob differs" in failure
        for failure in verify_source_commit_proof(pack, commit, changed, lock_sha256)
    )
    assert verify_source_commit_proof(pack, commit, implementation, "0" * 64) == [
        "source proof uv.lock digest mismatch"
    ]

    extra = _git(root, "hash-object", "-w", "--stdin", input_bytes=b"unrelated extra object\n").decode("ascii").strip()
    layout = _proof_layout(root, commit, _object_format(root))
    extra_pack = _pack_objects(root, frozenset({*layout.objects, extra}))
    assert any(
        "object set is not exact" in failure
        for failure in verify_source_commit_proof(extra_pack, commit, implementation, lock_sha256)
    )


@pytest.mark.parametrize(
    ("mode", "path", "message"),
    [
        ("120000", "src/cavada_eval/link.py", "symlink"),
        ("160000", "src/cavada_eval/vendor", "submodule"),
    ],
)
def test_source_commit_proof_rejects_symlink_and_submodule_modes(
    tmp_path: Path,
    mode: str,
    path: str,
    message: str,
) -> None:
    root, commit, _, _ = _repository(tmp_path, "sha1")
    if mode == "120000":
        oid = _git(root, "hash-object", "-w", "--stdin", input_bytes=b"target.py").decode("ascii").strip()
    else:
        oid = commit
    _git(root, "update-index", "--add", "--cacheinfo", f"{mode},{oid},{path}")
    _git(root, "commit", "--quiet", "-m", f"add {message}")
    changed_commit = _git(root, "rev-parse", "HEAD").decode("ascii").strip()

    with pytest.raises(ProtocolError, match=message):
        build_source_commit_proof(root, changed_commit)


@pytest.mark.parametrize(
    ("paths", "message"),
    [
        (("src/cavada_eval/Foo.py", "src/cavada_eval/foo.py"), "case-colliding"),
        (("src/cavada_eval/cafe\N{COMBINING ACUTE ACCENT}.py",), "non-NFC"),
    ],
)
def test_source_commit_proof_rejects_ambiguous_tree_paths(
    tmp_path: Path,
    paths: tuple[str, ...],
    message: str,
) -> None:
    root, _, _, _ = _repository(tmp_path, "sha1")
    _git(root, "config", "core.precomposeunicode", "false")
    oid = _git(root, "hash-object", "-w", "--stdin", input_bytes=b"VALUE = 1\n").decode("ascii").strip()
    for path in paths:
        _git(root, "update-index", "--add", "--cacheinfo", f"100644,{oid},{path}")
    _git(root, "commit", "--quiet", "-m", "add ambiguous path")
    commit = _git(root, "rev-parse", "HEAD").decode("ascii").strip()

    with pytest.raises(ProtocolError, match=message):
        build_source_commit_proof(root, commit)


def test_source_commit_proof_path_input_must_be_unique_regular_file(tmp_path: Path) -> None:
    root, commit, implementation, lock_sha256 = _repository(tmp_path, "sha1")
    pack_path = tmp_path / "proof.pack"
    pack_path.write_bytes(build_source_commit_proof(root, commit))
    link = tmp_path / "proof-link.pack"
    os.symlink(pack_path.name, link)

    assert verify_source_commit_proof(pack_path, commit, implementation, lock_sha256) == []
    assert verify_source_commit_proof(link, commit, implementation, lock_sha256) == [
        "source proof pack path is not a unique regular file"
    ]
