from __future__ import annotations

import hashlib
import io
import json
import os
import re
import stat
import subprocess
import tarfile
import tempfile
import unicodedata
from collections.abc import Callable, Mapping
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

from .artifacts import _read_regular
from .protocol import ProtocolError, _strict_json_loads

REGISTRY_VERSION = "2.0.0"
ARCHIVE_VERSION = "1.0.0"
ARCHIVE_FORMAT = "cavada-public-evidence-tar"
ARCHIVE_MANIFEST = "evidence-archive.json"
MAX_ARCHIVE_BYTES = 2 * 1024 * 1024 * 1024
MAX_ARCHIVE_FILES = 100_000
_SHA256 = re.compile(r"[a-f0-9]{64}")
_COMMIT = re.compile(r"[a-f0-9]{40}")
_REQUIRED_REFERENCES = {"run_bundle", "engagement", "release_approval", "verification_result"}
_REFERENCE_FIELDS = {"relative_path", "sha256", "media_type", "artifact_type", "schema_version"}
_ARCHIVE_FIELDS = {"archive_version", "artifact_type", "files", *_REQUIRED_REFERENCES}
_REGISTRY_FIELDS = {"registry_version", "records", "events"}
_RECORD_FIELDS = {
    "record_version",
    "record_id",
    "record_type",
    "archive",
    "artifact_type",
    "suite",
    "system",
    "protocol_version",
    "assurance_level",
    "verification_result_sha256",
    "release_approval_sha256",
    "published_at",
    "expires_at",
    "claim_scope",
    "rankable",
    "model_claim_allowed",
    "benchmark_claim_allowed",
    "reproduction_status",
    "attestation",
}
_ARCHIVE_RECORD_FIELDS = {"relative_path", "sha256", "format", "format_version"}
_SUITE_FIELDS = {"name", "version"}
_SYSTEM_FIELDS = {"identity", "revision"}
_ATTESTATION_FIELDS = {
    "attestation_version",
    "provider",
    "subject_name",
    "subject_sha256",
    "repository",
    "signer_workflow",
    "source_commit",
    "source_ref",
    "protocol_version",
    "schema_version",
}
_EVENT_FIELDS = {"event_version", "event_id", "record_id", "event_type", "occurred_at", "previous_event_id", "related_record_id", "reason"}
_TERMINAL_EVENTS = {"withdrawn", "corrected", "superseded", "expired"}

BehaviorVerifier = Callable[..., dict[str, Any]]
ReleaseVerifier = Callable[..., dict[str, Any]]
AttestationVerifier = Callable[[Path, dict[str, Any]], list[str]]


def _canonical_json(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False) + "\n").encode()


def _exact(value: Any, fields: set[str], label: str) -> list[str]:
    if not isinstance(value, dict):
        return [f"{label} must be an object"]
    missing = sorted(fields - set(value))
    unknown = sorted(set(value) - fields)
    return [f"{label} fields are not exact; missing={missing}; unknown={unknown}"] if missing or unknown else []


def _relative(value: Any, label: str, *, directory: bool = False) -> tuple[str | None, list[str]]:
    if not isinstance(value, str) or not value:
        return None, [f"{label} must be a non-empty relative path"]
    posix = PurePosixPath(value)
    windows = PureWindowsPath(value)
    invalid = (
        value != unicodedata.normalize("NFC", value)
        or "\\" in value
        or value.startswith("/")
        or value.endswith("/")
        or "//" in value
        or posix.is_absolute()
        or windows.is_absolute()
        or bool(windows.drive)
        or any(part in {"", ".", ".."} for part in posix.parts)
        or posix.as_posix() != value
    )
    if invalid or (not directory and value == "."):
        return None, [f"{label} is unsafe or non-canonical: {value}"]
    return value, []


def _timestamp(value: Any, label: str) -> tuple[datetime | None, list[str]]:
    if not isinstance(value, str) or not value.endswith("Z"):
        return None, [f"{label} must be a canonical UTC ISO 8601 timestamp ending in Z"]
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        return None, [f"{label} must be a valid ISO 8601 timestamp"]
    if parsed.tzinfo != timezone.utc or parsed.isoformat().replace("+00:00", "Z") != value:
        return None, [f"{label} must be a canonical UTC ISO 8601 timestamp"]
    return parsed, []


def _reference(value: Any, label: str) -> tuple[dict[str, Any] | None, list[str]]:
    errors = _exact(value, _REFERENCE_FIELDS, label)
    if errors or not isinstance(value, dict):
        return None, errors
    relative, path_errors = _relative(value.get("relative_path"), f"{label}.relative_path")
    errors.extend(path_errors)
    if not isinstance(value.get("sha256"), str) or _SHA256.fullmatch(value["sha256"]) is None:
        errors.append(f"{label}.sha256 must be a lowercase SHA-256")
    for field in ("media_type", "artifact_type"):
        if not isinstance(value.get(field), str) or not value[field].strip():
            errors.append(f"{label}.{field} must be non-empty")
    if value.get("schema_version") is not None and (not isinstance(value["schema_version"], str) or not value["schema_version"].strip()):
        errors.append(f"{label}.schema_version must be null or non-empty")
    return ({**value, "relative_path": relative} if relative is not None else None), errors


def _media_type(path: str) -> str:
    suffix = Path(path).suffix.casefold()
    return {
        ".json": "application/json",
        ".jsonl": "application/x-ndjson",
        ".toml": "application/toml",
        ".md": "text/markdown",
        ".html": "text/html",
        ".txt": "text/plain",
    }.get(suffix, "application/octet-stream")


def _tar_bytes(files: Mapping[str, bytes]) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name in sorted(files):
            raw = files[name]
            member = tarfile.TarInfo(name)
            member.size = len(raw)
            member.mode = 0o644
            member.uid = member.gid = 0
            member.uname = member.gname = ""
            member.mtime = 0
            archive.addfile(member, io.BytesIO(raw))
    return output.getvalue()


def _source_files(root: Path) -> dict[str, bytes]:
    before = root.lstat()
    if root.is_symlink() or not stat.S_ISDIR(before.st_mode):
        raise ProtocolError("public evidence source must be a non-symlink directory")
    files: dict[str, bytes] = {}
    folded: set[str] = set()
    total = 0
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        _, errors = _relative(relative, "public evidence source path", directory=path.is_dir())
        if errors:
            raise ProtocolError(errors[0])
        if path.is_symlink():
            raise ProtocolError(f"public evidence source contains a symlink: {relative}")
        value = path.lstat()
        if path.is_dir():
            if not stat.S_ISDIR(value.st_mode):
                raise ProtocolError(f"public evidence source contains an unsafe directory: {relative}")
            continue
        if not stat.S_ISREG(value.st_mode) or value.st_nlink != 1:
            raise ProtocolError(f"public evidence source contains a non-regular or hard-linked file: {relative}")
        collision = unicodedata.normalize("NFC", relative).casefold()
        if collision in folded:
            raise ProtocolError(f"public evidence source contains a case-colliding path: {relative}")
        folded.add(collision)
        if relative == ARCHIVE_MANIFEST:
            raise ProtocolError(f"{ARCHIVE_MANIFEST} is generated and must not exist in the source")
        try:
            raw = _read_regular(root, Path(relative))
        except OSError as exc:
            raise ProtocolError(f"public evidence source changed while it was read: {relative}") from exc
        total += len(raw)
        if len(files) >= MAX_ARCHIVE_FILES or total > MAX_ARCHIVE_BYTES:
            raise ProtocolError("public evidence source exceeds the bounded archive limits")
        files[relative] = raw
    if root.lstat() != before:
        raise ProtocolError("public evidence source changed while it was read")
    return files


def build_public_evidence_archive(source_root: Path, archive_directory: Path, *, references: Mapping[str, str]) -> Path:
    """Build a byte-deterministic public evidence tar from an already prepared closed directory."""
    if set(references) != _REQUIRED_REFERENCES:
        raise ProtocolError(f"archive references must be exactly {sorted(_REQUIRED_REFERENCES)}")
    files = _source_files(source_root)
    reference_meta = {
        "run_bundle": ("behavior-run-bundle", "1.0.0"),
        "engagement": ("engagement-governance", "1.1.0"),
        "release_approval": ("public-release-approval", "1.0.0"),
        "verification_result": ("behavior-verification-result", "2.0.0"),
    }
    by_path = {path: name for name, path in references.items()}
    declared: list[dict[str, Any]] = []
    for path, raw in sorted(files.items()):
        name = by_path.get(path)
        artifact_type, schema_version = reference_meta[name] if name is not None else ("supporting-evidence", None)
        declared.append(
            {
                "relative_path": path,
                "sha256": hashlib.sha256(raw).hexdigest(),
                "media_type": _media_type(path),
                "artifact_type": artifact_type,
                "schema_version": schema_version,
            }
        )
    declared_by_path = {item["relative_path"]: item for item in declared}
    missing = sorted(set(references.values()) - set(declared_by_path))
    if missing or len(set(references.values())) != len(references):
        raise ProtocolError(f"archive semantic references must be distinct declared files; missing={missing}")
    manifest = {
        "archive_version": ARCHIVE_VERSION,
        "artifact_type": "behavior-run",
        "files": declared,
        **{name: declared_by_path[path] for name, path in references.items()},
    }
    archive_files = {ARCHIVE_MANIFEST: _canonical_json(manifest), **files}
    try:
        raw_archive = _tar_bytes(archive_files)
    except (OSError, UnicodeError, ValueError) as exc:
        raise ProtocolError("public evidence paths cannot be represented in the canonical tar format") from exc
    digest = hashlib.sha256(raw_archive).hexdigest()
    output = archive_directory / f"{digest}.tar"
    archive_directory.mkdir(parents=True, exist_ok=True)
    directory_state = archive_directory.lstat()
    if archive_directory.is_symlink() or not stat.S_ISDIR(directory_state.st_mode):
        raise ProtocolError("public evidence archive destination must be a non-symlink directory")
    try:
        output.lstat()
    except FileNotFoundError:
        pass
    else:
        raise ProtocolError("public evidence archives are immutable and cannot be overwritten")
    temporary = output.with_name(f".{output.name}.{os.getpid()}.tmp")
    try:
        with temporary.open("xb") as handle:
            handle.write(raw_archive)
            handle.flush()
            os.fsync(handle.fileno())
        current_directory = archive_directory.lstat()
        if (current_directory.st_dev, current_directory.st_ino) != (directory_state.st_dev, directory_state.st_ino):
            raise ProtocolError("public evidence archive destination changed while it was written")
        os.replace(temporary, output)
    finally:
        temporary.unlink(missing_ok=True)
    return output


def _read_archive(path: Path) -> tuple[str, dict[str, Any], dict[str, bytes]]:
    try:
        before = path.lstat()
    except OSError as exc:
        raise ProtocolError("public evidence archive is missing") from exc
    if path.is_symlink() or not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > MAX_ARCHIVE_BYTES:
        raise ProtocolError("public evidence archive must be a bounded, non-symlink, non-hard-linked regular file")
    try:
        raw = _read_regular(path.parent, Path(path.name))
    except OSError as exc:
        raise ProtocolError("public evidence archive changed while it was read") from exc
    if path.lstat() != before:
        raise ProtocolError("public evidence archive changed while it was read")
    digest = hashlib.sha256(raw).hexdigest()
    files: dict[str, bytes] = {}
    folded: set[str] = set()
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
            members = archive.getmembers()
            if len(members) > MAX_ARCHIVE_FILES + 1:
                raise ProtocolError("public evidence archive has too many files")
            for member in members:
                name, errors = _relative(member.name, "public evidence archive member")
                if errors or name is None:
                    raise ProtocolError(errors[0])
                collision = unicodedata.normalize("NFC", name).casefold()
                if name in files or collision in folded:
                    raise ProtocolError(f"public evidence archive has a duplicate or case-colliding path: {name}")
                folded.add(collision)
                if not member.isreg() or member.linkname:
                    raise ProtocolError(f"public evidence archive contains a link or non-regular member: {name}")
                if (
                    member.mode != 0o644
                    or member.uid != 0
                    or member.gid != 0
                    or member.uname
                    or member.gname
                    or member.mtime != 0
                    or member.pax_headers
                ):
                    raise ProtocolError(f"public evidence archive member metadata is not canonical: {name}")
                handle = archive.extractfile(member)
                if handle is None:
                    raise ProtocolError(f"public evidence archive member cannot be read: {name}")
                content = handle.read(MAX_ARCHIVE_BYTES + 1)
                if len(content) != member.size or len(content) > MAX_ARCHIVE_BYTES:
                    raise ProtocolError(f"public evidence archive member is truncated or oversized: {name}")
                files[name] = content
    except (tarfile.TarError, EOFError, OSError) as exc:
        raise ProtocolError("public evidence archive is not a readable uncompressed tar") from exc
    try:
        canonical = _tar_bytes(files)
    except (OSError, UnicodeError, ValueError) as exc:
        raise ProtocolError("public evidence archive cannot be reconstructed canonically") from exc
    if raw != canonical:
        raise ProtocolError("public evidence archive is not in canonical deterministic tar form")
    manifest_raw = files.get(ARCHIVE_MANIFEST)
    try:
        manifest = _strict_json_loads(manifest_raw) if manifest_raw is not None else None
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise ProtocolError("public evidence archive manifest is not strict JSON") from exc
    if not isinstance(manifest, dict):
        raise ProtocolError("public evidence archive manifest is missing or not an object")
    if manifest_raw != _canonical_json(manifest):
        raise ProtocolError("public evidence archive manifest is not in canonical byte form")
    return digest, manifest, files


def _archive_manifest_errors(manifest: dict[str, Any], files: Mapping[str, bytes]) -> list[str]:
    errors = _exact(manifest, _ARCHIVE_FIELDS, "public evidence archive manifest")
    if manifest.get("archive_version") != ARCHIVE_VERSION:
        errors.append(f"archive_version must be {ARCHIVE_VERSION}")
    if manifest.get("artifact_type") != "behavior-run":
        errors.append("archive artifact_type must be behavior-run")
    listed = manifest.get("files")
    if not isinstance(listed, list) or not listed:
        return [*errors, "archive files must be a non-empty array"]
    declared: dict[str, dict[str, Any]] = {}
    folded: set[str] = set()
    for index, value in enumerate(listed):
        reference, item_errors = _reference(value, f"archive files[{index}]")
        errors.extend(item_errors)
        if reference is None:
            continue
        relative = str(reference["relative_path"])
        collision = unicodedata.normalize("NFC", relative).casefold()
        if relative in declared or collision in folded:
            errors.append(f"archive files has a duplicate or case-colliding path: {relative}")
        declared[relative] = reference
        folded.add(collision)
    actual = set(files) - {ARCHIVE_MANIFEST}
    if set(declared) != actual:
        errors.append(f"archive closed file set differs; missing={sorted(set(declared) - actual)}; extra={sorted(actual - set(declared))}")
    for relative, reference in declared.items():
        raw = files.get(relative)
        if raw is not None and hashlib.sha256(raw).hexdigest() != reference.get("sha256"):
            errors.append(f"archive file hash mismatch: {relative}")
    semantic_digests: set[str] = set()
    semantic_paths: set[str] = set()
    for name in sorted(_REQUIRED_REFERENCES):
        reference, item_errors = _reference(manifest.get(name), f"archive {name}")
        errors.extend(item_errors)
        if reference is None:
            continue
        relative = str(reference["relative_path"])
        if declared.get(relative) != reference:
            errors.append(f"archive {name} is not exactly one of the declared files")
        digest = str(reference.get("sha256"))
        if relative in semantic_paths or digest in semantic_digests:
            errors.append("archive semantic references must have distinct paths and digests")
        semantic_paths.add(relative)
        semantic_digests.add(digest)
    return errors


def _materialize(files: Mapping[str, bytes], root: Path) -> None:
    for relative, raw in files.items():
        if relative == ARCHIVE_MANIFEST:
            continue
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        path.chmod(0o600)


def verify_public_evidence_archive(
    archive_path: Path,
    *,
    expected_digest: str | None = None,
    now: datetime | None = None,
    behavior_verifier: BehaviorVerifier | None = None,
    release_verifier: ReleaseVerifier | None = None,
) -> dict[str, Any]:
    """Reconstruct one public evidence archive from bytes; no attestation network call occurs here."""
    failures: list[str] = []
    try:
        digest, manifest, files = _read_archive(archive_path)
    except ProtocolError as exc:
        return {"valid": False, "archive_sha256": None, "failures": [str(exc)]}
    if expected_digest is not None and digest != expected_digest:
        failures.append("public evidence archive digest does not match the registry")
    failures.extend(_archive_manifest_errors(manifest, files))
    result: dict[str, Any] = {
        "valid": False,
        "archive_sha256": digest,
        "manifest": manifest,
        "failures": failures,
        "behavior_verification": None,
        "release_verification": None,
        "behavior_manifest": None,
    }
    if failures:
        return result
    if behavior_verifier is None:
        from .behavior_verify import verify_behavior_run

        behavior_verifier = verify_behavior_run
    if release_verifier is None:
        from .release import verified_public_release

        release_verifier = verified_public_release
    with tempfile.TemporaryDirectory(prefix="cavada-public-evidence-") as temporary:
        root = Path(temporary)
        _materialize(files, root)
        run_bundle = Path(str(manifest["run_bundle"]["relative_path"]))
        run_dir = root / run_bundle.parent
        engagement = root / str(manifest["engagement"]["relative_path"])
        release_approval = root / str(manifest["release_approval"]["relative_path"])
        declared_verification_path = root / str(manifest["verification_result"]["relative_path"])
        try:
            behavior = behavior_verifier(run_dir, now=now)
        except (OSError, ProtocolError, ValueError, TypeError) as exc:
            failures.append(f"behavior semantic verification failed: {exc}")
            behavior = None
        if not isinstance(behavior, dict) or behavior.get("valid") is not True:
            failures.append("archived behavior run is not semantically and assuredly valid")
        try:
            declared_verification = _strict_json_loads(declared_verification_path.read_bytes())
        except (OSError, UnicodeDecodeError, ValueError, RecursionError) as exc:
            failures.append(f"archived verification result is not strict JSON: {exc}")
            declared_verification = None
        if behavior is not None and declared_verification != behavior:
            failures.append("archived verification result does not equal canonical reconstruction")
        try:
            release = release_verifier(run_dir, engagement, release_approval, now=now)
        except (OSError, ProtocolError, ValueError, TypeError) as exc:
            failures.append(f"public release verification failed: {exc}")
            release = None
        try:
            behavior_manifest = _strict_json_loads((run_dir / "manifest.json").read_bytes())
        except (OSError, UnicodeDecodeError, ValueError, RecursionError):
            behavior_manifest = None
            failures.append("archived behavior manifest is not strict JSON")
        if not isinstance(behavior_manifest, dict):
            failures.append("archived behavior manifest is not an object")
        result.update(
            {
                "valid": not failures,
                "failures": list(dict.fromkeys(failures)),
                "behavior_verification": behavior,
                "release_verification": release,
                "behavior_manifest": behavior_manifest,
            }
        )
    return result


def _attestation_binding_errors(attestation: Any, record: dict[str, Any], archive_path: Path) -> list[str]:
    errors = _exact(attestation, _ATTESTATION_FIELDS, "registry attestation")
    if errors or not isinstance(attestation, dict):
        return errors
    archive_value = record.get("archive")
    archive: dict[str, Any] = archive_value if isinstance(archive_value, dict) else {}
    expected = {
        "attestation_version": "1.0.0",
        "provider": "github-artifact-attestations",
        "subject_name": archive_path.name,
        "subject_sha256": archive.get("sha256"),
        "repository": "cavadalabs/cavadalabs-evals",
        "protocol_version": record.get("protocol_version"),
        "schema_version": REGISTRY_VERSION,
    }
    for field, value in expected.items():
        if attestation.get(field) != value:
            errors.append(f"registry attestation {field} does not match the exact archive or record")
    if attestation.get("signer_workflow") != "cavadalabs/cavadalabs-evals/.github/workflows/release.yml":
        errors.append("registry attestation signer_workflow must identify the canonical release workflow")
    if not isinstance(attestation.get("source_commit"), str) or _COMMIT.fullmatch(attestation["source_commit"]) is None:
        errors.append("registry attestation source_commit must be a full lowercase Git commit")
    if not isinstance(attestation.get("source_ref"), str) or not attestation["source_ref"].startswith("refs/tags/v"):
        errors.append("registry attestation source_ref must be an immutable release tag ref")
    return errors


def verify_github_attestation(archive_path: Path, attestation: dict[str, Any]) -> list[str]:
    """Verify GitHub's Sigstore-backed attestation online with the installed gh CLI."""
    command = [
        "gh",
        "attestation",
        "verify",
        str(archive_path),
        "--repo",
        str(attestation["repository"]),
        "--signer-workflow",
        str(attestation["signer_workflow"]),
        "--source-digest",
        str(attestation["source_commit"]),
        "--source-ref",
        str(attestation["source_ref"]),
        "--deny-self-hosted-runners",
        "--format",
        "json",
    ]
    try:
        completed = subprocess.run(command, check=False, capture_output=True, text=True, timeout=60)  # noqa: S603
    except (OSError, subprocess.TimeoutExpired) as exc:
        return [f"online GitHub attestation verification is unavailable: {exc}"]
    if completed.returncode != 0:
        detail = completed.stderr.strip() or "gh attestation verify failed"
        return [f"online GitHub attestation verification failed: {detail}"]
    try:
        output = _strict_json_loads(completed.stdout)
    except (ValueError, json.JSONDecodeError, RecursionError):
        return ["online GitHub attestation verification returned invalid JSON"]
    if not isinstance(output, list) or not output:
        return ["online GitHub attestation verification returned no verified attestations"]
    expected_subject = {"name": attestation["subject_name"], "digest": {"sha256": attestation["subject_sha256"]}}
    for item in output:
        if not isinstance(item, dict):
            continue
        verification = item.get("verificationResult")
        statement = verification.get("statement") if isinstance(verification, dict) else None
        subjects = statement.get("subject") if isinstance(statement, dict) else None
        if isinstance(subjects, list) and expected_subject in subjects:
            return []
    return ["verified GitHub attestation does not contain the exact expected subject name and digest"]


def _record_shape_errors(record: Any, index: int) -> list[str]:
    label = f"registry records[{index}]"
    errors = _exact(record, _RECORD_FIELDS, label)
    if errors or not isinstance(record, dict):
        return errors
    if record.get("record_version") != REGISTRY_VERSION:
        errors.append(f"{label}.record_version must be {REGISTRY_VERSION}")
    if not isinstance(record.get("record_id"), str) or not record["record_id"].strip():
        errors.append(f"{label}.record_id must be non-empty")
    if record.get("record_type") not in {"official", "conformance"}:
        errors.append(f"{label}.record_type is invalid")
    errors.extend(_exact(record.get("archive"), _ARCHIVE_RECORD_FIELDS, f"{label}.archive"))
    archive = record.get("archive")
    if isinstance(archive, dict):
        relative, path_errors = _relative(archive.get("relative_path"), f"{label}.archive.relative_path")
        errors.extend(path_errors)
        digest = archive.get("sha256")
        if not isinstance(digest, str) or _SHA256.fullmatch(digest) is None:
            errors.append(f"{label}.archive.sha256 must be a lowercase SHA-256")
        elif relative != f"archive/sha256/{digest}.tar":
            errors.append(f"{label}.archive.relative_path is not content-addressed by its digest")
        if archive.get("format") != ARCHIVE_FORMAT or archive.get("format_version") != ARCHIVE_VERSION:
            errors.append(f"{label}.archive format or version is unsupported")
    if record.get("artifact_type") != "behavior-run":
        errors.append(f"{label}.artifact_type must be behavior-run")
    for name, fields in (("suite", _SUITE_FIELDS), ("system", _SYSTEM_FIELDS)):
        value = record.get(name)
        errors.extend(_exact(value, fields, f"{label}.{name}"))
        if isinstance(value, dict):
            for field in fields:
                if not isinstance(value.get(field), str) or not value[field].strip():
                    errors.append(f"{label}.{name}.{field} must be non-empty")
    for field in ("verification_result_sha256", "release_approval_sha256"):
        if not isinstance(record.get(field), str) or _SHA256.fullmatch(record[field]) is None:
            errors.append(f"{label}.{field} must be a lowercase SHA-256")
    published, time_errors = _timestamp(record.get("published_at"), f"{label}.published_at")
    errors.extend(time_errors)
    expires, time_errors = _timestamp(record.get("expires_at"), f"{label}.expires_at")
    errors.extend(time_errors)
    if published is not None and expires is not None and published >= expires:
        errors.append(f"{label} publication must precede expiry")
    claims = record.get("claim_scope")
    if not isinstance(claims, list) or any(not isinstance(item, str) or not item.strip() for item in claims) or len(claims) != len(set(claims)):
        errors.append(f"{label}.claim_scope must contain unique non-empty strings")
    for field in ("rankable", "model_claim_allowed", "benchmark_claim_allowed"):
        if not isinstance(record.get(field), bool):
            errors.append(f"{label}.{field} must be boolean")
    if record.get("reproduction_status") != "not-reproduced":
        errors.append(f"{label}.reproduction_status must remain not-reproduced until a versioned reproduction evidence format exists")
    if record.get("record_type") == "conformance":
        if record.get("assurance_level") != "conformance-fixture":
            errors.append(f"{label} conformance assurance_level must be conformance-fixture")
        if any(record.get(field) is not False for field in ("rankable", "model_claim_allowed", "benchmark_claim_allowed")) or claims:
            errors.append(f"{label} conformance records cannot be rankable or authorize claims")
        if record.get("attestation") is not None:
            errors.append(f"{label} conformance evidence must not be attested as a real result")
    else:
        if record.get("assurance_level") != "official":
            errors.append(f"{label} official assurance_level must be official")
        if not claims:
            errors.append(f"{label} official claim_scope must not be empty")
        if record.get("rankable") is True and not (record.get("model_claim_allowed") is True and record.get("benchmark_claim_allowed") is True):
            errors.append(f"{label} cannot be rankable without model and benchmark claim authorization")
    return errors


def _event_errors(events: Any, records: list[dict[str, Any]], now: datetime) -> list[str]:
    if not isinstance(events, list):
        return ["registry events must be an array"]
    errors: list[str] = []
    record_ids = {str(record.get("record_id")) for record in records}
    event_ids: set[str] = set()
    chains: dict[str, list[dict[str, Any]]] = {record_id: [] for record_id in record_ids}
    for index, event in enumerate(events):
        label = f"registry events[{index}]"
        errors.extend(_exact(event, _EVENT_FIELDS, label))
        if not isinstance(event, dict):
            continue
        if event.get("event_version") != REGISTRY_VERSION:
            errors.append(f"{label}.event_version must be {REGISTRY_VERSION}")
        event_id = event.get("event_id")
        if not isinstance(event_id, str) or not event_id.strip() or event_id in event_ids:
            errors.append(f"{label}.event_id must be unique and non-empty")
        else:
            event_ids.add(event_id)
        record_id = event.get("record_id")
        if record_id not in record_ids:
            errors.append(f"{label}.record_id does not identify a registry record")
            continue
        if event.get("event_type") not in {"published", *_TERMINAL_EVENTS}:
            errors.append(f"{label}.event_type is invalid")
        _, time_errors = _timestamp(event.get("occurred_at"), f"{label}.occurred_at")
        errors.extend(time_errors)
        if not isinstance(event.get("reason"), str) or not event["reason"].strip():
            errors.append(f"{label}.reason must be non-empty")
        chains[str(record_id)].append(event)
    records_by_id = {str(record["record_id"]): record for record in records if isinstance(record.get("record_id"), str)}
    for record_id, chain in chains.items():
        if sum(event.get("event_type") == "published" for event in chain) != 1:
            errors.append(f"registry record {record_id} must contain exactly one published event")
        if not chain or chain[0].get("event_type") != "published":
            errors.append(f"registry record {record_id} must begin with one published event")
            continue
        if chain[0].get("previous_event_id") is not None or chain[0].get("related_record_id") is not None:
            errors.append(f"registry record {record_id} published event cannot reference another event or record")
        previous_id: str | None = None
        previous_time: datetime | None = None
        terminal = False
        for position, event in enumerate(chain):
            occurred, _ = _timestamp(event.get("occurred_at"), "event occurred_at")
            if position and event.get("previous_event_id") != previous_id:
                errors.append(f"registry record {record_id} lifecycle is not an append-only event chain")
            if previous_time is not None and occurred is not None and occurred < previous_time:
                errors.append(f"registry record {record_id} lifecycle timestamps are not monotonic")
            if terminal and position:
                errors.append(f"registry record {record_id} has an event after a terminal lifecycle event")
            event_type = event.get("event_type")
            related = event.get("related_record_id")
            if event_type in {"corrected", "superseded"}:
                if related not in record_ids or related == record_id:
                    errors.append(f"registry record {record_id} {event_type} event must reference a distinct replacement record")
            elif position and related is not None:
                errors.append(f"registry record {record_id} {event_type} event cannot reference a replacement record")
            if event_type in _TERMINAL_EVENTS:
                terminal = True
            previous_id = str(event.get("event_id"))
            previous_time = occurred
        record = records_by_id.get(record_id, {})
        published, _ = _timestamp(record.get("published_at"), "record published_at")
        expires, _ = _timestamp(record.get("expires_at"), "record expires_at")
        first_time, _ = _timestamp(chain[0].get("occurred_at"), "published event occurred_at")
        if published is not None and first_time != published:
            errors.append(f"registry record {record_id} published event timestamp does not match the record")
        if expires is not None and now >= expires and not terminal:
            errors.append(f"registry record {record_id} is expired but has no append-only terminal lifecycle event")
    return errors


def validate_registry_v2(
    registry: dict[str, Any],
    *,
    root: Path | None,
    previous: dict[str, Any] | None = None,
    initial_empty: bool = False,
    now: datetime | None = None,
    behavior_verifier: BehaviorVerifier | None = None,
    release_verifier: ReleaseVerifier | None = None,
    attestation_verifier: AttestationVerifier | None = None,
) -> list[str]:
    errors = _exact(registry, _REGISTRY_FIELDS, "results registry")
    if registry.get("registry_version") != REGISTRY_VERSION:
        errors.append(f"registry_version must be {REGISTRY_VERSION}")
    records = registry.get("records")
    events = registry.get("events")
    if not isinstance(records, list):
        records = []
        errors.append("registry records must be an array")
    if not isinstance(events, list):
        events = []
        errors.append("registry events must be an array")
    if initial_empty and (records or events):
        errors.append("initial registry v2 must be empty")
    if previous is not None:
        if previous.get("registry_version") != REGISTRY_VERSION:
            errors.append("previous registry must use version 2.0.0")
        else:
            previous_records = previous.get("records")
            previous_events = previous.get("events")
            if not isinstance(previous_records, list) or records[: len(previous_records)] != previous_records:
                errors.append("registry records are not append-only")
            if not isinstance(previous_events, list) or events[: len(previous_events)] != previous_events:
                errors.append("registry lifecycle events are not append-only")
    record_ids: set[str] = set()
    typed_records: list[dict[str, Any]] = []
    now = now or datetime.now(timezone.utc)
    for index, value in enumerate(records):
        errors.extend(_record_shape_errors(value, index))
        if not isinstance(value, dict):
            continue
        typed_records.append(value)
        record_id = value.get("record_id")
        if isinstance(record_id, str):
            if record_id in record_ids:
                errors.append(f"duplicate registry record_id: {record_id}")
            record_ids.add(record_id)
        archive = value.get("archive")
        if not isinstance(archive, dict) or not isinstance(archive.get("relative_path"), str) or not isinstance(archive.get("sha256"), str):
            continue
        if root is None:
            errors.append(f"registry record {record_id} cannot be verified without the registry root")
            continue
        relative, path_errors = _relative(archive["relative_path"], f"registry record {record_id} archive path")
        errors.extend(path_errors)
        if relative is None:
            continue
        archive_path = root / relative
        reconstructed = verify_public_evidence_archive(
            archive_path,
            expected_digest=archive["sha256"],
            now=now,
            behavior_verifier=behavior_verifier,
            release_verifier=release_verifier,
        )
        errors.extend(f"registry record {record_id}: {failure}" for failure in reconstructed["failures"])
        manifest = reconstructed.get("manifest")
        behavior_manifest = reconstructed.get("behavior_manifest")
        release = reconstructed.get("release_verification")
        if isinstance(manifest, dict):
            if value.get("verification_result_sha256") != manifest.get("verification_result", {}).get("sha256"):
                errors.append(f"registry record {record_id} verification result digest does not match the archive")
            if value.get("release_approval_sha256") != manifest.get("release_approval", {}).get("sha256"):
                errors.append(f"registry record {record_id} release approval digest does not match the archive")
        if isinstance(behavior_manifest, dict):
            suite = behavior_manifest.get("suite")
            target = behavior_manifest.get("target")
            expected_suite = {key: suite.get(key) for key in _SUITE_FIELDS} if isinstance(suite, dict) else None
            expected_system = (
                {"identity": target.get("expected_reported_model"), "revision": target.get("revision")} if isinstance(target, dict) else None
            )
            if value.get("suite") != expected_suite:
                errors.append(f"registry record {record_id} suite identity does not match the behavior manifest")
            if value.get("system") != expected_system:
                errors.append(f"registry record {record_id} system identity does not match the behavior manifest")
            if value.get("protocol_version") != behavior_manifest.get("protocol_version"):
                errors.append(f"registry record {record_id} protocol_version does not match the behavior manifest")
            if value.get("assurance_level") != behavior_manifest.get("assurance"):
                errors.append(f"registry record {record_id} assurance_level does not match the behavior manifest")
        if isinstance(release, dict):
            if value.get("claim_scope") != release.get("permitted_claims"):
                errors.append(f"registry record {record_id} claim_scope does not match the release approval")
            for field in ("model_claim_allowed", "benchmark_claim_allowed"):
                if value.get(field) != release.get(field):
                    errors.append(f"registry record {record_id} {field} does not match the release verification")
            if value.get("expires_at") != release.get("expires_at"):
                errors.append(f"registry record {record_id} expires_at does not match the release approval")
        if value.get("record_type") == "official":
            attestation = value.get("attestation")
            binding_errors = _attestation_binding_errors(attestation, value, archive_path)
            errors.extend(f"registry record {record_id}: {failure}" for failure in binding_errors)
            if not binding_errors and isinstance(attestation, dict):
                if attestation_verifier is None:
                    errors.append(f"registry record {record_id}: public attestation requires explicit online GitHub verification")
                else:
                    errors.extend(f"registry record {record_id}: {failure}" for failure in attestation_verifier(archive_path, attestation))
    errors.extend(_event_errors(events, typed_records, now))
    return list(dict.fromkeys(errors))
