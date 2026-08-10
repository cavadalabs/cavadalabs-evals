#!/usr/bin/env python3
"""Validate cross-record and append-only rules for the public results registry."""

from __future__ import annotations

import argparse
import json
import shutil
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Mapping

from jsonschema import Draft202012Validator, FormatChecker  # type: ignore[import-untyped]

from cavada_eval.protocol import ProtocolError, sha256_bytes, sha256_file
from cavada_eval.public_verify import verify_public_bundle

PROHIBITED_CLAIMS = ("accredited", "certified", "legally compliant", "universally correct", "universally safe", "universally secure")
DEVELOPMENT_PERFORMANCE_CLAIM = "Development performance evidence under the declared conditions."
COLLECTIONS = ("results", "reproductions", "corrections")
SCHEMA_ROOT = Path(__file__).resolve().parents[1] / "schemas"
SCHEMAS = {
    "1.0.0": SCHEMA_ROOT / "results-registry.schema.json",
    "2.0.0": SCHEMA_ROOT / "results-registry-2.0.0.schema.json",
}


def _load(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"{path} must be a readable JSON object") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{path} must be a readable JSON object")
    return value


def _records(registry: dict[str, Any], name: str, errors: list[str]) -> list[dict[str, Any]]:
    value = registry.get(name)
    if not isinstance(value, list):
        errors.append(f"{name} must be an array")
        return []
    if any(not isinstance(item, dict) for item in value):
        errors.append(f"{name} must contain only objects")
        return []
    return value


def _time(value: Any, label: str, errors: list[str]) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        errors.append(f"{label} must be an ISO 8601 timestamp")
        return None
    if parsed.tzinfo is None:
        errors.append(f"{label} must include a timezone")
        return None
    return parsed


def _bundle_hash(record: dict[str, Any]) -> Any:
    artifact = record.get("artifact")
    return artifact.get("bundle_sha256") if isinstance(artifact, dict) else None


def _placeholder_hashes(value: Any, path: str = "$") -> list[str]:
    if isinstance(value, dict):
        failures: list[str] = []
        for key, child in value.items():
            child_path = f"{path}.{key}"
            if (key.endswith("sha256") and child == "0" * 64) or (key == "source_commit" and child in {"0" * 40, "0" * 64}):
                failures.append(child_path)
            failures.extend(_placeholder_hashes(child, child_path))
        return failures
    if isinstance(value, list):
        return [failure for index, child in enumerate(value) for failure in _placeholder_hashes(child, f"{path}[{index}]")]
    return []


def _append_only(current: dict[str, Any], previous: dict[str, Any], errors: list[str]) -> None:
    empty_v1_migration = (
        previous.get("registry_version") == "1.0.0"
        and current.get("registry_version") == "2.0.0"
        and set(previous) == {"registry_version", *COLLECTIONS}
        and all(previous.get(name) == [] for name in COLLECTIONS)
    )
    if previous.get("registry_version") != current.get("registry_version") and not empty_v1_migration:
        errors.append("registry_version cannot change in place; publish a new registry version")
    for name in COLLECTIONS:
        old = previous.get(name)
        new = current.get(name)
        if not isinstance(old, list) or not isinstance(new, list) or new[: len(old)] != old:
            errors.append(f"{name} must preserve every previous record, unchanged and in order")


def _extract_public_archive(path: Path, destination: Path) -> None:
    if path.is_symlink() or not path.is_file():
        raise ValueError("public artifact must be a regular archive")
    try:
        with tarfile.open(path, "r:*") as archive:
            seen: set[str] = set()
            for member in archive.getmembers():
                relative = PurePosixPath(member.name)
                canonical = relative.as_posix()
                if (
                    not member.name
                    or relative.is_absolute()
                    or ".." in relative.parts
                    or (relative.parts and ":" in relative.parts[0])
                    or canonical in seen
                    or not (member.isfile() or member.isdir())
                ):
                    raise ValueError(f"public artifact contains an unsafe member: {member.name!r}")
                seen.add(canonical)
            archive.extractall(destination, filter="data")
    except (OSError, tarfile.TarError) as exc:
        raise ValueError("public artifact must be a readable tar archive") from exc


def _exact_performance_release(
    manifest: dict[str, Any],
    artifact: dict[str, Any],
    *,
    archive_sha256: str,
    bundle_sha256: str,
    manifest_sha256: str,
) -> dict[str, Any] | None:
    release = manifest.get("release")
    if not isinstance(release, dict):
        return None
    return {
        "release_version": release.get("release_version"),
        "release_id": release.get("release_id"),
        "run_id": manifest.get("run_id"),
        "source_bundle_sha256": manifest.get("source_bundle_sha256"),
        "source_manifest_sha256": manifest.get("source_manifest_sha256"),
        "bundle_sha256": bundle_sha256,
        "manifest_sha256": manifest_sha256,
        "engagement_id": release.get("engagement_id"),
        "engagement_sha256": release.get("engagement_sha256"),
        "approval_sha256": release.get("approval_sha256"),
        "approver_id": release.get("approver_id"),
        "permitted_claims": release.get("permitted_claims"),
        "approved_at": release.get("approved_at"),
        "expires_at": release.get("expires_at"),
        "public_release": {"uri": artifact.get("uri"), "sha256": archive_sha256},
    }


def _validate_v2_performance_artifact(
    result: dict[str, Any],
    archive: Path | None,
) -> list[str]:
    result_id = str(result.get("id", "<missing>"))
    if archive is None:
        return [f"performance result {result_id} requires its local public artifact for offline semantic verification"]
    time_errors: list[str] = []
    published_at = _time(result.get("published_at"), f"performance result {result_id} published_at", time_errors)
    if published_at is None:
        return time_errors
    artifact_value = result.get("artifact")
    artifact = artifact_value if isinstance(artifact_value, dict) else {}
    try:
        with tempfile.TemporaryDirectory(prefix="cavada-registry-public-") as temporary:
            temporary_root = Path(temporary)
            archive_snapshot = temporary_root / "public.tar"
            if archive.is_symlink() or not archive.is_file():
                raise ValueError("public artifact must be a regular archive")
            shutil.copyfile(archive, archive_snapshot)
            archive_sha256 = sha256_file(archive_snapshot)
            if archive_sha256 != artifact.get("sha256"):
                return [f"performance result {result_id} public artifact SHA-256 does not match its archive bytes"]
            root = temporary_root / "artifact"
            root.mkdir()
            _extract_public_archive(archive_snapshot, root)
            verification = verify_public_bundle(root, effective_at=published_at)
            manifest = _load(root / "public_manifest.json")
            bundle_sha256 = sha256_file(root / "bundle.json")
            manifest_sha256 = sha256_file(root / "public_manifest.json")
    except (OSError, ProtocolError, ValueError) as exc:
        return [f"performance result {result_id} public artifact verification failed: {exc}"]

    errors: list[str] = []
    evaluation_finished_at = _time(
        manifest.get("evaluation_finished_at"),
        f"performance result {result_id} evaluation_finished_at",
        errors,
    )
    if evaluation_finished_at is not None and published_at < evaluation_finished_at:
        errors.append(f"performance result {result_id} cannot be published before its evaluation finished")
    if verification.get("type") != "performance" or verification.get("semantic_valid") is not True:
        errors.append(f"performance result {result_id} public artifact is not a semantically verified performance bundle")
    if artifact.get("bundle_sha256") != bundle_sha256 or artifact.get("manifest_sha256") != manifest_sha256:
        errors.append(f"performance result {result_id} does not bind the exact public bundle and manifest bytes")
    if manifest.get("publication_version") != "2.0.0" or manifest.get("performance_protocol_version") != "2.0.0":
        errors.append(f"performance result {result_id} is not a v2 public performance publication")
    if result.get("run_id") != manifest.get("run_id"):
        errors.append(f"performance result {result_id} run_id differs from its public manifest")
    for field in ("status", "cells", "source", "limitations"):
        if result.get(field) != manifest.get(field):
            errors.append(f"performance result {result_id} {field} differs from its public manifest")

    compatibility_value = result.get("compatibility")
    compatibility = compatibility_value if isinstance(compatibility_value, dict) else {}
    source_value = manifest.get("source")
    plan_value = manifest.get("plan")
    workload_value = manifest.get("workload")
    runtime_value = manifest.get("runtime")
    source: dict[str, Any] = source_value if isinstance(source_value, dict) else {}
    plan: dict[str, Any] = plan_value if isinstance(plan_value, dict) else {}
    workload: dict[str, Any] = workload_value if isinstance(workload_value, dict) else {}
    runtime: dict[str, Any] = runtime_value if isinstance(runtime_value, dict) else {}
    evidence_value = manifest.get("system_evidence")
    evidence: dict[str, Any] = evidence_value if isinstance(evidence_value, dict) else {}
    compatibility_expected = {
        "protocol": {
            "id": "llm-serving-performance",
            "version": manifest.get("performance_protocol_version"),
            "sha256": manifest.get("protocol_sha256"),
        },
        "benchmark": {"id": plan.get("name"), "version": plan.get("revision"), "sha256": plan.get("sha256")},
        "inputs": {"id": workload.get("id"), "version": workload.get("revision"), "sha256": workload.get("sha256")},
        "measurement": {
            "id": "performance-publication",
            "version": manifest.get("publication_version"),
            "sha256": sha256_file(SCHEMA_ROOT / "performance-publication-2.0.0.schema.json"),
        },
        "parameters_sha256": runtime.get("sha256"),
        "conditions_sha256": evidence.get("sha256") if evidence else sha256_bytes(b"null"),
        "source_commit": source.get("commit"),
    }
    if compatibility != compatibility_expected:
        errors.append(f"performance result {result_id} compatibility differs from its public manifest")
    if result.get("evaluated_system") != f"{runtime.get('expected_model')} on {runtime.get('engine')}":
        errors.append(f"performance result {result_id} evaluated_system differs from its public manifest")

    official = manifest.get("official") is True
    expected_assurance = "official" if official else "development"
    if (
        result.get("assurance") != expected_assurance
        or result.get("rankable") is not official
        or verification.get("assurance") != ("approved" if official else "development")
    ):
        errors.append(f"performance result {result_id} assurance or rankability differs from its verified publication")
    cells_value = manifest.get("cells")
    reconciliation_value = manifest.get("request_reconciliation")
    cells: dict[str, Any] = cells_value if isinstance(cells_value, dict) else {}
    reconciliation: dict[str, Any] = reconciliation_value if isinstance(reconciliation_value, dict) else {}
    if official:
        if (
            manifest.get("status") != "completed"
            or cells.get("invalid_loadgen") != 0
            or cells.get("with_errors") != 0
            or reconciliation.get("campaign_complete") is not True
        ):
            errors.append(f"official performance result {result_id} is not a clean completed campaign")
        expected_release = _exact_performance_release(
            manifest,
            artifact,
            archive_sha256=archive_sha256,
            bundle_sha256=bundle_sha256,
            manifest_sha256=manifest_sha256,
        )
        if result.get("release_evidence") != expected_release:
            errors.append(f"official performance result {result_id} does not exactly match its public release projection")
        release_value = manifest.get("release")
        release: dict[str, Any] = release_value if isinstance(release_value, dict) else {}
        if result.get("claims") != release.get("permitted_claims"):
            errors.append(f"official performance result {result_id} claims differ from its exact release approval")
    elif result.get("release_evidence") is not None:
        errors.append(f"development performance result {result_id} cannot carry release evidence")
    elif result.get("claims") != [DEVELOPMENT_PERFORMANCE_CLAIM]:
        errors.append(f"development performance result {result_id} must use the fixed development claim")
    return errors


def current_rankable_result_ids(registry: dict[str, Any], *, now: datetime | None = None) -> list[str]:
    """Return results eligible for ranking at the requested instant."""
    instant = now or datetime.now(timezone.utc)
    if instant.tzinfo is None:
        raise ValueError("ranking time must include a timezone")
    terminal = {
        str(correction.get("subject_id"))
        for correction in registry.get("corrections", [])
        if isinstance(correction, dict)
        and correction.get("subject_kind") == "result"
        and correction.get("action") in {"withdraw", "supersede"}
        and (_time(correction.get("published_at"), "correction published_at", []) or datetime.max.replace(tzinfo=timezone.utc)) <= instant
    }
    current: list[str] = []
    for result in registry.get("results", []):
        if not isinstance(result, dict) or result.get("assurance") != "official" or result.get("rankable") is not True:
            continue
        published = _time(result.get("published_at"), "result published_at", [])
        expires = _time(result.get("expires_at"), "result expires_at", [])
        result_id = str(result.get("id", ""))
        if published is not None and expires is not None and published <= instant < expires and result_id not in terminal:
            current.append(result_id)
    return current


def _resolve_artifacts(registry: dict[str, Any], registry_path: Path, supplied: Mapping[str, Path]) -> dict[str, Path]:
    resolved = dict(supplied)
    if registry.get("registry_version") != "2.0.0":
        return resolved
    for result in registry.get("results", []):
        if not isinstance(result, dict) or result.get("kind") != "performance":
            continue
        result_id = result.get("id")
        artifact = result.get("artifact")
        digest = artifact.get("sha256") if isinstance(artifact, dict) else None
        if (
            isinstance(result_id, str)
            and result_id not in resolved
            and isinstance(digest, str)
            and len(digest) == 64
            and set(digest) <= set("0123456789abcdef")
        ):
            candidate = registry_path.parent / "artifacts" / f"{digest}.tar.gz"
            if candidate.exists() or candidate.is_symlink():
                resolved[result_id] = candidate
    return resolved


def _correction_state(
    corrections: list[dict[str, Any]],
    subjects: dict[tuple[str, str], dict[str, Any]],
    published: dict[tuple[str, str], datetime],
    errors: list[str],
) -> None:
    terminal: set[tuple[str, str]] = set()
    replacements: dict[tuple[str, str], tuple[str, str]] = {}
    for correction in corrections:
        correction_id = str(correction.get("id", "<missing>"))
        key = (str(correction.get("subject_kind", "")), str(correction.get("subject_id", "")))
        subject = subjects.get(key)
        if subject is None:
            errors.append(f"correction {correction_id} references an unknown subject")
            continue
        if correction.get("subject_bundle_sha256") != _bundle_hash(subject):
            errors.append(f"correction {correction_id} does not bind the subject bundle SHA-256")
        corrected_at = _time(correction.get("published_at"), f"correction {correction_id} published_at", errors)
        if corrected_at is not None and corrected_at < published[key]:
            errors.append(f"correction {correction_id} predates its subject")
        action = correction.get("action")
        if action in {"withdraw", "supersede"}:
            if key in terminal:
                errors.append(f"{key[0]} {key[1]} has more than one terminal correction")
            terminal.add(key)
        if action == "supersede":
            replacement = (key[0], str(correction.get("replacement_id", "")))
            replacement_record = subjects.get(replacement)
            if replacement == key or replacement_record is None:
                errors.append(f"correction {correction_id} has an invalid replacement")
                continue
            replacements[key] = replacement
            if corrected_at is not None and published[replacement] > corrected_at:
                errors.append(f"correction {correction_id} predates its replacement")

    for start in replacements:
        seen: set[tuple[str, str]] = set()
        current = start
        while current in replacements:
            if current in seen:
                errors.append(f"supersession cycle starts at {start[0]} {start[1]}")
                break
            seen.add(current)
            current = replacements[current]


def validate_registry(
    registry: dict[str, Any],
    *,
    previous: dict[str, Any] | None = None,
    initial_empty: bool = False,
    artifacts: Mapping[str, Path] | None = None,
) -> list[str]:
    registry_version = registry.get("registry_version")
    schema_path = SCHEMAS.get(str(registry_version))
    if schema_path is None:
        return [f"unsupported registry_version: {registry_version}"]
    schema = _load(schema_path)
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    errors = [
        "schema " + ("/".join(map(str, failure.absolute_path)) or "$") + f": {failure.message}"
        for failure in sorted(validator.iter_errors(registry), key=lambda failure: tuple(map(str, failure.absolute_path)))
    ]
    if set(registry) != {"registry_version", *COLLECTIONS}:
        errors.append("registry must contain exactly registry_version, results, reproductions, and corrections")
    placeholder_hashes = _placeholder_hashes(registry)
    if placeholder_hashes:
        errors.append("placeholder hashes are forbidden: " + ", ".join(placeholder_hashes))
    results = _records(registry, "results", errors)
    reproductions = _records(registry, "reproductions", errors)
    corrections = _records(registry, "corrections", errors)
    if registry_version == "2.0.0" and reproductions:
        errors.append("v2 reproductions are unsupported until their exact local artifacts can be semantically verified")
    if initial_empty and any((results, reproductions, corrections)):
        errors.append("the initial public registry must be empty")
    if previous is not None:
        _append_only(registry, previous, errors)

    all_records = [*results, *reproductions, *corrections]
    ids = [item.get("id") for item in all_records]
    if any(not isinstance(item, str) or not item for item in ids):
        errors.append("every registry record requires a non-empty id")
    if len(ids) != len(set(map(str, ids))):
        errors.append("registry record ids must be globally unique")

    result_by_id = {str(item.get("id")): item for item in results}
    reproduction_by_id = {str(item.get("id")): item for item in reproductions}
    subjects = {
        **{("result", key): value for key, value in result_by_id.items()},
        **{("reproduction", key): value for key, value in reproduction_by_id.items()},
    }
    published: dict[tuple[str, str], datetime] = {}
    expiry: dict[tuple[str, str], datetime] = {}
    for key, record in subjects.items():
        start = _time(record.get("published_at"), f"{key[0]} {key[1]} published_at", errors)
        end = _time(record.get("expires_at"), f"{key[0]} {key[1]} expires_at", errors)
        if start is not None:
            published[key] = start
        if end is not None:
            expiry[key] = end
        if start is not None and end is not None and start >= end:
            errors.append(f"{key[0]} {key[1]} must expire after publication")
    if len(published) != len(subjects):
        published = {key: value for key, value in published.items() if key in subjects}

    safe_published = {key: published.get(key, datetime.min.replace(tzinfo=timezone.utc)) for key in subjects}
    _correction_state(corrections, subjects, safe_published, errors)

    for result in results:
        result_id = str(result.get("id", "<missing>"))
        claims = result.get("claims")
        claims = claims if isinstance(claims, list) and all(isinstance(item, str) for item in claims) else []
        prohibited = [claim for claim in claims if any(fragment in claim.casefold() for fragment in PROHIBITED_CLAIMS)]
        if prohibited:
            errors.append(f"result {result_id} contains a prohibited certification or universal claim")
        release = result.get("release_evidence")
        if result.get("assurance") == "official":
            if result.get("kind") == "external-import":
                errors.append(f"external import {result_id} cannot be official")
            if not isinstance(release, dict):
                errors.append(f"official result {result_id} requires release evidence")
                continue
            raw_artifact = result.get("artifact")
            artifact: dict[str, Any] = raw_artifact if isinstance(raw_artifact, dict) else {}
            expected = {"run_id": result.get("run_id"), "bundle_sha256": _bundle_hash(result), "manifest_sha256": artifact.get("manifest_sha256")}
            if any(release.get(field) != value for field, value in expected.items()):
                errors.append(f"official result {result_id} does not match its release evidence")
            public_release = release.get("public_release")
            if (
                not isinstance(public_release, dict)
                or public_release.get("uri") != artifact.get("uri")
                or public_release.get("sha256") != artifact.get("sha256")
            ):
                errors.append(f"official result {result_id} does not bind its exact public artifact")
            if result.get("kind") == "performance":
                release_version = "2.0.0" if registry_version == "2.0.0" else "1.0.0"
                required_fields: tuple[str, ...] = (
                    "release_id",
                    "source_bundle_sha256",
                    "source_manifest_sha256",
                    "approval_sha256",
                    "approver_id",
                )
                if registry_version == "2.0.0":
                    required_fields += ("engagement_id", "engagement_sha256")
                if release.get("release_version") != release_version or not all(
                    isinstance(release.get(field), str) and release[field].strip() for field in required_fields
                ):
                    errors.append(f"official performance result {result_id} lacks exact approved public release evidence")
            else:
                decisions = release.get("decision_statuses")
                if (
                    release.get("release_version") != "1.0.0"
                    or release.get("assurance_level") != "approved"
                    or not isinstance(decisions, dict)
                    or any(decisions.get(name) != "passed" for name in ("statistical", "security", "disclosure", "release"))
                    or decisions.get("privacy_legal") not in {"passed", "not-applicable"}
                ):
                    errors.append(f"official result {result_id} lacks passed release decisions")
            permitted = release.get("permitted_claims")
            if not isinstance(permitted, list) or not set(claims) <= set(map(str, permitted)):
                errors.append(f"official result {result_id} exceeds its permitted release claims")
            approved_at = _time(release.get("approved_at"), f"official result {result_id} approved_at", errors)
            approval_expiry = _time(release.get("expires_at"), f"official result {result_id} release expires_at", errors)
            result_published = published.get(("result", result_id))
            result_expiry = expiry.get(("result", result_id))
            if (
                approved_at is not None
                and approval_expiry is not None
                and result_published is not None
                and result_expiry is not None
                and not approved_at <= result_published < result_expiry <= approval_expiry
            ):
                errors.append(f"official result {result_id} was not published inside its approval window")
        else:
            if release is not None:
                errors.append(f"non-official result {result_id} cannot carry official release evidence")
            if any("official" in claim.casefold() for claim in claims):
                errors.append(f"non-official result {result_id} cannot make an official claim")

        if registry_version == "2.0.0" and result.get("kind") == "performance":
            errors.extend(
                _validate_v2_performance_artifact(
                    result,
                    (artifacts or {}).get(result_id),
                )
            )

    for reproduction in reproductions:
        reproduction_id = str(reproduction.get("id", "<missing>"))
        original = result_by_id.get(str(reproduction.get("original_result_id", "")))
        if original is None:
            errors.append(f"reproduction {reproduction_id} references an unknown original result")
            continue
        if reproduction.get("original_bundle_sha256") != _bundle_hash(original):
            errors.append(f"reproduction {reproduction_id} does not bind the original bundle SHA-256")
        if reproduction.get("compatibility") != original.get("compatibility"):
            errors.append(f"reproduction {reproduction_id} is not exactly compatible with its original result")
        if _bundle_hash(reproduction) == _bundle_hash(original):
            errors.append(f"reproduction {reproduction_id} reuses the original bundle")
        independence = reproduction.get("independence")
        if not isinstance(independence, dict) or independence.get("independent") is not True or independence.get("conflicts_disclosed") is not True:
            errors.append(f"reproduction {reproduction_id} lacks an independent conflict disclosure")
        elif independence.get("conflicts") and not str(independence.get("conflict_mitigation", "")).strip():
            errors.append(f"reproduction {reproduction_id} has unmitigated disclosed conflicts")

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("registry", type=Path, nargs="?", default=Path("results/registry.json"))
    history = parser.add_mutually_exclusive_group()
    history.add_argument("--previous", type=Path, help="Prior published registry; existing record values and order must be unchanged")
    history.add_argument("--initial-empty", action="store_true", help="Require the first published registry to contain no claims")
    parser.add_argument(
        "--artifact",
        action="append",
        default=[],
        metavar="RESULT_ID=ARCHIVE",
        help="Local immutable public archive required to validate each v2 performance result; repeat per result",
    )
    args = parser.parse_args()
    try:
        artifacts: dict[str, Path] = {}
        for item in args.artifact:
            result_id, separator, raw_path = item.partition("=")
            if not separator or not result_id or not raw_path or result_id in artifacts:
                raise ValueError("--artifact must be a unique RESULT_ID=ARCHIVE mapping")
            artifacts[result_id] = Path(raw_path)
        registry = _load(args.registry)
        errors = validate_registry(
            registry,
            previous=_load(args.previous) if args.previous else None,
            initial_empty=args.initial_empty,
            artifacts=_resolve_artifacts(registry, args.registry, artifacts),
        )
    except ValueError as exc:
        print(f"Invalid results registry: {exc}")
        return 1
    if errors:
        print("Invalid results registry:\n" + "\n".join(errors))
        return 1
    print("Results registry is valid")
    rankable = current_rankable_result_ids(registry)
    print("Current rankable results: " + (", ".join(rankable) if rankable else "none"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
