from __future__ import annotations

import copy
import json
import os
import re
import shutil
import stat
import tomllib
import unicodedata
from collections import Counter
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path, PureWindowsPath
from tempfile import TemporaryDirectory
from typing import Any

from .artifacts import _read_regular, snapshot_bundle_files, verify_bundle, write_bundle
from .calibration import _qualification_structure_errors, qualify_judge_run
from .program import (
    reviewer_qualification_support_errors,
    validate_judge_qualification_blueprint,
    validate_judge_qualification_blueprint_approval,
)
from .protocol import (
    PROTOCOL_VERSION,
    ProtocolError,
    Suite,
    _closed_object_errors,
    _strict_json_loads,
    atomic_json,
    load_suite,
    sha256_bytes,
    validate_suite,
)

QUALIFICATION_EVIDENCE_VERSION = "1.0.0"
QUALIFICATION_EVIDENCE_MANIFEST = "qualification_evidence.json"

BaseBehaviorVerifier = Callable[[Path, datetime], Mapping[str, Any]]

_HASH = re.compile(r"[a-f0-9]{64}")
_SEMVER = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")
_PACKAGE_FIELDS = {"package_version", "artifact_type", "protocol_version", "created_at", "claim_scope", "artifacts"}
_ARTIFACT_FIELDS = {"artifact_id", "relative_path", "sha256", "artifact_type", "media_type", "schema_version"}
_REFERENCE_FIELDS = {"relative_path", "sha256", "artifact_type", "schema_version"}
_REQUIRED_ARTIFACT_TYPES = {
    "qualification-report",
    "qualification-approval",
    "qualification-run-bundle",
    "qualification-run-checksums",
    "corpus-manifest",
    "corpus-suite-configuration",
    "corpus-dataset",
    "corpus-rubric",
    "corpus-source-items",
    "recorded-judge-responses",
    "source-suite-configuration",
    "source-suite-dataset",
    "source-suite-rubric",
    "qualification-blueprint",
    "qualification-blueprint-approval",
    "blueprint-approver-qualification",
    "judge-approver-qualification",
}
_SINGLETON_ARTIFACT_TYPES = _REQUIRED_ARTIFACT_TYPES
_PROTECTED_DIGEST_TYPES = {
    "qualification-report",
    "qualification-approval",
    "qualification-blueprint",
    "qualification-blueprint-approval",
    "blueprint-approver-qualification",
    "judge-approver-qualification",
}
_CORPUS_FIELDS = {
    "corpus_version",
    "frozen_at",
    "blueprint_version",
    "blueprint_path",
    "blueprint_sha256",
    "blueprint_approval_path",
    "blueprint_approval_sha256",
    "source_suite",
    "source_dataset_sha256",
    "source_rubric_sha256",
    "items_source_sha256",
    "dataset_sha256",
    "recorded_responses_sha256",
    "rubric_sha256",
    "items",
    "model_family_aliases",
    "gold_evidence_sha256",
    "identity_blinded_to_judge",
    "independent_gold_required",
}
_CORPUS_ITEM_FIELDS = {
    "item_id",
    "source_case_id",
    "input",
    "response",
    "mandatory_criteria",
    "expected_behavior",
    "gold_verdict",
    "gold_rationale",
    "module",
    "risk_domain",
    "severity",
    "language",
    "locale",
    "response_length",
    "response_style",
    "probe_type",
    "model_family_alias",
    "source_run_manifest_sha256",
    "gold_evidence_sha256",
    "review_method",
}
_REVIEWER_FIELDS = {
    "qualification_version",
    "reviewer_id",
    "role",
    "decision",
    "assessor_id",
    "assessor_independent",
    "conflict_of_interest_assessment",
    "conflicts_resolved",
    "permitted_claim_scope",
    "supporting_evidence",
    "qualified_at",
    "expires_at",
    "revoked_at",
    "revocation_reason",
}
_SOURCE_RUN_EVIDENCE_FIELDS = {
    "evidence_version",
    "run_id",
    "producer_id",
    "source_suite",
    "system",
    "completed_at",
    "record_count",
    "source_items_subject_sha256",
}
_GOLD_EVIDENCE_FIELDS = {
    "evidence_version",
    "evidence_id",
    "status",
    "reviewers",
    "adjudicator_id",
    "adjudication_method",
    "completed_at",
    "record_count",
    "gold_items_subject_sha256",
}
_APPROVAL_FIELDS = {
    "approval_version",
    "approval_id",
    "scope",
    "protocol_version",
    "subject",
    "decision",
    "independent",
    "approver_id",
    "approver_qualification_evidence",
    "conflict_of_interest_assessment",
    "conflicts_resolved",
    "decision_rationale",
    "permitted_claim_scope",
    "approved_at",
    "expires_at",
    "revoked_at",
    "revocation_reason",
}
_BLUEPRINT_APPROVAL_FIELDS = _APPROVAL_FIELDS | {"suite"}


@dataclass(frozen=True)
class QualificationVerification:
    package_version: str | None
    package_sha256: str | None
    integrity_valid: bool
    semantic_valid: bool
    approval_valid: bool
    integrity_failures: tuple[str, ...]
    semantic_failures: tuple[str, ...]
    approval_failures: tuple[str, ...]
    reconstructed_report: dict[str, Any] | None
    source_suite_configuration_sha256: str | None = None

    @property
    def valid(self) -> bool:
        return self.integrity_valid and self.semantic_valid and self.approval_valid

    @property
    def failures(self) -> tuple[str, ...]:
        return (*self.integrity_failures, *self.semantic_failures, *self.approval_failures)

    def as_dict(self) -> dict[str, Any]:
        return {
            "verification_version": QUALIFICATION_EVIDENCE_VERSION,
            "artifact_type": "judge-qualification-evidence-package",
            "valid": self.valid,
            "package_version": self.package_version,
            "package_sha256": self.package_sha256,
            "integrity_valid": self.integrity_valid,
            "semantic_valid": self.semantic_valid,
            "approval_valid": self.approval_valid,
            "integrity_failures": list(self.integrity_failures),
            "semantic_failures": list(self.semantic_failures),
            "approval_failures": list(self.approval_failures),
            "source_suite_configuration_sha256": self.source_suite_configuration_sha256,
        }


def _unique(errors: list[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(errors))


def _aware_time(value: Any, label: str, errors: list[str]) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError
    except (TypeError, ValueError):
        errors.append(f"{label} must be an ISO-8601 timestamp with timezone")
        return None
    return parsed


def _safe_relative(value: Any, label: str, errors: list[str]) -> Path | None:
    if not isinstance(value, str) or not value:
        errors.append(f"{label} must be a non-empty relative path")
        return None
    candidate = Path(value)
    windows = PureWindowsPath(value)
    if (
        candidate.is_absolute()
        or value != unicodedata.normalize("NFC", value)
        or windows.drive
        or ".." in candidate.parts
        or ".." in windows.parts
        or candidate.as_posix() != value
        or windows.as_posix() != value
    ):
        errors.append(f"{label} is unsafe: {value}")
        return None
    return candidate


def _strict_object(root: Path, relative: str, label: str, errors: list[str]) -> dict[str, Any] | None:
    try:
        value = _strict_json_loads(_read_regular(root, Path(relative)))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        errors.append(f"{label} is not strict JSON: {exc}")
        return None
    if not isinstance(value, dict):
        errors.append(f"{label} must be a JSON object")
        return None
    return value


def _strict_jsonl(root: Path, relative: str, label: str, errors: list[str]) -> list[dict[str, Any]] | None:
    try:
        lines = _read_regular(root, Path(relative)).decode("utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as exc:
        errors.append(f"{label} is not regular UTF-8 JSONL: {exc}")
        return None
    rows: list[dict[str, Any]] = []
    for line_number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            row = _strict_json_loads(line)
        except (json.JSONDecodeError, ValueError) as exc:
            errors.append(f"{label} line {line_number} is not strict JSON: {exc}")
            continue
        if not isinstance(row, dict):
            errors.append(f"{label} line {line_number} must be an object")
            continue
        rows.append(row)
    return rows


def _strict_toml(root: Path, relative: str, label: str, errors: list[str]) -> tuple[dict[str, Any], bytes] | None:
    try:
        raw = _read_regular(root, Path(relative))
        value = tomllib.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        errors.append(f"{label} is not strict TOML: {exc}")
        return None
    return value, raw


def _artifact_reference(
    value: Any,
    expected: Mapping[str, Any],
    *,
    label: str,
    errors: list[str],
    namespace_prefix: str = "",
) -> None:
    errors.extend(_closed_object_errors(value, _REFERENCE_FIELDS, label))
    if not isinstance(value, dict) or set(value) != _REFERENCE_FIELDS:
        errors.append(f"{label} must contain exactly {sorted(_REFERENCE_FIELDS)}")
        return
    expected_reference = dict(expected)
    relative = expected_reference.get("relative_path")
    if namespace_prefix and isinstance(relative, str) and relative.startswith(namespace_prefix):
        expected_reference["relative_path"] = relative.removeprefix(namespace_prefix)
    if any(value.get(field) != expected_reference.get(field) for field in _REFERENCE_FIELDS):
        errors.append(f"{label} does not bind the exact package artifact")


def _artifact_at(
    artifacts_by_path: Mapping[str, dict[str, Any]],
    value: Any,
    *,
    label: str,
    errors: list[str],
    namespace_prefix: str = "",
) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        errors.append(f"{label} must be an artifact reference")
        return None
    relative = value.get("relative_path")
    package_relative = namespace_prefix + relative if namespace_prefix and isinstance(relative, str) else relative
    artifact = artifacts_by_path.get(package_relative) if isinstance(package_relative, str) else None
    if artifact is None:
        errors.append(f"{label} references an undeclared package artifact")
        return None
    _artifact_reference(value, artifact, label=label, errors=errors, namespace_prefix=namespace_prefix)
    return artifact


def _approval_times(record: Mapping[str, Any], now: datetime, label: str, errors: list[str]) -> tuple[datetime, datetime] | None:
    start = _aware_time(record.get("approved_at"), f"{label}.approved_at", errors)
    end = _aware_time(record.get("expires_at"), f"{label}.expires_at", errors)
    if start is None or end is None:
        return None
    if end <= start or start > now or end <= now:
        errors.append(f"{label} is not currently effective")
    revoked = record.get("revoked_at")
    reason = record.get("revocation_reason")
    if revoked is not None or reason != "":
        errors.append(f"{label} has been revoked")
    return start, end


def _reviewer_errors(
    record: Any,
    *,
    package: Path,
    artifact: Mapping[str, Any],
    expected_role: str,
    expected_scope: str,
    artifacts_by_path: Mapping[str, dict[str, Any]],
    now: datetime,
    namespace_prefix: str = "",
    allow_synthetic_fixture: bool = False,
) -> tuple[list[str], tuple[datetime, datetime] | None]:
    label = f"{expected_role} qualification evidence"
    errors = _closed_object_errors(record, _REVIEWER_FIELDS, label)
    if not isinstance(record, dict) or set(record) != _REVIEWER_FIELDS:
        errors.append(f"{label} must contain exactly {sorted(_REVIEWER_FIELDS)}")
        return errors, None
    if (
        artifact.get("schema_version") != "1.0.0"
        or record.get("qualification_version") != "1.0.0"
        or record.get("role") != expected_role
        or record.get("decision") != "qualified"
        or record.get("assessor_independent") is not True
        or record.get("conflicts_resolved") is not True
        or record.get("permitted_claim_scope") != [expected_scope]
        or not all(
            isinstance(record.get(field), str) and record[field].strip()
            for field in ("reviewer_id", "assessor_id", "conflict_of_interest_assessment")
        )
        or record.get("reviewer_id") == record.get("assessor_id")
    ):
        errors.append(f"{label} is incomplete, conflicted, or did not qualify the reviewer")
    start = _aware_time(record.get("qualified_at"), f"{label}.qualified_at", errors)
    end = _aware_time(record.get("expires_at"), f"{label}.expires_at", errors)
    supports = record.get("supporting_evidence")
    seen: set[str] = set()
    if not isinstance(supports, list) or not supports:
        errors.append(f"{label}.supporting_evidence must be non-empty")
    else:
        for index, reference in enumerate(supports):
            support = _artifact_at(
                artifacts_by_path,
                reference,
                label=f"{label}.supporting_evidence[{index}]",
                errors=errors,
                namespace_prefix=namespace_prefix,
            )
            if support is not None and support.get("artifact_type") != "reviewer-qualification-support":
                errors.append(f"{label}.supporting_evidence[{index}] has the wrong artifact type")
            if support is not None:
                support_record = _strict_object(
                    package,
                    str(support["relative_path"]),
                    f"{label}.supporting_evidence[{index}]",
                    errors,
                )
                errors.extend(
                    reviewer_qualification_support_errors(
                        support_record,
                        now=now,
                        label=f"{label}.supporting_evidence[{index}]",
                        expected_subject_id=str(record.get("reviewer_id", "")),
                        expected_issuer_id=str(record.get("assessor_id", "")),
                        allow_synthetic_fixture=allow_synthetic_fixture,
                        not_after=start,
                    )
                )
            relative = reference.get("relative_path") if isinstance(reference, dict) else None
            if isinstance(relative, str):
                if relative in seen:
                    errors.append(f"{label}.supporting_evidence contains duplicate paths")
                seen.add(relative)
    period = (start, end) if start is not None and end is not None else None
    if period is not None and (period[1] <= period[0] or period[0] > now or period[1] <= now):
        errors.append(f"{label} is not currently effective")
    if record.get("revoked_at") is not None or record.get("revocation_reason") != "":
        errors.append(f"{label} has been revoked")
    return errors, period


def _approval_errors(
    approval: Any,
    reviewer: Any,
    *,
    approval_artifact: Mapping[str, Any],
    subject_artifact: Mapping[str, Any],
    reviewer_artifact: Mapping[str, Any],
    scope: str,
    approval_version: str,
    now: datetime,
    reviewer_period: tuple[datetime, datetime] | None,
) -> list[str]:
    label = f"{scope} approval"
    expected_fields = _BLUEPRINT_APPROVAL_FIELDS if scope == "judge-qualification-blueprint" else _APPROVAL_FIELDS
    errors = _closed_object_errors(approval, expected_fields, label)
    if not isinstance(approval, dict) or set(approval) != expected_fields:
        errors.append(f"{label} must contain exactly {sorted(expected_fields)}")
        return errors
    if (
        approval_artifact.get("schema_version") != approval_version
        or approval.get("approval_version") != approval_version
        or approval.get("scope") != scope
        or approval.get("protocol_version") != PROTOCOL_VERSION
        or approval.get("decision") != "approved"
        or approval.get("independent") is not True
        or approval.get("conflicts_resolved") is not True
        or approval.get("permitted_claim_scope") != [scope]
        or not all(
            isinstance(approval.get(field), str) and approval[field].strip()
            for field in ("approval_id", "approver_id", "conflict_of_interest_assessment", "decision_rationale")
        )
    ):
        errors.append(f"{label} is incomplete, conflicted, or did not approve the exact scope")
    namespace_prefix = "source-suite/" if scope == "judge-qualification-blueprint" else ""
    _artifact_reference(
        approval.get("subject"),
        subject_artifact,
        label=f"{label}.subject",
        errors=errors,
        namespace_prefix=namespace_prefix,
    )
    _artifact_reference(
        approval.get("approver_qualification_evidence"),
        reviewer_artifact,
        label=f"{label}.approver_qualification_evidence",
        errors=errors,
        namespace_prefix=namespace_prefix,
    )
    if isinstance(reviewer, dict) and approval.get("approver_id") != reviewer.get("reviewer_id"):
        errors.append(f"{label} approver identity does not match its qualification evidence")
    period = _approval_times(approval, now, label, errors)
    if period is not None and reviewer_period is not None:
        if period[0] < reviewer_period[0] or period[1] > reviewer_period[1]:
            errors.append(f"{label} is outside the approver qualification validity period")
    return errors


def _suite_identity(suite: Suite) -> dict[str, str]:
    return {
        "name": suite.name,
        "version": suite.version,
        "dataset_sha256": sha256_bytes(_read_regular(suite.root, suite.dataset_path.relative_to(suite.root))),
        "rubric_sha256": sha256_bytes(_read_regular(suite.root, suite.rubric_path.relative_to(suite.root))),
    }


def _expected_corpus_rows(items: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    cases: list[dict[str, Any]] = []
    responses: list[dict[str, Any]] = []
    for item in items:
        cases.append(
            {
                "id": item["item_id"],
                "input": item["input"],
                "category": item["module"],
                "module": item["module"],
                "risk_domain": item["risk_domain"],
                "severity": item["severity"],
                "language": item["language"],
                "locale": item["locale"],
                "split": "calibration",
                "tags": ["judge-calibration", str(item["probe_type"])],
                "expected_behavior": item["expected_behavior"],
                "expected_behavior_reason": item["gold_rationale"],
                "mandatory_criteria": item["mandatory_criteria"],
                "judge_gold_verdict": item["gold_verdict"],
                "response_length": item["response_length"],
                "response_style": item["response_style"],
                "probe_type": item["probe_type"],
                "model_family_alias": item["model_family_alias"],
                "source": {
                    "origin": "restricted human-gold judge calibration corpus",
                    "source_case_id": item["source_case_id"],
                    "source_run_manifest_sha256": item["source_run_manifest_sha256"],
                    "gold_evidence_sha256": item["gold_evidence_sha256"],
                    "model_family_alias": item["model_family_alias"],
                },
                "review": {"status": "approved", "method": item["review_method"]},
            }
        )
        responses.append({"case_id": item["item_id"], "response": {"answer": item["response"], "model": "recorded-human-gold"}})
    return cases, responses


def _items_subject_sha256(items: list[dict[str, Any]], *, gold: bool) -> str:
    excluded = {"source_run_manifest_sha256", "gold_evidence_sha256"}
    if not gold:
        excluded.update({"gold_verdict", "gold_rationale", "review_method"})
    payload = "".join(
        json.dumps(
            {key: value for key, value in item.items() if key not in excluded},
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        + "\n"
        for item in items
    ).encode("utf-8")
    return sha256_bytes(payload)


def _corpus_errors(
    root: Path,
    by_type: Mapping[str, list[dict[str, Any]]],
    artifacts_by_path: Mapping[str, dict[str, Any]],
    *,
    now: datetime,
) -> tuple[
    list[str],
    dict[str, Any] | None,
    dict[str, Any] | None,
    Path | None,
    Path | None,
    dict[str, Any] | None,
    dict[str, Any] | None,
]:
    errors: list[str] = []

    def one(name: str) -> dict[str, Any]:
        return by_type[name][0]

    source_config_artifact = one("source-suite-configuration")
    source_config_loaded = _strict_toml(root, str(source_config_artifact["relative_path"]), "source suite configuration", errors)
    source_dataset_artifact = one("source-suite-dataset")
    source_rubric_artifact = one("source-suite-rubric")
    source_cases = _strict_jsonl(root, str(source_dataset_artifact["relative_path"]), "source suite dataset", errors)
    if source_config_loaded is None or source_cases is None:
        return errors, None, None, None, None, None, None
    source_config, _ = source_config_loaded
    source_root = (root / str(source_config_artifact["relative_path"])).parent
    try:
        source_dataset_path = source_root / str(source_config.get("dataset", "dataset.jsonl"))
        source_rubric_path = source_root / str(source_config.get("rubric", "rubric.md"))
        if source_dataset_path.relative_to(root).as_posix() != source_dataset_artifact["relative_path"]:
            errors.append("source suite dataset artifact does not match suite.toml")
        if source_rubric_path.relative_to(root).as_posix() != source_rubric_artifact["relative_path"]:
            errors.append("source suite rubric artifact does not match suite.toml")
    except (TypeError, ValueError):
        errors.append("source suite dataset or rubric path is unsafe")
        return errors, None, None, None, None, None, None
    try:
        source_rubric = _read_regular(root, Path(str(source_rubric_artifact["relative_path"]))).decode("utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        errors.append(f"source suite rubric is unreadable: {exc}")
        return errors, None, None, None, None, None, None
    source_suite = Suite(source_root, source_config, tuple(source_cases), source_rubric, source_dataset_path, source_rubric_path)
    validation_config = copy.deepcopy(source_config)
    validation_config.pop("judge", None)
    errors.extend(validate_suite(Suite(source_root, validation_config, tuple(source_cases), source_rubric, source_dataset_path, source_rubric_path)))
    source_identity = _suite_identity(source_suite)
    if source_config.get("dataset_sha256") != source_identity["dataset_sha256"] or source_config.get("rubric_sha256") != source_identity["rubric_sha256"]:
        errors.append("source suite configuration does not pin its dataset and rubric")

    blueprint_artifact = one("qualification-blueprint")
    blueprint_loaded = _strict_toml(root, str(blueprint_artifact["relative_path"]), "qualification blueprint", errors)
    blueprint_path = root / str(blueprint_artifact["relative_path"])
    blueprint: dict[str, Any] | None = blueprint_loaded[0] if blueprint_loaded is not None else None
    source_judge = source_config.get("judge")
    blueprint_approval_artifact = one("qualification-blueprint-approval")
    if not isinstance(source_judge, dict):
        errors.append("source suite must pin the qualification blueprint and approval")
    else:
        for field in ("qualification_blueprint", "qualification_blueprint_approval"):
            relative = source_judge.get(field)
            expected_hash = source_judge.get(f"{field}_sha256")
            try:
                configured = (source_root / str(relative)).relative_to(root).as_posix()
            except (TypeError, ValueError):
                configured = ""
            configured_artifact = artifacts_by_path.get(configured)
            if configured_artifact is None or expected_hash != configured_artifact.get("sha256"):
                errors.append(f"source suite {field} does not bind the package artifact")
            elif field == "qualification_blueprint" and configured_artifact != blueprint_artifact:
                errors.append("source suite qualification_blueprint differs from the immutable package blueprint")
            elif field == "qualification_blueprint_approval" and configured_artifact != blueprint_approval_artifact:
                errors.append("source suite qualification_blueprint_approval differs from the package approval")
    if blueprint_loaded is not None:
        errors.extend(validate_judge_qualification_blueprint(blueprint_path, source_suite, raw=blueprint_loaded[1]))
        try:
            blueprint_approval_raw = _read_regular(
                root,
                Path(str(blueprint_approval_artifact["relative_path"])),
            )
        except OSError as exc:
            errors.append(f"qualification blueprint approval is unreadable: {exc}")
        else:
            errors.extend(
                validate_judge_qualification_blueprint_approval(
                    root / str(blueprint_approval_artifact["relative_path"]),
                    source_suite,
                    str(blueprint_artifact["sha256"]),
                    raw=blueprint_approval_raw,
                    now=now,
                    require_effective=True,
                )
            )

    corpus_config_artifact = one("corpus-suite-configuration")
    corpus_root = (root / str(corpus_config_artifact["relative_path"])).parent
    try:
        corpus_suite = load_suite(corpus_root)
    except ProtocolError as exc:
        errors.append(f"qualification corpus suite is invalid: {exc}")
        return errors, source_identity, None, blueprint_path, None, blueprint, None
    corpus_identity = _suite_identity(corpus_suite)
    corpus_dataset_artifact = one("corpus-dataset")
    corpus_rubric_artifact = one("corpus-rubric")
    responses_artifact = one("recorded-judge-responses")
    target = corpus_suite.config.get("target")
    expected_paths = {
        "corpus-dataset": corpus_suite.dataset_path,
        "corpus-rubric": corpus_suite.rubric_path,
        "recorded-judge-responses": corpus_root / str(target.get("responses", "")) if isinstance(target, dict) else corpus_root,
    }
    for artifact_type, path in expected_paths.items():
        try:
            observed = path.relative_to(root).as_posix()
        except ValueError:
            observed = ""
        if observed != one(artifact_type)["relative_path"]:
            errors.append(f"{artifact_type} does not match the corpus suite configuration")
    if not isinstance(target, dict) or target.get("kind") != "recorded" or target.get("responses_sha256") != responses_artifact["sha256"]:
        errors.append("qualification corpus must pin its recorded judge responses")

    corpus_manifest_artifact = one("corpus-manifest")
    corpus_manifest_path = root / str(corpus_manifest_artifact["relative_path"])
    if corpus_manifest_path.parent != corpus_root:
        errors.append("corpus manifest and suite configuration must share a package directory")
    corpus = _strict_object(root, str(corpus_manifest_artifact["relative_path"]), "corpus manifest", errors)
    items_artifact = one("corpus-source-items")
    items = _strict_jsonl(root, str(items_artifact["relative_path"]), "corpus source items", errors)
    dataset_rows = _strict_jsonl(root, str(corpus_dataset_artifact["relative_path"]), "corpus dataset", errors)
    response_rows = _strict_jsonl(root, str(responses_artifact["relative_path"]), "recorded judge responses", errors)
    if corpus is None or items is None or dataset_rows is None or response_rows is None or blueprint is None:
        return errors, source_identity, corpus_identity, blueprint_path, corpus_manifest_path, blueprint, corpus
    errors.extend(_closed_object_errors(corpus, _CORPUS_FIELDS, "corpus manifest"))
    if set(corpus) != _CORPUS_FIELDS:
        errors.append(f"corpus manifest must contain exactly {sorted(_CORPUS_FIELDS)}")
    item_ids: set[str] = set()
    source_case_ids = {str(case.get("id")) for case in source_cases}
    for index, item in enumerate(items, 1):
        errors.extend(_closed_object_errors(item, _CORPUS_ITEM_FIELDS, f"corpus item {index}"))
        if set(item) != _CORPUS_ITEM_FIELDS:
            errors.append(f"corpus item {index} must contain exactly {sorted(_CORPUS_ITEM_FIELDS)}")
            continue
        item_id = item.get("item_id")
        if not isinstance(item_id, str) or not item_id or item_id in item_ids:
            errors.append(f"corpus item {index} has an invalid or duplicate item_id")
        else:
            item_ids.add(item_id)
        if item.get("source_case_id") not in source_case_ids:
            errors.append(f"corpus item {index} references an unknown source case")
        if item.get("gold_verdict") not in {"pass", "fail"}:
            errors.append(f"corpus item {index} has an invalid gold verdict")
        for field in ("source_run_manifest_sha256", "gold_evidence_sha256"):
            if not isinstance(item.get(field), str) or _HASH.fullmatch(item[field]) is None:
                errors.append(f"corpus item {index}.{field} is not a SHA-256 digest")
        if not isinstance(item.get("mandatory_criteria"), list) or not item["mandatory_criteria"]:
            errors.append(f"corpus item {index} has no mandatory criteria")
    if all(set(item) == _CORPUS_ITEM_FIELDS for item in items):
        expected_cases, expected_responses = _expected_corpus_rows(items)
        if dataset_rows != expected_cases:
            errors.append("corpus dataset does not reconstruct from the source items")
        if response_rows != expected_responses:
            errors.append("recorded judge responses do not reconstruct from the source items")

    target_unique = blueprint.get("target_unique_responses")
    if not isinstance(target_unique, int) or isinstance(target_unique, bool) or len(items) != target_unique:
        errors.append("corpus item count does not match the qualification blueprint")
    allocations = blueprint.get("allocations")
    for dimension in ("language", "severity", "response_length", "response_style", "probe_type"):
        rows = allocations.get(dimension) if isinstance(allocations, dict) else None
        expected = {str(row.get("id")): row.get("target") for row in rows or [] if isinstance(row, dict)}
        if Counter(str(item.get(dimension)) for item in items) != Counter(expected):
            errors.append(f"corpus {dimension} allocation does not match the qualification blueprint")
    modules = blueprint.get("modules")
    module_rows = {str(row.get("id")): row for row in modules or [] if isinstance(row, dict)}
    if Counter(str(item.get("module")) for item in items) != Counter(
        {module: row.get("target") for module, row in module_rows.items()}
    ):
        errors.append("corpus module allocation does not match the qualification blueprint")
    for module, rule in module_rows.items():
        verdicts = Counter(str(item.get("gold_verdict")) for item in items if item.get("module") == module)
        if verdicts != Counter({"pass": rule.get("pass_target"), "fail": rule.get("fail_target")}):
            errors.append(f"corpus module {module} verdict allocation does not match the qualification blueprint")
    aliases = sorted({str(item.get("model_family_alias")) for item in items})
    if "" in aliases or len(aliases) < int(blueprint.get("minimum_model_families", 0)):
        errors.append("corpus model-family allocation does not match the qualification blueprint")

    expected_manifest = {
        "corpus_version": corpus.get("corpus_version"),
        "frozen_at": corpus.get("frozen_at"),
        "blueprint_version": blueprint.get("version"),
        "blueprint_path": corpus.get("blueprint_path"),
        "blueprint_sha256": blueprint_artifact["sha256"],
        "blueprint_approval_path": corpus.get("blueprint_approval_path"),
        "blueprint_approval_sha256": blueprint_approval_artifact["sha256"],
        "source_suite": source_identity,
        "source_dataset_sha256": source_dataset_artifact["sha256"],
        "source_rubric_sha256": source_rubric_artifact["sha256"],
        "items_source_sha256": items_artifact["sha256"],
        "dataset_sha256": corpus_dataset_artifact["sha256"],
        "recorded_responses_sha256": responses_artifact["sha256"],
        "rubric_sha256": corpus_rubric_artifact["sha256"],
        "items": len(items),
        "model_family_aliases": aliases,
        "gold_evidence_sha256": sorted({str(item.get("gold_evidence_sha256")) for item in items}),
        "identity_blinded_to_judge": True,
        "independent_gold_required": True,
    }
    if corpus != expected_manifest:
        errors.append("corpus manifest does not reconstruct from the package bytes")
    if not isinstance(corpus.get("corpus_version"), str) or _SEMVER.fullmatch(corpus["corpus_version"]) is None:
        errors.append("corpus version is not semantic")
    frozen_at = _aware_time(corpus.get("frozen_at"), "corpus frozen_at", errors)
    if frozen_at is not None and frozen_at > now:
        errors.append("corpus frozen_at is in the future")
    if corpus_rubric_artifact["sha256"] != source_rubric_artifact["sha256"]:
        errors.append("qualification corpus rubric differs from the source suite rubric")
    expected_source_runs = {str(item.get("source_run_manifest_sha256")) for item in items}
    source_run_artifacts = by_type.get("corpus-source-run-manifest", [])
    packaged_source_runs = {str(row["sha256"]) for row in source_run_artifacts}
    if packaged_source_runs != expected_source_runs:
        errors.append("source run manifest evidence is not a closed digest set")
    for index, artifact in enumerate(source_run_artifacts):
        source_run_items = [
            item for item in items if item.get("source_run_manifest_sha256") == artifact["sha256"]
        ]
        record = _strict_object(root, str(artifact["relative_path"]), f"source run manifest evidence[{index}]", errors)
        source_suite_identity = record.get("source_suite") if isinstance(record, dict) else None
        system = record.get("system") if isinstance(record, dict) else None
        completed_at = (
            _aware_time(record.get("completed_at"), f"source run manifest evidence[{index}].completed_at", errors)
            if isinstance(record, dict)
            else None
        )
        if (
            record is None
            or set(record) != _SOURCE_RUN_EVIDENCE_FIELDS
            or record.get("evidence_version") != "1.0.0"
            or any(
                not isinstance(record.get(field), str) or not record[field].strip()
                for field in ("run_id", "producer_id")
            )
            or source_suite_identity != source_identity
            or not isinstance(system, dict)
            or set(system) != {"identity", "revision"}
            or any(not isinstance(system.get(field), str) or not system[field].strip() for field in system)
            or not isinstance(record.get("record_count"), int)
            or isinstance(record.get("record_count"), bool)
            or record["record_count"] != len(source_run_items)
            or record.get("source_items_subject_sha256") != _items_subject_sha256(source_run_items, gold=False)
            or completed_at is None
            or completed_at > now
            or frozen_at is not None
            and completed_at > frozen_at
        ):
            errors.append(f"source run manifest evidence[{index}] is not a strict source-run record")
    expected_gold = {str(item.get("gold_evidence_sha256")) for item in items}
    gold_artifacts = by_type.get("corpus-gold-evidence", [])
    packaged_gold = {str(row["sha256"]) for row in gold_artifacts}
    if packaged_gold != expected_gold:
        errors.append("human-gold evidence is not a closed digest set")
    for index, artifact in enumerate(gold_artifacts):
        gold_items = [item for item in items if item.get("gold_evidence_sha256") == artifact["sha256"]]
        record = _strict_object(root, str(artifact["relative_path"]), f"human-gold evidence[{index}]", errors)
        reviewers = record.get("reviewers") if isinstance(record, dict) else None
        completed_at = (
            _aware_time(record.get("completed_at"), f"human-gold evidence[{index}].completed_at", errors)
            if isinstance(record, dict)
            else None
        )
        reviewer_ids = (
            [reviewer.get("reviewer_id") for reviewer in reviewers if isinstance(reviewer, dict)]
            if isinstance(reviewers, list)
            else []
        )
        reviewed_times: list[datetime] = []
        if isinstance(reviewers, list):
            for reviewer_index, reviewer in enumerate(reviewers):
                if isinstance(reviewer, dict):
                    reviewed_at = _aware_time(
                        reviewer.get("reviewed_at"),
                        f"human-gold evidence[{index}].reviewers[{reviewer_index}].reviewed_at",
                        errors,
                    )
                    if reviewed_at is not None:
                        reviewed_times.append(reviewed_at)
        if (
            record is None
            or set(record) != _GOLD_EVIDENCE_FIELDS
            or record.get("evidence_version") != "1.0.0"
            or record.get("status") != "approved"
            or any(
                not isinstance(record.get(field), str) or not record[field].strip()
                for field in ("evidence_id", "adjudicator_id", "adjudication_method")
            )
            or not isinstance(reviewers, list)
            or len(reviewers) < 2
            or any(
                not isinstance(reviewer, dict)
                or set(reviewer) != {"reviewer_id", "decision", "rationale", "reviewed_at"}
                or reviewer.get("decision") != "approved"
                or not isinstance(reviewer.get("reviewer_id"), str)
                or not reviewer["reviewer_id"].strip()
                or not isinstance(reviewer.get("rationale"), str)
                or not reviewer["rationale"].strip()
                for reviewer in reviewers
            )
            or len(reviewed_times) != len(reviewers)
            or len(reviewer_ids) != len(set(reviewer_ids))
            or record.get("adjudicator_id") in reviewer_ids
            or not isinstance(record.get("record_count"), int)
            or isinstance(record.get("record_count"), bool)
            or record["record_count"] != len(gold_items)
            or record.get("gold_items_subject_sha256") != _items_subject_sha256(gold_items, gold=True)
            or completed_at is None
            or completed_at > now
            or reviewed_times
            and completed_at is not None
            and max(reviewed_times) > completed_at
            or frozen_at is not None
            and completed_at is not None
            and completed_at > frozen_at
        ):
            errors.append(f"human-gold evidence[{index}] is not a strict independent-review record")
    for field, expected_type in (
        ("blueprint_path", "qualification-blueprint"),
        ("blueprint_approval_path", "qualification-blueprint-approval"),
    ):
        relative = corpus.get(field)
        try:
            package_relative = (corpus_root / str(relative)).relative_to(root).as_posix()
        except (TypeError, ValueError):
            package_relative = ""
        bound_artifact = artifacts_by_path.get(package_relative)
        if bound_artifact is None or bound_artifact.get("sha256") != corpus.get(field.removesuffix("_path") + "_sha256"):
            errors.append(f"corpus {field} is missing or not hash-bound")
        elif bound_artifact.get("artifact_type") not in {expected_type, "corpus-support"}:
            errors.append(f"corpus {field} has an invalid artifact type")
    return errors, source_identity, corpus_identity, blueprint_path, corpus_manifest_path, blueprint, corpus


def _package_integrity(
    package: Path,
) -> tuple[str | None, dict[str, Any] | None, dict[str, dict[str, Any]], dict[str, list[dict[str, Any]]], list[str]]:
    errors: list[str] = []
    try:
        bundle_verification = verify_bundle(package, verify_hmac=False)
    except ProtocolError as exc:
        return None, None, {}, {}, [str(exc)]
    errors.extend(str(error) for error in bundle_verification["failures"])
    try:
        bundle_raw = _read_regular(package, Path("bundle.json"))
        bundle = _strict_json_loads(bundle_raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        return None, None, {}, {}, [*errors, f"cannot read package bundle: {exc}"]
    package_sha = sha256_bytes(bundle_raw)
    bundle_files = bundle.get("files") if isinstance(bundle, dict) else None
    if not isinstance(bundle_files, dict):
        return package_sha, None, {}, {}, [*errors, "package bundle file map is malformed"]
    manifest = _strict_object(package, QUALIFICATION_EVIDENCE_MANIFEST, "qualification evidence manifest", errors)
    if manifest is None:
        return package_sha, None, {}, {}, errors
    errors.extend(_closed_object_errors(manifest, _PACKAGE_FIELDS, "qualification evidence manifest"))
    if set(manifest) != _PACKAGE_FIELDS:
        errors.append(f"qualification evidence manifest must contain exactly {sorted(_PACKAGE_FIELDS)}")
    if (
        manifest.get("package_version") != QUALIFICATION_EVIDENCE_VERSION
        or manifest.get("artifact_type") != "judge-qualification-evidence-package"
        or manifest.get("protocol_version") != PROTOCOL_VERSION
        or manifest.get("claim_scope") != ["judge-qualification"]
    ):
        errors.append("qualification evidence manifest identity or claim scope is invalid")
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        errors.append("qualification evidence manifest artifacts must be non-empty")
        return package_sha, manifest, {}, {}, errors
    by_path: dict[str, dict[str, Any]] = {}
    by_type: dict[str, list[dict[str, Any]]] = {}
    identifiers: set[str] = set()
    for index, artifact in enumerate(artifacts):
        label = f"qualification evidence artifact[{index}]"
        errors.extend(_closed_object_errors(artifact, _ARTIFACT_FIELDS, label))
        if not isinstance(artifact, dict) or set(artifact) != _ARTIFACT_FIELDS:
            errors.append(f"{label} must contain exactly {sorted(_ARTIFACT_FIELDS)}")
            continue
        artifact_id = artifact.get("artifact_id")
        relative = artifact.get("relative_path")
        digest = artifact.get("sha256")
        artifact_type = artifact.get("artifact_type")
        media_type = artifact.get("media_type")
        schema_version = artifact.get("schema_version")
        safe = _safe_relative(relative, f"{label}.relative_path", errors)
        if not isinstance(artifact_id, str) or not artifact_id or artifact_id in identifiers:
            errors.append(f"{label}.artifact_id is empty or duplicated")
        else:
            identifiers.add(artifact_id)
        if not isinstance(digest, str) or _HASH.fullmatch(digest) is None:
            errors.append(f"{label}.sha256 is invalid")
        if not isinstance(artifact_type, str) or not artifact_type:
            errors.append(f"{label}.artifact_type is invalid")
        if not isinstance(media_type, str) or not media_type:
            errors.append(f"{label}.media_type is invalid")
        if schema_version is not None and (not isinstance(schema_version, str) or _SEMVER.fullmatch(schema_version) is None):
            errors.append(f"{label}.schema_version is invalid")
        if safe is not None and isinstance(relative, str):
            if relative in by_path:
                errors.append(f"duplicate qualification evidence artifact path: {relative}")
            else:
                by_path[relative] = artifact
        if isinstance(artifact_type, str):
            by_type.setdefault(artifact_type, []).append(artifact)
        if bundle_files.get(relative) != digest:
            errors.append(f"{label} does not match package bundle.json")
    expected_artifact_paths = set(map(str, bundle_files)) - {QUALIFICATION_EVIDENCE_MANIFEST}
    if set(by_path) != expected_artifact_paths:
        errors.append("qualification evidence manifest does not enumerate the closed package file set")
    try:
        staged = {relative: _read_regular(package, Path(relative)) for relative in sorted(expected_artifact_paths)}
        canonical_artifacts = _package_artifacts(staged)
    except (OSError, ProtocolError, TypeError, ValueError) as exc:
        errors.append(f"qualification evidence artifact roles cannot be reconstructed: {exc}")
    else:
        if artifacts != canonical_artifacts:
            errors.append("qualification evidence artifact metadata differs from canonical byte reconstruction")
    for artifact_type in sorted(_REQUIRED_ARTIFACT_TYPES):
        if len(by_type.get(artifact_type, [])) != 1:
            errors.append(f"qualification evidence package requires exactly one {artifact_type} artifact")
    protected_digests: dict[str, str] = {}
    for artifact_type in sorted(_PROTECTED_DIGEST_TYPES):
        for artifact in by_type.get(artifact_type, []):
            digest = str(artifact.get("sha256"))
            previous = protected_digests.get(digest)
            if previous is not None:
                errors.append(f"semantically distinct artifacts share a digest: {previous}, {artifact_type}")
            protected_digests[digest] = artifact_type
    run_bundles = by_type.get("qualification-run-bundle", [])
    run_checksums = by_type.get("qualification-run-checksums", [])
    if len(run_bundles) == 1 and len(run_checksums) == 1:
        run_root = Path(str(run_bundles[0]["relative_path"])).parent
        if Path(str(run_checksums[0]["relative_path"])).parent != run_root:
            errors.append("qualification run bundle and checksums do not share a directory")
        run_prefix = run_root.as_posix() + "/"
        for artifact in by_type.get("qualification-run-artifact", []):
            relative = str(artifact.get("relative_path", ""))
            if not relative.startswith(run_prefix):
                errors.append("qualification-run-artifact escapes the qualification run directory")
            elif relative == run_prefix + "verification.json":
                errors.append("qualification run verification.json must be regenerated, not packaged as evidence")
    return package_sha, manifest, by_path, by_type, errors


def _run_corpus_binding_errors(
    package: Path,
    run_root: Path,
    by_type: Mapping[str, list[dict[str, Any]]],
    *,
    blueprint: Mapping[str, Any] | None,
    source_identity: Mapping[str, Any] | None,
    corpus_identity: Mapping[str, Any] | None,
    report: Mapping[str, Any] | None,
) -> list[str]:
    errors: list[str] = []
    try:
        manifest_value = _strict_json_loads(_read_regular(run_root, Path("manifest.json")))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        return [f"qualification run manifest is not strict JSON: {exc}"]
    if not isinstance(manifest_value, dict):
        return ["qualification run manifest must be an object"]
    if (
        manifest_value.get("assurance") != "candidate"
        or manifest_value.get("official") is not False
        or manifest_value.get("official_requested") is not False
        or manifest_value.get("model_claim_allowed") is not False
        or manifest_value.get("benchmark_claim_allowed") is not False
    ):
        errors.append("qualification run must be candidate, non-official, non-rankable, and claim-free")
    run_suite = manifest_value.get("suite")
    corpus_config_artifact = by_type["corpus-suite-configuration"][0]
    if not isinstance(run_suite, dict) or corpus_identity is None:
        errors.append("qualification run suite identity is missing")
    else:
        expected_suite = {
            **corpus_identity,
            "suite_config_sha256": corpus_config_artifact["sha256"],
        }
        if any(run_suite.get(field) != value for field, value in expected_suite.items()):
            errors.append("qualification run suite identity does not bind the corpus package")
    target = manifest_value.get("target")
    responses_artifact = by_type["recorded-judge-responses"][0]
    if (
        not isinstance(target, dict)
        or target.get("kind") != "recorded"
        or target.get("recorded_responses_sha256") != responses_artifact["sha256"]
    ):
        errors.append("qualification run target does not bind the recorded response corpus")
    parameters = manifest_value.get("parameters")
    if isinstance(blueprint, Mapping) and isinstance(parameters, dict):
        for parameter, blueprint_field in (
            ("repetitions", "minimum_target_repetitions"),
            ("judge_repetitions", "minimum_judge_repetitions"),
        ):
            actual = parameters.get(parameter)
            minimum = blueprint.get(blueprint_field)
            if (
                not isinstance(actual, int)
                or isinstance(actual, bool)
                or not isinstance(minimum, int)
                or isinstance(minimum, bool)
                or actual < minimum
            ):
                errors.append(f"qualification run {parameter} does not satisfy the immutable blueprint")
    else:
        errors.append("qualification run parameters or immutable blueprint are missing")
    for run_name, artifact_type in (
        ("suite_snapshot.toml", "corpus-suite-configuration"),
        ("dataset_snapshot.jsonl", "corpus-dataset"),
        ("rubric_snapshot.md", "corpus-rubric"),
    ):
        artifact = by_type[artifact_type][0]
        try:
            observed = sha256_bytes(_read_regular(run_root, Path(run_name)))
        except OSError:
            errors.append(f"qualification run is missing {run_name}")
        else:
            if observed != artifact["sha256"]:
                errors.append(f"qualification run {run_name} differs from the corpus package")
    if report is not None:
        blueprint_artifact = by_type["qualification-blueprint"][0]
        blueprint_approval_artifact = by_type["qualification-blueprint-approval"][0]
        corpus_manifest_artifact = by_type["corpus-manifest"][0]
        corpus_dataset_artifact = by_type["corpus-dataset"][0]
        corpus_rubric_artifact = by_type["corpus-rubric"][0]
        try:
            run_manifest_sha256 = sha256_bytes(_read_regular(run_root, Path("manifest.json")))
        except OSError:
            errors.append("qualification run manifest changed while its report binding was checked")
        else:
            expected = {
                "run_manifest_sha256": run_manifest_sha256,
                "corpus_manifest_sha256": corpus_manifest_artifact["sha256"],
                "blueprint_sha256": blueprint_artifact["sha256"],
                "blueprint_approval_sha256": blueprint_approval_artifact["sha256"],
                "corpus_dataset_sha256": corpus_dataset_artifact["sha256"],
                "rubric_sha256": corpus_rubric_artifact["sha256"],
                "source_suite": source_identity,
                "judge_configuration": manifest_value.get("judge"),
            }
            if any(report.get(field) != value for field, value in expected.items()):
                errors.append(
                    "qualification report does not bind the exact run, corpus, rubric, blueprint, and judge configuration"
                )
    return errors


def _snapshot_staging_tree(root: Path) -> dict[str, bytes]:
    """Read an unbundled staging tree twice through the canonical regular-file boundary."""
    if root.is_symlink() or not root.is_dir():
        raise ProtocolError("qualification package staging root must be a regular directory")

    def read_once() -> dict[str, bytes]:
        paths: dict[str, Path] = {}
        folded: dict[str, str] = {}
        try:
            entries = sorted(root.rglob("*"))
            for path in entries:
                metadata = path.lstat()
                relative = path.relative_to(root).as_posix()
                if stat.S_ISDIR(metadata.st_mode):
                    continue
                if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                    raise OSError(f"staging artifact is not a unique regular file: {relative}")
                normalized = unicodedata.normalize("NFC", relative)
                collision = normalized.casefold()
                if normalized != relative or collision in folded:
                    raise OSError(f"staging artifact path is non-canonical or case-colliding: {relative}")
                folded[collision] = relative
                paths[relative] = path
            return {relative: _read_regular(root, path.relative_to(root)) for relative, path in paths.items()}
        except OSError as exc:
            raise ProtocolError(f"qualification package staging tree is unsafe: {exc}") from exc

    first = read_once()
    second = read_once()
    if first != second:
        raise ProtocolError("qualification package staging tree changed while it was snapshotted")
    forbidden = {QUALIFICATION_EVIDENCE_MANIFEST, "bundle.json", "checksums.txt", "signature.json", "verification.json"}
    present = sorted(forbidden & set(first))
    if present:
        raise ProtocolError(f"qualification package staging root contains generated control files: {present}")
    return first


def _package_artifacts(snapshot: Mapping[str, bytes]) -> list[dict[str, Any]]:
    """Classify the fixed production staging layout without trusting caller-provided artifact types."""
    specifications: dict[str, tuple[str, str, str | None]] = {}

    def media_type(relative: str) -> str:
        return {
            ".json": "application/json",
            ".jsonl": "application/x-ndjson",
            ".md": "text/markdown",
            ".toml": "application/toml",
            ".txt": "text/plain",
        }.get(Path(relative).suffix.lower(), "application/octet-stream")

    def require(relative: str, artifact_type: str, schema_version: str | None) -> str:
        failures: list[str] = []
        safe = _safe_relative(relative, artifact_type, failures)
        if safe is None or relative not in snapshot:
            detail = failures[0] if failures else f"missing staging artifact: {relative}"
            raise ProtocolError(detail)
        previous = specifications.get(relative)
        current = (artifact_type, media_type(relative), schema_version)
        if previous is not None and previous != current:
            raise ProtocolError(f"staging artifact has conflicting semantic roles: {relative}")
        specifications[relative] = current
        return relative

    def object_at(relative: str, label: str) -> dict[str, Any]:
        try:
            value = _strict_json_loads(snapshot[relative])
        except (KeyError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise ProtocolError(f"{label} is not strict JSON: {exc}") from exc
        if not isinstance(value, dict):
            raise ProtocolError(f"{label} must be a JSON object")
        return value

    def toml_at(relative: str, label: str) -> dict[str, Any]:
        try:
            value = tomllib.loads(snapshot[relative].decode("utf-8"))
        except (KeyError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
            raise ProtocolError(f"{label} is not TOML: {exc}") from exc
        return value

    def under(directory: str, value: Any, label: str) -> str:
        failures: list[str] = []
        safe = _safe_relative(value, label, failures)
        if safe is None:
            raise ProtocolError(failures[0])
        return (Path(directory) / safe).as_posix()

    source_config_path = require("source-suite/suite.toml", "source-suite-configuration", "2.0.0")
    source_config = toml_at(source_config_path, "source suite configuration")
    require(
        under("source-suite", source_config.get("dataset", "dataset.jsonl"), "source suite dataset path"),
        "source-suite-dataset",
        "2.0.0",
    )
    require(
        under("source-suite", source_config.get("rubric", "rubric.md"), "source suite rubric path"),
        "source-suite-rubric",
        None,
    )
    source_judge = source_config.get("judge")
    if not isinstance(source_judge, dict):
        raise ProtocolError("source suite must declare its qualification blueprint and approval")
    blueprint_path = require(
        under("source-suite", source_judge.get("qualification_blueprint"), "qualification blueprint path"),
        "qualification-blueprint",
        "1.0.0",
    )
    blueprint_approval_path = require(
        under(
            "source-suite",
            source_judge.get("qualification_blueprint_approval"),
            "qualification blueprint approval path",
        ),
        "qualification-blueprint-approval",
        "2.0.0",
    )

    corpus_config_path = require("corpus/suite.toml", "corpus-suite-configuration", "2.0.0")
    corpus_config = toml_at(corpus_config_path, "qualification corpus suite configuration")
    require(
        under("corpus", corpus_config.get("dataset", "dataset.jsonl"), "qualification corpus dataset path"),
        "corpus-dataset",
        "2.0.0",
    )
    require(
        under("corpus", corpus_config.get("rubric", "rubric.md"), "qualification corpus rubric path"),
        "corpus-rubric",
        None,
    )
    corpus_target = corpus_config.get("target")
    if not isinstance(corpus_target, dict) or corpus_target.get("kind") != "recorded":
        raise ProtocolError("qualification corpus staging suite must use a recorded target")
    require(
        under("corpus", corpus_target.get("responses"), "recorded judge responses path"),
        "recorded-judge-responses",
        "1.0.0",
    )
    require("corpus/corpus_manifest.json", "corpus-manifest", "1.0.0")
    source_items_path = require("corpus/source-items.jsonl", "corpus-source-items", "1.0.0")
    require("run/bundle.json", "qualification-run-bundle", "1.0.0")
    require("run/checksums.txt", "qualification-run-checksums", None)
    if "run/verification.json" in snapshot:
        raise ProtocolError("qualification run verification.json is derived and cannot enter the evidence package")
    report_path = require("qualification/report.json", "qualification-report", "2.0.0")
    qualification_approval_path = require("qualification/approval.json", "qualification-approval", "3.0.0")

    blueprint_approval = object_at(blueprint_approval_path, "qualification blueprint approval")
    qualification_approval = object_at(qualification_approval_path, "judge qualification approval")
    reviewer_paths: list[tuple[str, str, str]] = []
    for approval, artifact_type, label, namespace in (
        (
            blueprint_approval,
            "blueprint-approver-qualification",
            "blueprint approver qualification evidence",
            "source-suite",
        ),
        (qualification_approval, "judge-approver-qualification", "judge approver qualification evidence", ""),
    ):
        reference = approval.get("approver_qualification_evidence")
        if not isinstance(reference, dict):
            raise ProtocolError(f"{label} must be a hash-bound artifact reference")
        referenced = str(reference.get("relative_path", ""))
        relative = require(under(namespace, referenced, label) if namespace else referenced, artifact_type, "1.0.0")
        reviewer_paths.append((relative, label, namespace))
    for relative, label, namespace in reviewer_paths:
        reviewer = object_at(relative, label)
        supports = reviewer.get("supporting_evidence")
        if not isinstance(supports, list) or not supports:
            raise ProtocolError(f"{label} must reference supporting evidence")
        for reference in supports:
            if not isinstance(reference, dict):
                raise ProtocolError(f"{label} contains a malformed supporting-evidence reference")
            referenced = str(reference.get("relative_path", ""))
            require(
                under(namespace, referenced, f"{label} supporting evidence") if namespace else referenced,
                "reviewer-qualification-support",
                "1.0.0",
            )

    try:
        source_items = [
            _strict_json_loads(line)
            for line in snapshot[source_items_path].decode("utf-8").splitlines()
            if line.strip()
        ]
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ProtocolError(f"qualification corpus source items are not strict JSONL: {exc}") from exc
    if not all(isinstance(item, dict) for item in source_items):
        raise ProtocolError("qualification corpus source items must be JSON objects")
    digests = {relative: sha256_bytes(raw) for relative, raw in snapshot.items()}

    def evidence_for_digest(digest: Any, artifact_type: str) -> None:
        if not isinstance(digest, str) or _HASH.fullmatch(digest) is None:
            raise ProtocolError(f"{artifact_type} digest is invalid")
        candidates = [
            relative
            for relative, observed in digests.items()
            if observed == digest and relative.startswith("corpus/") and relative not in specifications
        ]
        if len(candidates) != 1:
            raise ProtocolError(f"{artifact_type} digest must resolve to exactly one corpus artifact")
        require(candidates[0], artifact_type, "1.0.0")

    for digest in sorted({item.get("source_run_manifest_sha256") for item in source_items if isinstance(item, dict)}, key=str):
        evidence_for_digest(digest, "corpus-source-run-manifest")
    for digest in sorted({item.get("gold_evidence_sha256") for item in source_items if isinstance(item, dict)}, key=str):
        evidence_for_digest(digest, "corpus-gold-evidence")

    for relative in sorted(snapshot):
        if relative in specifications:
            continue
        if relative.startswith("source-suite/"):
            specifications[relative] = ("source-suite-support", media_type(relative), None)
        elif relative.startswith("corpus/"):
            specifications[relative] = ("corpus-support", media_type(relative), None)
        elif relative.startswith("run/"):
            specifications[relative] = ("qualification-run-artifact", media_type(relative), None)
        else:
            raise ProtocolError(f"unrecognized artifact outside the canonical qualification staging layout: {relative}")

    if specifications[blueprint_path][0] != "qualification-blueprint":
        raise ProtocolError("qualification blueprint staging role is ambiguous")
    if specifications[report_path][0] != "qualification-report":
        raise ProtocolError("qualification report staging role is ambiguous")
    return [
        {
            "artifact_id": f"artifact-{index:03d}",
            "relative_path": relative,
            "sha256": sha256_bytes(snapshot[relative]),
            "artifact_type": artifact_type,
            "media_type": media,
            "schema_version": schema,
        }
        for index, (relative, (artifact_type, media, schema)) in enumerate(sorted(specifications.items()), 1)
    ]


def build_judge_qualification_package(
    staging_root: Path,
    output: Path,
    *,
    now: datetime,
    base_behavior_verifier: BaseBehaviorVerifier,
) -> QualificationVerification:
    """Build and reverify a package from a closed canonical staging tree.

    Required layout: ``source-suite/`` and ``corpus/`` contain their exact
    ``suite.toml`` trees, ``run/`` is the finalized qualification bundle,
    ``qualification/{report,approval}.json`` are separately approved evidence,
    and reviewer/support files use the package-relative paths bound by those
    approvals. Generated package control files must not be present in staging.
    """
    if now.tzinfo is None:
        raise ProtocolError("qualification package build time must include a timezone")
    staging = staging_root.resolve()
    destination = output.resolve()
    if output.exists() or output.is_symlink():
        raise ProtocolError(f"refusing to overwrite qualification evidence package: {output}")
    if destination == staging or destination.is_relative_to(staging):
        raise ProtocolError("qualification evidence package output must be outside its staging tree")
    snapshot = _snapshot_staging_tree(staging)
    artifacts = _package_artifacts(snapshot)
    output.parent.mkdir(parents=True, exist_ok=True)
    with TemporaryDirectory(prefix=".cavada-qualification-", dir=output.parent) as temporary:
        package = Path(temporary) / "package"
        package.mkdir(mode=0o700)
        for relative, raw in sorted(snapshot.items()):
            path = package / Path(relative)
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            path.write_bytes(raw)
            os.chmod(path, 0o600)
        atomic_json(
            package / QUALIFICATION_EVIDENCE_MANIFEST,
            {
                "package_version": QUALIFICATION_EVIDENCE_VERSION,
                "artifact_type": "judge-qualification-evidence-package",
                "protocol_version": PROTOCOL_VERSION,
                "created_at": now.isoformat().replace("+00:00", "Z"),
                "claim_scope": ["judge-qualification"],
                "artifacts": artifacts,
            },
        )
        write_bundle(package)
        result = reconstruct_judge_qualification(
            package,
            now=now,
            base_behavior_verifier=base_behavior_verifier,
        )
        verification = verify_bundle(package, verify_hmac=False)
        bundle_sha = sha256_bytes(_read_regular(package, Path("bundle.json")))
        if not result.valid or verification.get("valid") is not True or result.package_sha256 != bundle_sha:
            failures = result.failures or tuple(map(str, verification.get("failures", [])))
            raise ProtocolError("built judge qualification package is invalid:\n" + "\n".join(failures))
        lock_path = output.parent / f".{output.name}.publish.lock"
        try:
            lock_fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError as exc:
            raise ProtocolError(f"qualification evidence package publication is already in progress: {output}") from exc
        try:
            if output.exists() or output.is_symlink():
                raise ProtocolError(f"cannot publish qualification evidence package without overwriting: {output}")
            try:
                shutil.copytree(package, output, copy_function=shutil.copy2)
            except (FileExistsError, OSError) as exc:
                raise ProtocolError(
                    f"cannot publish qualification evidence package without overwriting: {output}"
                ) from exc
            directory_fd = os.open(output.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            os.close(lock_fd)
            lock_path.unlink(missing_ok=True)
        published = reconstruct_judge_qualification(
            output,
            now=now,
            base_behavior_verifier=base_behavior_verifier,
        )
        if published != result:
            raise ProtocolError("published judge qualification package differs from the verified package")
        return published


def reconstruct_judge_qualification(
    evidence_package: Path,
    *,
    now: datetime,
    base_behavior_verifier: BaseBehaviorVerifier,
) -> QualificationVerification:
    """Reconstruct qualification only from one hash-bound byte snapshot."""
    try:
        snapshot = snapshot_bundle_files(evidence_package, allow_verification=False, verify_hmac=False)
    except ProtocolError as exc:
        return QualificationVerification(None, None, False, False, False, (str(exc),), (), (), None)
    with TemporaryDirectory(prefix="cavada-qualification-snapshot-") as temporary:
        package = Path(temporary).resolve()
        for relative, raw in snapshot.items():
            destination = package / Path(relative)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(raw)
        return _reconstruct_judge_qualification_snapshot(
            package,
            now=now,
            base_behavior_verifier=base_behavior_verifier,
        )


def _reconstruct_judge_qualification_snapshot(
    evidence_package: Path,
    *,
    now: datetime,
    base_behavior_verifier: BaseBehaviorVerifier,
) -> QualificationVerification:
    """Reconstruct an exact qualification from an already immutable snapshot."""
    if now.tzinfo is None:
        return QualificationVerification(
            None,
            None,
            False,
            False,
            False,
            ("verification now must include a timezone",),
            (),
            (),
            None,
        )
    package = evidence_package
    package_sha, manifest, artifacts_by_path, by_type, integrity_errors = _package_integrity(package)
    package_version = manifest.get("package_version") if isinstance(manifest, dict) and isinstance(manifest.get("package_version"), str) else None
    if integrity_errors:
        return QualificationVerification(
            package_version,
            package_sha,
            False,
            False,
            False,
            _unique(integrity_errors),
            (),
            (),
            None,
        )
    assert manifest is not None
    semantic_errors: list[str] = []
    approval_errors: list[str] = []
    created_at = _aware_time(manifest.get("created_at"), "qualification evidence manifest.created_at", semantic_errors)
    if created_at is not None and created_at > now:
        semantic_errors.append("qualification evidence manifest.created_at is in the future")
    source_config_artifact = by_type["source-suite-configuration"][0]
    source_config_for_policy = _strict_toml(
        package,
        str(source_config_artifact["relative_path"]),
        "source suite configuration",
        approval_errors,
    )
    source_report = source_config_for_policy[0].get("report") if source_config_for_policy is not None else None
    allow_synthetic_fixture = (
        isinstance(source_report, dict)
        and source_report.get("assurance") == "conformance-fixture"
        and source_report.get("model_claim_allowed") is False
        and source_report.get("benchmark_claim_allowed") is False
    )

    try:
        corpus_result = _corpus_errors(package, by_type, artifacts_by_path, now=now)
    except (KeyError, OSError, ProtocolError, TypeError, ValueError) as exc:
        corpus_result = ([f"qualification corpus reconstruction failed: {exc}"], None, None, None, None, None, None)
    corpus_failures, source_identity, corpus_identity, blueprint_path, corpus_manifest_path, blueprint, corpus = corpus_result
    semantic_errors.extend(corpus_failures)
    reconstructed_report: dict[str, Any] | None = None
    report_artifact = by_type["qualification-report"][0]
    report = _strict_object(package, str(report_artifact["relative_path"]), "qualification report", semantic_errors)
    if report is not None:
        semantic_errors.extend(_qualification_structure_errors(report))

    run_bundle_artifact = by_type["qualification-run-bundle"][0]
    run_root = package / Path(str(run_bundle_artifact["relative_path"])).parent
    try:
        run_integrity = verify_bundle(run_root, verify_hmac=False)
    except ProtocolError as exc:
        semantic_errors.append(f"qualification run bundle is invalid: {exc}")
        run_integrity = {"valid": False}
    if run_integrity.get("valid") is not True:
        semantic_errors.append("qualification run bundle does not pass integrity verification")
    semantic_errors.extend(
        _run_corpus_binding_errors(
            package,
            run_root,
            by_type,
            blueprint=blueprint,
            source_identity=source_identity,
            corpus_identity=corpus_identity,
            report=report,
        )
    )
    try:
        base_result = base_behavior_verifier(run_root, now)
    except (OSError, ProtocolError, TypeError, ValueError) as exc:
        semantic_errors.append(f"qualification run base semantic verification failed: {exc}")
        base_result = {}
    if base_result.get("integrity_valid") is not True or base_result.get("semantic_valid") is not True:
        semantic_errors.append("qualification run did not pass base behavior semantic verification")

    if not semantic_errors and blueprint_path is not None and corpus_manifest_path is not None:
        try:
            with TemporaryDirectory(prefix="cavada-qualification-reconstruction-") as temporary:
                output = Path(temporary) / "qualification.json"
                reconstructed_report = qualify_judge_run(
                    run_root,
                    blueprint_path,
                    corpus_manifest_path,
                    output,
                    now=now,
                )
        except (OSError, ProtocolError, TypeError, ValueError) as exc:
            semantic_errors.append(f"qualification report reconstruction failed: {exc}")
        else:
            if reconstructed_report != report:
                semantic_errors.append("declared qualification report differs from byte-reconstructed report")
            if reconstructed_report.get("passed") is not True:
                semantic_errors.append("byte-reconstructed qualification gates did not pass")

    blueprint_artifact = by_type["qualification-blueprint"][0]
    blueprint_approval_artifact = by_type["qualification-blueprint-approval"][0]
    blueprint_approval = _strict_object(
        package,
        str(blueprint_approval_artifact["relative_path"]),
        "qualification blueprint approval",
        approval_errors,
    )
    blueprint_reviewer_artifact = by_type["blueprint-approver-qualification"][0]
    blueprint_reviewer = _strict_object(
        package,
        str(blueprint_reviewer_artifact["relative_path"]),
        "blueprint approver qualification evidence",
        approval_errors,
    )
    blueprint_reviewer_failures, blueprint_reviewer_period = _reviewer_errors(
        blueprint_reviewer,
        package=package,
        artifact=blueprint_reviewer_artifact,
        expected_role="blueprint-approver",
        expected_scope="judge-qualification-blueprint",
        artifacts_by_path=artifacts_by_path,
        now=now,
        namespace_prefix="source-suite/",
        allow_synthetic_fixture=allow_synthetic_fixture,
    )
    approval_errors.extend(blueprint_reviewer_failures)
    if blueprint_approval is not None:
        approval_errors.extend(
            _approval_errors(
                blueprint_approval,
                blueprint_reviewer,
                approval_artifact=blueprint_approval_artifact,
                subject_artifact=blueprint_artifact,
                reviewer_artifact=blueprint_reviewer_artifact,
                scope="judge-qualification-blueprint",
                approval_version="2.0.0",
                now=now,
                reviewer_period=blueprint_reviewer_period,
            )
        )
        if source_identity is not None and blueprint_approval.get("suite") != source_identity:
            approval_errors.append("qualification blueprint approval does not bind the source suite")

    qualification_approval_artifact = by_type["qualification-approval"][0]
    qualification_approval = _strict_object(
        package,
        str(qualification_approval_artifact["relative_path"]),
        "judge qualification approval",
        approval_errors,
    )
    judge_reviewer_artifact = by_type["judge-approver-qualification"][0]
    judge_reviewer = _strict_object(
        package,
        str(judge_reviewer_artifact["relative_path"]),
        "judge approver qualification evidence",
        approval_errors,
    )
    judge_reviewer_failures, judge_reviewer_period = _reviewer_errors(
        judge_reviewer,
        package=package,
        artifact=judge_reviewer_artifact,
        expected_role="judge-qualification-approver",
        expected_scope="judge-qualification",
        artifacts_by_path=artifacts_by_path,
        now=now,
        allow_synthetic_fixture=allow_synthetic_fixture,
    )
    approval_errors.extend(judge_reviewer_failures)
    if qualification_approval is not None:
        approval_errors.extend(
            _approval_errors(
                qualification_approval,
                judge_reviewer,
                approval_artifact=qualification_approval_artifact,
                subject_artifact=report_artifact,
                reviewer_artifact=judge_reviewer_artifact,
                scope="judge-qualification",
                approval_version="3.0.0",
                now=now,
                reviewer_period=judge_reviewer_period,
            )
        )
    if isinstance(blueprint_reviewer, dict) and isinstance(judge_reviewer, dict):
        blueprint_id = blueprint_reviewer.get("reviewer_id")
        judge_id = judge_reviewer.get("reviewer_id")
        if blueprint_id == judge_id:
            approval_errors.append("blueprint and judge qualification approvals require distinct reviewers")
        judge_configuration = reconstructed_report.get("judge_configuration") if isinstance(reconstructed_report, dict) else None
        model_rows = judge_configuration.get("models") if isinstance(judge_configuration, dict) else None
        model_identities = {
            str(value)
            for row in model_rows or []
            if isinstance(row, dict)
            for value in (row.get("id"), row.get("model"), row.get("expected_model"))
            if isinstance(value, str)
        }
        if blueprint_id in model_identities or judge_id in model_identities:
            approval_errors.append("approval reviewers must be independent of the qualified judge identities")

    run_manifest = _strict_object(run_root, "manifest.json", "qualification run manifest", semantic_errors)
    run_started = (
        _aware_time(run_manifest.get("started_at"), "qualification run started_at", approval_errors)
        if isinstance(run_manifest, dict)
        else None
    )
    run_finished = (
        _aware_time(run_manifest.get("finished_at"), "qualification run finished_at", approval_errors)
        if isinstance(run_manifest, dict)
        else None
    )
    corpus_frozen = (
        _aware_time(corpus.get("frozen_at"), "qualification corpus frozen_at", approval_errors)
        if isinstance(corpus, dict)
        else None
    )
    blueprint_approved = (
        _aware_time(blueprint_approval.get("approved_at"), "qualification blueprint approval.approved_at", approval_errors)
        if isinstance(blueprint_approval, dict)
        else None
    )
    qualification_approved = (
        _aware_time(qualification_approval.get("approved_at"), "judge qualification approval.approved_at", approval_errors)
        if isinstance(qualification_approval, dict)
        else None
    )
    if blueprint_approved is not None and corpus_frozen is not None and blueprint_approved > corpus_frozen:
        approval_errors.append("qualification blueprint approval must precede corpus freeze")
    if corpus_frozen is not None and run_started is not None and corpus_frozen > run_started:
        approval_errors.append("qualification corpus must be frozen before the qualification run starts")
    if run_finished is not None and qualification_approved is not None and qualification_approved < run_finished:
        approval_errors.append("judge qualification approval predates the completed qualification run")
    if created_at is not None and any(
        boundary is not None and created_at < boundary
        for boundary in (corpus_frozen, run_finished, qualification_approved)
    ):
        approval_errors.append("qualification evidence package was created before its subject evidence and approvals")

    try:
        final_integrity = verify_bundle(package, verify_hmac=False)
    except ProtocolError as exc:
        integrity_errors.append(f"qualification evidence package changed during reconstruction: {exc}")
    else:
        try:
            final_sha = sha256_bytes(_read_regular(package, Path("bundle.json")))
        except OSError as exc:
            integrity_errors.append(f"qualification evidence package changed during reconstruction: {exc}")
        else:
            if final_integrity.get("valid") is not True or final_sha != package_sha:
                integrity_errors.append("qualification evidence package changed during reconstruction")

    return QualificationVerification(
        package_version,
        package_sha,
        not integrity_errors,
        not semantic_errors,
        not approval_errors,
        _unique(integrity_errors),
        _unique(semantic_errors),
        _unique(approval_errors),
        reconstructed_report,
        str(by_type["source-suite-configuration"][0]["sha256"]),
    )
