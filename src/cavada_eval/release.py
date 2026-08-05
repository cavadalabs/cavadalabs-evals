from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .artifacts import verify_bundle
from .protocol import PROTOCOL_VERSION, ProtocolError, Suite, sha256_file

_PLACEHOLDERS = {"", "unavailable", "unassigned", "unassessed", "not-assessed", "replace-me"}
_PROHIBITED_CLAIM_FRAGMENTS = ("accredited", "certified", "legally compliant", "universally correct", "universally safe", "universally secure")
_DECISIONS = ("statistical", "security", "privacy_legal", "disclosure", "release")
_EVIDENCE = ("authorization", "conflict_assessment", "legal_applicability", "approver_qualification")


def _read_object(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ProtocolError(f"{label} must be a readable JSON object") from exc
    if not isinstance(value, dict):
        raise ProtocolError(f"{label} must be a readable JSON object")
    return value


def _time(value: Any, label: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError as exc:
        raise ProtocolError(f"{label} must be an ISO 8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise ProtocolError(f"{label} must include a timezone")
    return parsed


def _usable(value: Any) -> bool:
    return isinstance(value, str) and value.strip().casefold() not in _PLACEHOLDERS


def _evidence_error(container: Path, relative: Any, expected_hash: Any, label: str) -> str | None:
    if not _usable(relative) or not isinstance(expected_hash, str) or not re.fullmatch(r"[a-f0-9]{64}", expected_hash) or expected_hash == "0" * 64:
        return f"{label} path and non-placeholder SHA-256 are required"
    path = Path(str(relative))
    if path.is_absolute() or ".." in path.parts:
        return f"{label} path must stay inside its restricted evidence package"
    resolved = (container.parent / path).resolve()
    if not resolved.is_relative_to(container.parent.resolve()) or not resolved.is_file() or resolved.is_symlink():
        return f"{label} must be a regular file inside its restricted evidence package"
    if sha256_file(resolved) != expected_hash:
        return f"{label} hash mismatch"
    return None


def verified_engagement(
    path: Path,
    suite: Suite,
    *,
    expected_model: str,
    model_revision: str,
    now: datetime | None = None,
) -> dict[str, Any]:
    record = _read_object(path, "engagement governance record")
    now = now or datetime.now(timezone.utc)
    errors: list[str] = []
    if record.get("engagement_version") != "1.1.0" or record.get("status") != "approved":
        errors.append("engagement must be version 1.1.0 with approved status")
    approved_at = _time(record.get("approved_at"), "engagement approved_at")
    expires_at = _time(record.get("expires_at"), "engagement expires_at")
    if not approved_at <= now < expires_at:
        errors.append("engagement is not currently effective")
    expected_suite = {
        "protocol_version": PROTOCOL_VERSION,
        "name": suite.name,
        "version": suite.version,
        "dataset_sha256": sha256_file(suite.dataset_path),
        "rubric_sha256": sha256_file(suite.rubric_path),
        "suite_config_sha256": sha256_file(suite.root / "suite.toml"),
    }
    if record.get("suite") != expected_suite:
        errors.append("engagement does not match the exact suite configuration")
    expected_sut = {"expected_model": expected_model, "revision": model_revision}
    sut = record.get("sut")
    if not isinstance(sut, dict) or any(sut.get(key) != value for key, value in expected_sut.items()):
        errors.append("engagement does not match the exact SUT identity and revision")
    roles = record.get("cavadalabs_roles")
    if not isinstance(roles, list) or not {"evaluator", "testing-laboratory"} & set(map(str, roles)):
        errors.append("engagement must assign CavadaLabs an evaluator or testing-laboratory role")
    if record.get("conflicts_assessed") is not True:
        errors.append("engagement conflicts must be assessed")
    for field in ("counterparty_roles", "jurisdictions", "requested_claims"):
        values = record.get(field)
        if not isinstance(values, list) or not values or not all(_usable(item) for item in values):
            errors.append(f"engagement {field} is missing or contains placeholders")
    conflicts = record.get("conflicts")
    if not isinstance(conflicts, list) or any(not _usable(item) for item in conflicts):
        errors.append("engagement conflicts must be a reviewed array")
    for name in _EVIDENCE:
        error = _evidence_error(path, record.get(f"{name}_evidence"), record.get(f"{name}_evidence_sha256"), f"engagement {name} evidence")
        if error:
            errors.append(error)
    for field in (
        "engagement_id",
        "execution_owner_id",
        "commercial_owner_id",
        "scope",
        "system_owner_reference",
        "complaints_process_reference",
        "appeals_process_reference",
        "correction_revocation_reference",
        "disclosure_policy_reference",
        "approver_id",
    ):
        if not _usable(record.get(field)):
            errors.append(f"engagement {field} is missing or a placeholder")
    if record.get("approver_id") in {record.get("execution_owner_id"), record.get("commercial_owner_id")}:
        errors.append("engagement approver must be independent of execution and commercial ownership")
    if record.get("surveillance_required") is True and not _usable(record.get("surveillance_plan_reference")):
        errors.append("engagement requires a surveillance plan reference")
    permitted = record.get("permitted_claims")
    prohibited = record.get("prohibited_claims")
    if not isinstance(permitted, list) or not permitted or not all(_usable(item) for item in permitted):
        errors.append("engagement permitted claims are missing or contain placeholders")
        permitted = []
    if not isinstance(prohibited, list) or not prohibited or not all(_usable(item) for item in prohibited):
        errors.append("engagement prohibited claims are missing or contain placeholders")
        prohibited = []
    if {str(item).casefold() for item in permitted} & {str(item).casefold() for item in prohibited}:
        errors.append("engagement permitted and prohibited claims overlap")
    if any(fragment in str(claim).casefold() for claim in permitted for fragment in _PROHIBITED_CLAIM_FRAGMENTS):
        errors.append("engagement permits an unsupported certification, legal, or universal claim")
    if errors:
        raise ProtocolError("invalid engagement governance record:\n" + "\n".join(errors))
    return {
        "engagement_id": record["engagement_id"],
        "sha256": sha256_file(path),
        "status": record["status"],
        "cavadalabs_roles": roles,
        "jurisdictions": record.get("jurisdictions"),
        "permitted_claims": permitted,
        "prohibited_claims": prohibited,
        "execution_owner_id": record["execution_owner_id"],
        "commercial_owner_id": record["commercial_owner_id"],
        "approved_at": record["approved_at"],
        "expires_at": record["expires_at"],
        "authorization_evidence_sha256": record["authorization_evidence_sha256"],
        "conflict_assessment_evidence_sha256": record["conflict_assessment_evidence_sha256"],
        "legal_applicability_evidence_sha256": record["legal_applicability_evidence_sha256"],
        "approver_qualification_evidence_sha256": record["approver_qualification_evidence_sha256"],
    }


def verified_public_release(run_dir: Path, engagement_path: Path, approval_path: Path, *, now: datetime | None = None) -> dict[str, Any]:
    verification = verify_bundle(run_dir)
    if not verification["valid"]:
        raise ProtocolError("cannot release an invalid bundle")
    manifest = _read_object(run_dir / "manifest.json", "run manifest")
    if manifest.get("status") != "passed" or manifest.get("official") is not True or manifest.get("official_requested") is not True:
        raise ProtocolError("public release requires a passed official run")
    engagement = _read_object(engagement_path, "engagement governance record")
    recorded = manifest.get("engagement")
    if not isinstance(recorded, dict) or recorded.get("sha256") != sha256_file(engagement_path) or recorded.get("engagement_id") != engagement.get("engagement_id"):
        raise ProtocolError("release engagement does not match the run manifest")
    now = now or datetime.now(timezone.utc)
    if engagement.get("status") != "approved" or not _time(engagement.get("approved_at"), "engagement approved_at") <= now < _time(
        engagement.get("expires_at"), "engagement expires_at"
    ):
        raise ProtocolError("release engagement is not currently effective")
    engagement_evidence_errors = [
        error
        for name in _EVIDENCE
        if (error := _evidence_error(
            engagement_path,
            engagement.get(f"{name}_evidence"),
            engagement.get(f"{name}_evidence_sha256"),
            f"engagement {name} evidence",
        ))
    ]
    if engagement_evidence_errors:
        raise ProtocolError("invalid release engagement evidence:\n" + "\n".join(engagement_evidence_errors))

    approval = _read_object(approval_path, "release approval")
    errors: list[str] = []
    bundle_hash = sha256_file(run_dir / "bundle.json")
    expected = {
        "release_version": "1.0.0",
        "status": "approved",
        "run_id": manifest.get("run_id"),
        "bundle_sha256": bundle_hash,
        "manifest_sha256": sha256_file(run_dir / "manifest.json"),
        "engagement_id": engagement.get("engagement_id"),
        "engagement_sha256": sha256_file(engagement_path),
        "assurance_level": "approved",
    }
    for field, value in expected.items():
        if approval.get(field) != value:
            errors.append(f"release approval {field} does not match")
    if not _usable(approval.get("release_id")):
        errors.append("release approval release_id is missing or a placeholder")
    approved_at = _time(approval.get("approved_at"), "release approved_at")
    expires_at = _time(approval.get("expires_at"), "release expires_at")
    finished_at = _time(manifest.get("finished_at"), "run finished_at")
    engagement_expiry = _time(engagement.get("expires_at"), "engagement expires_at")
    if not finished_at <= approved_at <= now < expires_at <= engagement_expiry:
        errors.append("release approval timing is invalid or outside the engagement validity period")
    claims = approval.get("permitted_claims")
    engagement_claims = set(map(str, engagement.get("permitted_claims", [])))
    if not isinstance(claims, list) or not claims or not set(map(str, claims)) <= engagement_claims:
        errors.append("release claims are empty or exceed the approved engagement claims")
    if approval.get("limitations_acknowledged") is not True:
        errors.append("release approval must acknowledge the report limitations")
    decisions = approval.get("decisions")
    reviewers: dict[str, str] = {}
    decision_statuses: dict[str, str] = {}
    owners = {engagement.get("execution_owner_id"), engagement.get("commercial_owner_id")}
    if not isinstance(decisions, dict) or set(decisions) != set(_DECISIONS):
        errors.append("release approval requires the exact statistical, security, privacy_legal, disclosure, and release decisions")
    else:
        for name in _DECISIONS:
            decision = decisions[name]
            allowed_status = {"passed", "not-applicable"} if name == "privacy_legal" else {"passed"}
            if not isinstance(decision, dict) or decision.get("status") not in allowed_status or decision.get("independent") is not True:
                errors.append(f"release {name} decision did not pass independent review")
                continue
            reviewer = decision.get("reviewer_id")
            if not _usable(reviewer) or reviewer in owners:
                errors.append(f"release {name} reviewer is missing or not independent of execution/commercial ownership")
            else:
                reviewers[name] = str(reviewer)
            decision_statuses[name] = str(decision["status"])
            if not _usable(decision.get("rationale")):
                errors.append(f"release {name} decision lacks rationale")
            for evidence_name in ("review", "qualification"):
                error = _evidence_error(
                    approval_path,
                    decision.get(f"{evidence_name}_evidence"),
                    decision.get(f"{evidence_name}_evidence_sha256"),
                    f"release {name} {evidence_name} evidence",
                )
                if error:
                    errors.append(error)
            conflicts = decision.get("conflicts")
            if not isinstance(conflicts, list):
                errors.append(f"release {name} conflicts must be an array")
            elif conflicts and not _usable(decision.get("conflict_mitigation")):
                errors.append(f"release {name} conflicts require documented mitigation")
    if reviewers.get("release") in {value for key, value in reviewers.items() if key != "release"}:
        errors.append("release decision maker must be distinct from the technical, legal/privacy, and disclosure reviewers")
    if errors:
        raise ProtocolError("invalid public release approval:\n" + "\n".join(errors))
    return {
        "release_version": "1.0.0",
        "release_id": approval.get("release_id"),
        "run_id": manifest["run_id"],
        "bundle_sha256": bundle_hash,
        "manifest_sha256": expected["manifest_sha256"],
        "engagement_id": engagement["engagement_id"],
        "engagement_sha256": expected["engagement_sha256"],
        "approval_sha256": sha256_file(approval_path),
        "assurance_level": "approved",
        "permitted_claims": claims,
        "decision_statuses": decision_statuses,
        "approved_at": approval["approved_at"],
        "expires_at": approval["expires_at"],
    }
