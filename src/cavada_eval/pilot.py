from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .artifacts import verify_bundle
from .calibration import judge_evidence_errors, judge_signature
from .protocol import ProtocolError, atomic_json, sha256_file


def _json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ProtocolError(f"cannot read {label}: {exc}") from exc
    if not isinstance(value, dict):
        raise ProtocolError(f"{label} must be a JSON object")
    return value


def _evidence(campaign_root: Path, record: Any, label: str, errors: list[str]) -> dict[str, Any] | None:
    if not isinstance(record, dict) or not isinstance(record.get("path"), str) or not isinstance(record.get("sha256"), str):
        errors.append(f"{label} path and sha256 are required")
        return None
    path = (campaign_root / record["path"]).resolve()
    if not path.is_file():
        errors.append(f"{label} file is missing")
        return None
    if sha256_file(path) != record["sha256"]:
        errors.append(f"{label} hash mismatch")
        return None
    try:
        return _json(path, label)
    except ProtocolError as exc:
        errors.append(str(exc))
        return None


def audit_pilot_campaign(campaign_path: Path, output: Path) -> dict[str, Any]:
    campaign_path = campaign_path.resolve()
    output = output.resolve()
    if output.exists():
        raise ProtocolError(f"pilot audit output already exists: {output}")
    campaign = _json(campaign_path, "pilot campaign")
    if campaign.get("campaign_version") != "1.0.0":
        raise ProtocolError("pilot campaign_version must be 1.0.0")
    suite = campaign.get("suite")
    requirements = campaign.get("requirements")
    runs = campaign.get("runs")
    if not isinstance(suite, dict) or not isinstance(requirements, dict) or not isinstance(runs, list):
        raise ProtocolError("pilot campaign requires suite, requirements, and runs")
    suite_fields = ("name", "version", "dataset_sha256", "rubric_sha256", "suite_config_sha256")
    if not all(isinstance(suite.get(field), str) and suite[field] for field in suite_fields):
        raise ProtocolError("pilot suite identity is incomplete")
    numeric_requirements = (
        "minimum_model_families",
        "minimum_target_repetitions",
        "minimum_judge_repetitions",
        "evaluation_cases",
        "independent_scenarios",
    )
    if not all(isinstance(requirements.get(field), int) and not isinstance(requirements[field], bool) and requirements[field] > 0 for field in numeric_requirements):
        raise ProtocolError("pilot numeric requirements must be positive integers")
    positive_min = requirements.get("positive_control_min_pass_rate")
    negative_max = requirements.get("negative_control_max_pass_rate")
    if (
        not isinstance(positive_min, (int, float))
        or isinstance(positive_min, bool)
        or not isinstance(negative_max, (int, float))
        or isinstance(negative_max, bool)
        or not 0 <= float(negative_max) < float(positive_min) <= 1
    ):
        raise ProtocolError("pilot control pass-rate thresholds are invalid")

    errors: list[str] = []
    campaign_root = campaign_path.parent
    qualification = _evidence(campaign_root, campaign.get("judge_qualification"), "judge qualification", errors)
    approval = _evidence(campaign_root, campaign.get("judge_independent_approval"), "judge independent approval", errors)
    transcript = _evidence(campaign_root, campaign.get("transcript_review"), "transcript review", errors)
    if transcript is not None:
        reviewer_count = transcript.get("independent_reviewers")
        if (
            transcript.get("status") != "passed"
            or transcript.get("identity_blinded") is not True
            or not isinstance(reviewer_count, int)
            or isinstance(reviewer_count, bool)
            or reviewer_count < 2
            or transcript.get("separate_adjudicator") is not True
        ):
            errors.append("transcript review is incomplete or not independent and blinded")

    roles: dict[str, list[dict[str, Any]]] = {"target": [], "positive-control": [], "negative-control": []}
    run_paths: set[Path] = set()
    run_ids: set[str] = set()
    judge_signatures: set[str] = set()
    execution_signatures: set[str] = set()
    source_commits: set[str] = set()
    artifact_versions: set[tuple[str, ...]] = set()
    expected_judge_configuration: dict[str, Any] | None = None
    target_identities: set[tuple[str, str]] = set()
    summaries: list[dict[str, Any]] = []
    expected_suite = {field: suite[field] for field in suite_fields}
    for index, record in enumerate(runs, 1):
        if not isinstance(record, dict):
            raise ProtocolError(f"pilot run {index} must be an object")
        role = record.get("role")
        alias = record.get("family_alias")
        relative = record.get("path")
        if role not in roles or not isinstance(alias, str) or not alias or not isinstance(relative, str) or not relative:
            raise ProtocolError(f"pilot run {index} has invalid role, family_alias, or path")
        roles[str(role)].append(record)
        run_path = (campaign_root / relative).resolve()
        if run_path in run_paths:
            errors.append(f"pilot run path is repeated: {relative}")
            continue
        run_paths.add(run_path)
        try:
            verification = verify_bundle(run_path)
        except ProtocolError as exc:
            errors.append(f"pilot run bundle is invalid: {relative}: {exc}")
            continue
        if not verification["valid"]:
            errors.append(f"pilot run bundle is invalid: {relative}")
            continue
        manifest = _json(run_path / "manifest.json", f"pilot run {relative}")
        run_id = str(manifest.get("run_id", ""))
        if not run_id or run_id in run_ids:
            errors.append(f"pilot run_id is missing or repeated: {relative}")
        run_ids.add(run_id)
        actual_suite = manifest.get("suite") or {}
        if any(actual_suite.get(field) != expected for field, expected in expected_suite.items()):
            errors.append(f"pilot run suite identity mismatch: {relative}")
        parameters = manifest.get("parameters") or {}
        metrics = manifest.get("metrics") or {}
        target_repetitions = parameters.get("repetitions")
        judge_repetitions = parameters.get("judge_repetitions")
        if (
            parameters.get("max_cases") != 0
            or not isinstance(target_repetitions, int)
            or isinstance(target_repetitions, bool)
            or target_repetitions < requirements["minimum_target_repetitions"]
            or not isinstance(judge_repetitions, int)
            or isinstance(judge_repetitions, bool)
            or judge_repetitions < requirements["minimum_judge_repetitions"]
        ):
            errors.append(f"pilot run is partial or under-repeated: {relative}")
        if (
            metrics.get("analysis_unit") != "scenario"
            or metrics.get("evaluation_cases") != requirements["evaluation_cases"]
            or metrics.get("total") != requirements["independent_scenarios"]
        ):
            errors.append(f"pilot run analysis-unit counts mismatch: {relative}")
        integrity_counts = tuple(metrics.get(field) for field in ("invalid", "error", "skipped"))
        if any(not isinstance(value, int) or isinstance(value, bool) or value != 0 for value in integrity_counts):
            errors.append(f"pilot run contains invalid, error, or skipped scenarios: {relative}")
        if manifest.get("status") not in {"passed", "failed"} or manifest.get("abort_reason") or not manifest.get("finished_at"):
            errors.append(f"pilot run is aborted or unfinished: {relative}")
        artifact_versions.add(
            tuple(
                str(manifest.get(field, ""))
                for field in ("protocol_version", "schema_version", "report_version", "metric_version", "adapter_contract_version")
            )
        )
        manifest_judge = manifest.get("judge")
        judge_signatures.add(judge_signature(manifest_judge))
        if isinstance(manifest_judge, dict):
            expected_judge_configuration = manifest_judge
        execution = {
            field: parameters.get(field)
            for field in ("mode", "repetitions", "judge_repetitions", "timeout_seconds", "concurrency", "requests_per_second", "case_order_sha256")
        }
        case_order_sha256 = execution["case_order_sha256"]
        if (
            not isinstance(execution["mode"], str)
            or not execution["mode"]
            or not isinstance(execution["timeout_seconds"], (int, float))
            or isinstance(execution["timeout_seconds"], bool)
            or float(execution["timeout_seconds"]) <= 0
            or not isinstance(execution["concurrency"], int)
            or isinstance(execution["concurrency"], bool)
            or execution["concurrency"] <= 0
            or not isinstance(execution["requests_per_second"], (int, float))
            or isinstance(execution["requests_per_second"], bool)
            or float(execution["requests_per_second"]) < 0
            or not isinstance(case_order_sha256, str)
            or len(case_order_sha256) != 64
            or any(character not in "0123456789abcdef" for character in case_order_sha256)
        ):
            errors.append(f"pilot run execution configuration is incomplete: {relative}")
        else:
            execution_signatures.add(json.dumps(execution, sort_keys=True))
        source = manifest.get("source") or {}
        if source.get("dirty") is not False or not source.get("commit"):
            errors.append(f"pilot run source is dirty or uncommitted: {relative}")
        source_commits.add(str(source.get("commit", "")))
        target = manifest.get("target") or {}
        identity = (str(target.get("expected_reported_model", "")), str(target.get("revision", "")))
        if not all(identity):
            errors.append(f"pilot target identity is incomplete: {relative}")
        if role == "target":
            if identity in target_identities:
                errors.append(f"pilot target identity is repeated: {relative}")
            target_identities.add(identity)
        pass_rate = metrics.get("pass_rate")
        if role in {"positive-control", "negative-control"}:
            if not isinstance(pass_rate, (int, float)) or isinstance(pass_rate, bool):
                errors.append(f"{role} has no valid pass rate: {relative}")
            elif role == "positive-control" and float(pass_rate) < float(positive_min):
                errors.append(f"positive control did not meet its pass-rate threshold: {relative}")
            elif role == "negative-control" and float(pass_rate) > float(negative_max):
                errors.append(f"negative control did not meet its pass-rate threshold: {relative}")
        summaries.append({"run_id": run_id, "role": role, "family_alias": alias, "target": target, "pass_rate": pass_rate, "bundle_sha256": sha256_file(run_path / "bundle.json")})

    target_aliases = {str(record["family_alias"]) for record in roles["target"]}
    if len(target_aliases) < requirements["minimum_model_families"]:
        errors.append("pilot campaign has too few unrelated target model families")
    if not roles["positive-control"] or not roles["negative-control"]:
        errors.append("pilot campaign requires positive and negative control runs")
    if len(judge_signatures) != 1 or "" in judge_signatures:
        errors.append("pilot runs do not share one complete judge configuration")
    if len(execution_signatures) != 1:
        errors.append("pilot runs do not share one execution configuration")
    if len(source_commits) != 1 or "" in source_commits:
        errors.append("pilot runs do not share one clean source commit")
    if len(artifact_versions) != 1 or any(not value for value in next(iter(artifact_versions), ())):
        errors.append("pilot runs do not share one complete protocol and artifact version set")
    if qualification is not None and approval is not None and len(judge_signatures) == 1 and expected_judge_configuration is not None:
        qualification_record = campaign.get("judge_qualification") or {}
        errors.extend(
            judge_evidence_errors(
                qualification,
                approval,
                qualification_sha256=str(qualification_record.get("sha256", "")),
                expected_judge=expected_judge_configuration,
                rubric_sha256=str(suite["rubric_sha256"]),
            )
        )
    report = {
        "pilot_audit_version": "1.0.0",
        "passed": not errors,
        "campaign_sha256": sha256_file(campaign_path),
        "suite": suite,
        "requirements": requirements,
        "runs": summaries,
        "role_counts": {role: len(records) for role, records in roles.items()},
        "errors": errors,
        "limitations": [
            "Model-family independence and reviewer competence remain accountable external assertions.",
            "Pilot evidence is development evidence and cannot approve a model or create an official benchmark claim.",
        ],
    }
    atomic_json(output, report)
    return report
