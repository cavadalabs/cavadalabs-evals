from __future__ import annotations

import json
import math
import tomllib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .artifacts import verify_bundle
from .protocol import ProtocolError, _closed_object_errors, _strict_json_loads, atomic_json, sha256_bytes, sha256_file

_JUDGE_FIELDS = {
    "requested_model",
    "expected_reported_model",
    "revision",
    "endpoint",
    "prompt_sha256",
    "response_schema",
    "temperature",
    "models",
    "consensus",
}
_CALIBRATION_RESULT_FIELDS = {
    "true_pass",
    "true_fail",
    "false_pass",
    "false_fail",
    "cases",
    "samples",
    "invalid_cases",
    "observations",
    "accuracy",
    "failure_sensitivity",
    "failure_sensitivity_ci",
    "pass_specificity",
    "pass_specificity_ci",
    "false_pass_rate",
    "false_fail_rate",
    "balanced_accuracy",
    "repeated_cases",
    "stable_repeated_case_fraction",
}


def judge_signature(judge: Any) -> str:
    if not isinstance(judge, dict):
        return ""
    text_fields = ("requested_model", "expected_reported_model", "revision", "endpoint", "prompt_sha256", "response_schema")
    models = judge.get("models")
    if (
        set(judge) != _JUDGE_FIELDS
        or not all(isinstance(judge.get(field), str) and judge[field] for field in text_fields)
        or not isinstance(judge.get("temperature"), (int, float))
        or isinstance(judge.get("temperature"), bool)
        or not isinstance(models, list)
        or not models
        or not all(
            isinstance(model, dict)
            and set(model) == {"id", "model", "expected_model", "revision"}
            and all(isinstance(model.get(field), str) and model[field] for field in ("id", "model", "expected_model", "revision"))
            for model in models
        )
        or judge.get("consensus") not in {"majority", "unanimous"}
    ):
        return ""
    fields = (*text_fields, "temperature", "models", "consensus")
    return json.dumps({field: judge.get(field) for field in fields}, sort_keys=True, separators=(",", ":"))


def _qualification_structure_errors(qualification: Any) -> list[str]:
    fields = {
        "qualification_version",
        "passed",
        "run_manifest_sha256",
        "bundle_verification",
        "corpus_manifest_sha256",
        "blueprint_sha256",
        "blueprint_approval_sha256",
        "source_suite",
        "corpus_dataset_sha256",
        "judge_configuration",
        "rubric_sha256",
        "judges",
        "limitations",
    }
    errors: list[str] = []

    def exact(value: Any, expected: set[str], label: str) -> bool:
        errors.extend(_closed_object_errors(value, expected, label))
        if not isinstance(value, dict):
            return False
        missing = sorted(expected - set(value))
        if missing:
            errors.append(f"{label} is missing fields: {missing}")
        return not missing

    def number(value: Any) -> bool:
        return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(float(value))

    def integer(value: Any, minimum: int = 0) -> bool:
        return isinstance(value, int) and not isinstance(value, bool) and value >= minimum

    def rate(value: Any) -> bool:
        return number(value) and 0 <= float(value) <= 1

    def digest(value: Any) -> bool:
        return isinstance(value, str) and len(value) == 64 and all(character in "0123456789abcdef" for character in value)

    def interval(value: Any, label: str, *, nullable: bool = False) -> bool:
        if nullable and value is None:
            return True
        if not exact(value, {"lower", "upper", "confidence"}, label):
            return False
        assert isinstance(value, dict)
        if not number(value["lower"]) or not number(value["upper"]) or not number(value["confidence"]):
            errors.append(f"{label} values must be finite numbers")
            return False
        if not 0 <= float(value["lower"]) <= float(value["upper"]) <= 1:
            errors.append(f"{label} bounds must be ordered rates")
            return False
        if not 0 < float(value["confidence"]) < 1:
            errors.append(f"{label}.confidence must be between zero and one")
            return False
        return True

    exact(qualification, fields, "judge qualification")
    if not isinstance(qualification, dict):
        return errors
    if qualification.get("qualification_version") != "2.0.0" or not isinstance(qualification.get("passed"), bool):
        errors.append("judge qualification version or passed flag is invalid")
    for field in (
        "run_manifest_sha256",
        "corpus_manifest_sha256",
        "blueprint_sha256",
        "blueprint_approval_sha256",
        "corpus_dataset_sha256",
        "rubric_sha256",
    ):
        if not digest(qualification.get(field)):
            errors.append(f"judge qualification.{field} must be a SHA-256 digest")
    limitations = qualification.get("limitations")
    if not isinstance(limitations, list) or not limitations or not all(isinstance(item, str) and item for item in limitations):
        errors.append("judge qualification.limitations must contain non-empty strings")

    source_suite = qualification.get("source_suite")
    if exact(source_suite, {"name", "version", "dataset_sha256", "rubric_sha256"}, "judge qualification.source_suite"):
        assert isinstance(source_suite, dict)
        version = source_suite["version"]
        if (
            not isinstance(source_suite["name"], str)
            or not source_suite["name"]
            or not isinstance(version, str)
            or len(version.split(".")) != 3
            or not all(part.isdigit() for part in version.split("."))
            or not digest(source_suite["dataset_sha256"])
            or not digest(source_suite["rubric_sha256"])
        ):
            errors.append("judge qualification.source_suite is invalid")

    verification = qualification.get("bundle_verification")
    if exact(verification, {"valid", "failures", "signature", "files"}, "judge qualification.bundle_verification"):
        assert isinstance(verification, dict)
        failures = verification["failures"]
        if (
            not isinstance(verification["valid"], bool)
            or not isinstance(failures, list)
            or not all(isinstance(item, str) and item for item in failures)
            or verification["signature"] not in {"absent", "unverified", "valid", "invalid"}
            or not integer(verification["files"], 1)
        ):
            errors.append("judge qualification.bundle_verification is invalid")
        elif verification["valid"] is True and verification["failures"]:
            errors.append("judge qualification.bundle_verification cannot be valid with failures")

    configuration = qualification.get("judge_configuration")
    exact(configuration, _JUDGE_FIELDS, "judge qualification.judge_configuration")
    if isinstance(configuration, dict) and isinstance(configuration.get("models"), list):
        for index, model in enumerate(configuration["models"]):
            exact(model, {"id", "model", "expected_model", "revision"}, f"judge qualification.judge_configuration.models[{index}]")
    if not judge_signature(configuration):
        errors.append("judge qualification.judge_configuration is invalid")
    elif isinstance(configuration, dict):
        if not digest(configuration["prompt_sha256"]) or not 0 <= float(configuration["temperature"]) <= 2:
            errors.append("judge qualification.judge_configuration hash or temperature is invalid")

    judges = qualification.get("judges")
    if not isinstance(judges, dict) or not judges:
        return [*errors, "judge qualification.judges must be a non-empty object"]
    configured_ids = {
        str(model["id"])
        for model in (configuration.get("models", []) if isinstance(configuration, dict) else [])
        if isinstance(model, dict) and isinstance(model.get("id"), str) and model["id"]
    }
    if set(judges) != configured_ids:
        errors.append("judge qualification.judges must exactly match judge_configuration model ids")
    full_module = {
        "passed",
        "cases",
        "expected_cases",
        "invalid_cases",
        "failure_sensitivity_ci",
        "failure_sensitivity_gate",
        "pass_specificity_ci",
        "pass_specificity_gate",
    }
    for judge_id, result in judges.items():
        label = f"judge qualification.judges.{judge_id}"
        if not exact(result, {"passed", "checks", "modules", "diagnostic_slices"}, label):
            continue
        assert isinstance(result, dict)
        if not isinstance(result["passed"], bool):
            errors.append(f"{label}.passed must be boolean")
        checks = result.get("checks")
        if not isinstance(checks, list):
            errors.append(f"{label}.checks must be an array")
        else:
            check_names: list[Any] = []
            for index, check in enumerate(checks):
                check_label = f"{label}.checks[{index}]"
                if exact(check, {"name", "passed"}, check_label):
                    assert isinstance(check, dict)
                    check_names.append(check["name"])
                    if check["name"] not in {"all_modules", "invalid_cases", "judge_repetitions", "repeat_stability"} or not isinstance(
                        check["passed"], bool
                    ):
                        errors.append(f"{check_label} is invalid")
            expected_checks = {"all_modules", "invalid_cases", "judge_repetitions", "repeat_stability"}
            if len(check_names) != len(expected_checks) or any(check_names.count(name) != 1 for name in expected_checks):
                errors.append(f"{label}.checks must contain each required check exactly once")
            if qualification.get("passed") is True and any(not isinstance(check, dict) or check.get("passed") is not True for check in checks):
                errors.append(f"{label}.checks must all pass when the qualification passed")
        modules = result.get("modules")
        if not isinstance(modules, dict):
            errors.append(f"{label}.modules must be an object")
        else:
            for module_id, module in modules.items():
                module_label = f"{label}.modules.{module_id}"
                if not isinstance(module, dict):
                    errors.append(f"{module_label} must be an object")
                    continue
                if set(module) == {"passed", "reason"}:
                    if not isinstance(module["passed"], bool) or not isinstance(module["reason"], str) or not module["reason"]:
                        errors.append(f"{module_label} is invalid")
                    elif module["passed"] is True:
                        errors.append(f"{module_label} cannot pass without quantitative evidence")
                elif set(module) == full_module:
                    valid_shape = not (
                        not isinstance(module["passed"], bool)
                        or not integer(module["cases"])
                        or not integer(module["expected_cases"], 1)
                        or not integer(module["invalid_cases"])
                        or not rate(module["failure_sensitivity_gate"])
                        or not rate(module["pass_specificity_gate"])
                    )
                    if not valid_shape:
                        errors.append(f"{module_label} is invalid")
                    sensitivity_valid = interval(
                        module["failure_sensitivity_ci"], f"{module_label}.failure_sensitivity_ci", nullable=True
                    )
                    specificity_valid = interval(
                        module["pass_specificity_ci"], f"{module_label}.pass_specificity_ci", nullable=True
                    )
                    if valid_shape and module["passed"] is True:
                        sensitivity = module["failure_sensitivity_ci"]
                        specificity = module["pass_specificity_ci"]
                        if (
                            module["cases"] != module["expected_cases"]
                            or module["cases"] <= 0
                            or module["invalid_cases"] != 0
                            or not sensitivity_valid
                            or not specificity_valid
                            or not isinstance(sensitivity, dict)
                            or not isinstance(specificity, dict)
                            or float(sensitivity["lower"]) < float(module["failure_sensitivity_gate"])
                            or float(specificity["lower"]) < float(module["pass_specificity_gate"])
                        ):
                            errors.append(f"{module_label} passed flag conflicts with quantitative evidence")
                else:
                    errors.extend(_closed_object_errors(module, full_module | {"reason"}, module_label))
                    errors.append(f"{module_label} fields do not match a qualification result")
        if qualification.get("passed") is True and (
            result.get("passed") is not True
            or not modules
            or not isinstance(modules, dict)
            or any(not isinstance(module, dict) or module.get("passed") is not True for module in modules.values())
        ):
            errors.append(f"{label}.modules must be non-empty and all pass when the qualification passed")
        slices = result.get("diagnostic_slices")
        if not isinstance(slices, dict):
            errors.append(f"{label}.diagnostic_slices must be an object")
        else:
            for dimension, values in slices.items():
                if not isinstance(values, dict):
                    errors.append(f"{label}.diagnostic_slices.{dimension} must be an object")
                    continue
                for value, measured in values.items():
                    measured_label = f"{label}.diagnostic_slices.{dimension}.{value}"
                    if not exact(measured, _CALIBRATION_RESULT_FIELDS, measured_label):
                        continue
                    assert isinstance(measured, dict)
                    count_fields = {
                        "true_pass",
                        "true_fail",
                        "false_pass",
                        "false_fail",
                        "cases",
                        "samples",
                        "invalid_cases",
                        "observations",
                        "repeated_cases",
                    }
                    if not all(integer(measured[field]) for field in count_fields) or not rate(measured["accuracy"]):
                        errors.append(f"{measured_label} counts or accuracy are invalid")
                    for field in (
                        "failure_sensitivity",
                        "pass_specificity",
                        "false_pass_rate",
                        "false_fail_rate",
                        "balanced_accuracy",
                        "stable_repeated_case_fraction",
                    ):
                        if measured[field] is not None and not rate(measured[field]):
                            errors.append(f"{measured_label}.{field} must be null or a rate")
                    interval(measured["failure_sensitivity_ci"], f"{measured_label}.failure_sensitivity_ci", nullable=True)
                    interval(measured["pass_specificity_ci"], f"{measured_label}.pass_specificity_ci", nullable=True)
    return errors


def judge_evidence_errors(
    qualification: Any,
    approval: Any,
    *,
    qualification_sha256: str,
    expected_judge: Any,
    rubric_sha256: str,
    expected_blueprint_sha256: str | None = None,
    expected_blueprint_approval_sha256: str | None = None,
    now: datetime | None = None,
) -> list[str]:
    errors = _qualification_structure_errors(qualification)
    hashes = (
        "run_manifest_sha256",
        "corpus_manifest_sha256",
        "blueprint_sha256",
        "blueprint_approval_sha256",
        "corpus_dataset_sha256",
    )
    judges = qualification.get("judges") if isinstance(qualification, dict) else None
    source_suite = qualification.get("source_suite") if isinstance(qualification, dict) else None
    if (
        not isinstance(qualification, dict)
        or qualification.get("qualification_version") != "2.0.0"
        or qualification.get("passed") is not True
        or qualification.get("rubric_sha256") != rubric_sha256
        or not isinstance(source_suite, dict)
        or set(source_suite) != {"name", "version", "dataset_sha256", "rubric_sha256"}
        or not all(
            isinstance(source_suite.get(field), str) and source_suite[field]
            for field in ("name", "version")
        )
        or not all(
            isinstance(source_suite.get(field), str)
            and len(source_suite[field]) == 64
            and all(character in "0123456789abcdef" for character in source_suite[field])
            for field in ("dataset_sha256", "rubric_sha256")
        )
        or source_suite.get("rubric_sha256") != rubric_sha256
        or not isinstance(qualification.get("bundle_verification"), dict)
        or qualification["bundle_verification"].get("valid") is not True
        or not all(
            isinstance(qualification.get(field), str)
            and len(qualification[field]) == 64
            and all(character in "0123456789abcdef" for character in qualification[field])
            for field in hashes
        )
        or not isinstance(judges, dict)
        or not judges
        or not all(isinstance(result, dict) and result.get("passed") is True for result in judges.values())
    ):
        errors.append("judge qualification report is incomplete or did not pass")
    if expected_blueprint_sha256 is not None and qualification.get("blueprint_sha256") != expected_blueprint_sha256:
        errors.append("judge qualification does not match the suite-pinned blueprint")
    if (
        expected_blueprint_approval_sha256 is not None
        and qualification.get("blueprint_approval_sha256") != expected_blueprint_approval_sha256
    ):
        errors.append("judge qualification does not match the suite-pinned blueprint approval")
    qualification_judge = qualification.get("judge_configuration") if isinstance(qualification, dict) else None
    if judge_signature(qualification_judge) != judge_signature(expected_judge) or not judge_signature(expected_judge):
        errors.append("judge qualification does not match the exact run configuration")
    approval_fields = (
        "approval_id",
        "approver_id",
        "approver_qualification_evidence",
        "conflicts",
        "decision_rationale",
        "approved_at",
        "expires_at",
    )
    approval_expected_fields = {
        "approval_version",
        "approval_id",
        "scope",
        "status",
        "independent",
        "qualification_sha256",
        "approver_id",
        "approver_qualification_evidence",
        "conflicts",
        "conflicts_resolved",
        "decision_rationale",
        "approved_at",
        "expires_at",
        "revoked_at",
        "revocation_reason",
    }
    if (
        not isinstance(approval, dict)
        or set(approval) != approval_expected_fields
        or approval.get("approval_version") != "2.0.0"
        or approval.get("scope") != "judge-qualification"
        or approval.get("status") != "passed"
        or approval.get("independent") is not True
        or approval.get("conflicts_resolved") is not True
        or approval.get("qualification_sha256") != qualification_sha256
        or not all(isinstance(approval.get(field), str) and approval[field].strip() for field in approval_fields)
    ):
        errors.append("judge independent approval is incomplete, unlinked, or did not pass")
        return errors
    if approval.get("revoked_at") is not None or approval.get("revocation_reason") != "":
        errors.append("judge independent approval has been revoked")
    try:
        approved_at = datetime.fromisoformat(approval["approved_at"].replace("Z", "+00:00"))
        expires_at = datetime.fromisoformat(approval["expires_at"].replace("Z", "+00:00"))
    except ValueError:
        errors.append("judge independent approval timestamps are invalid")
        return errors
    current = now or datetime.now(timezone.utc)
    if approved_at.tzinfo is None or expires_at.tzinfo is None or approved_at > current or expires_at <= current or expires_at <= approved_at:
        errors.append("judge independent approval is not currently effective")
    return errors


def _json(path: Path) -> dict[str, Any]:
    try:
        value = _strict_json_loads(path.read_bytes())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ProtocolError(f"cannot read calibration evidence {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ProtocolError(f"calibration evidence must be an object: {path}")
    return value


def qualify_judge_run(
    run: Path,
    blueprint_path: Path,
    corpus_manifest_path: Path,
    output: Path,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    run = run.resolve()
    output = output.resolve()
    if output.exists():
        raise ProtocolError(f"judge qualification output already exists: {output}")
    if output == run or run in output.parents:
        raise ProtocolError("judge qualification output must not mutate the finalized run bundle")
    verification = verify_bundle(run, verify_hmac=False)
    if not verification["valid"]:
        raise ProtocolError("judge qualification requires a valid finalized run bundle")
    manifest = _json(run / "manifest.json")
    corpus_manifest_path = corpus_manifest_path.resolve()
    corpus = _json(corpus_manifest_path)
    try:
        blueprint_raw = blueprint_path.read_bytes()
        blueprint = tomllib.loads(blueprint_raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ProtocolError(f"cannot read judge qualification blueprint: {exc}") from exc
    blueprint_sha = sha256_bytes(blueprint_raw)
    suite = manifest.get("suite")
    if not isinstance(suite, dict) or suite.get("dataset_sha256") != corpus.get("dataset_sha256"):
        raise ProtocolError("run dataset does not match the calibration corpus manifest")
    if corpus.get("blueprint_sha256") != blueprint_sha:
        raise ProtocolError("calibration corpus does not match the qualification blueprint")
    corpus_root = corpus_manifest_path.parent
    for field in ("blueprint_path", "blueprint_approval_path"):
        relative = corpus.get(field)
        expected_hash = corpus.get(field.removesuffix("_path") + "_sha256")
        if not isinstance(relative, str) or not isinstance(expected_hash, str):
            raise ProtocolError(f"calibration corpus is missing {field} and its hash")
        candidate = corpus_root / relative
        resolved = candidate.resolve()
        try:
            resolved.relative_to(corpus_root)
        except ValueError as exc:
            raise ProtocolError(f"calibration corpus {field} escapes its evidence closure") from exc
        if candidate.is_symlink() or not resolved.is_file() or sha256_file(resolved) != expected_hash:
            raise ProtocolError(f"calibration corpus {field} is missing or has a hash mismatch")
    bundled_blueprint = (corpus_root / str(corpus["blueprint_path"])).resolve()
    if bundled_blueprint.read_bytes() != blueprint_raw:
        raise ProtocolError("supplied blueprint differs from the immutable corpus blueprint")
    blueprint_approval_path = (corpus_root / str(corpus["blueprint_approval_path"])).resolve()
    blueprint_approval = _json(blueprint_approval_path)
    source_suite = corpus.get("source_suite")
    blueprint_approval_version = blueprint_approval.get("approval_version")
    blueprint_approval_subject = blueprint_approval.get("subject")
    blueprint_approval_sha = (
        blueprint_approval_subject.get("sha256") if isinstance(blueprint_approval_subject, dict) else blueprint_approval.get("blueprint_sha256")
    )
    blueprint_approval_passed = (
        blueprint_approval.get("decision") == "approved"
        if blueprint_approval_version == "2.0.0"
        else blueprint_approval.get("status") == "passed"
    )
    if (
        not isinstance(source_suite, dict)
        or blueprint_approval_version not in {"1.0.0", "2.0.0"}
        or blueprint_approval.get("scope") != "judge-qualification-blueprint"
        or not blueprint_approval_passed
        or blueprint_approval.get("independent") is not True
        or blueprint_approval.get("conflicts_resolved") is not True
        or blueprint_approval_sha != blueprint_sha
        or blueprint_approval.get("suite") != source_suite
        or blueprint_approval.get("revoked_at") is not None
        or blueprint_approval.get("revocation_reason") != ""
    ):
        raise ProtocolError("calibration corpus blueprint approval is invalid, revoked, or unlinked")
    try:
        approval_start = datetime.fromisoformat(str(blueprint_approval.get("approved_at", "")).replace("Z", "+00:00"))
        approval_end = datetime.fromisoformat(str(blueprint_approval.get("expires_at", "")).replace("Z", "+00:00"))
    except ValueError as exc:
        raise ProtocolError("calibration corpus blueprint approval timestamps are invalid") from exc
    current = now or datetime.now(timezone.utc)
    if approval_start.tzinfo is None or approval_end.tzinfo is None or not approval_start <= current < approval_end:
        raise ProtocolError("calibration corpus blueprint approval is not currently effective")
    target = manifest.get("target")
    if (
        not isinstance(target, dict)
        or target.get("kind") != "recorded"
        or target.get("recorded_responses_sha256") != corpus.get("recorded_responses_sha256")
    ):
        raise ProtocolError("judge qualification requires the corpus's pinned recorded responses")
    if corpus.get("identity_blinded_to_judge") is not True or corpus.get("independent_gold_required") is not True:
        raise ProtocolError("calibration corpus lacks required blinding or independent-gold declarations")
    metrics = manifest.get("metrics")
    calibration = metrics.get("judge_calibration") if isinstance(metrics, dict) else None
    if not isinstance(calibration, dict) or not calibration:
        raise ProtocolError("run contains no judge calibration metrics")
    judge_models = (manifest.get("judge") or {}).get("models")
    if not isinstance(judge_models, list) or not judge_models:
        raise ProtocolError("run does not identify the qualified judge configuration")
    judge_ids = {str(model.get("id")) for model in judge_models if isinstance(model, dict) and model.get("id")}
    if judge_ids != set(calibration):
        raise ProtocolError("judge calibration metrics do not match the declared judge identities")
    minimum_repetitions = int(blueprint.get("minimum_judge_repetitions", 1))
    maximum_invalid = int(blueprint.get("maximum_invalid_cases", 0))
    minimum_stability = float(blueprint.get("minimum_repeat_stability", 0.0))
    modules = {str(row["id"]): row for row in blueprint.get("modules", []) if isinstance(row, dict) and row.get("id")}
    judge_results: dict[str, Any] = {}
    for judge_id, result in calibration.items():
        if not isinstance(result, dict):
            raise ProtocolError(f"invalid calibration metrics for judge {judge_id}")
        checks: list[dict[str, Any]] = []
        module_results: dict[str, Any] = {}
        category_slices = ((result.get("slices") or {}).get("category") or {}) if isinstance(result.get("slices"), dict) else {}
        for module, rule in modules.items():
            measured = category_slices.get(module) if isinstance(category_slices, dict) else None
            if not isinstance(measured, dict):
                module_results[module] = {"passed": False, "reason": "missing module metrics"}
                continue
            sensitivity = measured.get("failure_sensitivity_ci")
            specificity = measured.get("pass_specificity_ci")
            sensitivity_lower = sensitivity.get("lower") if isinstance(sensitivity, dict) else None
            specificity_lower = specificity.get("lower") if isinstance(specificity, dict) else None
            expected_cases = int(rule["target"])
            passed = (
                measured.get("cases") == expected_cases
                and measured.get("invalid_cases") == 0
                and isinstance(sensitivity_lower, (int, float))
                and float(sensitivity_lower) >= float(rule["failure_sensitivity_gate"])
                and isinstance(specificity_lower, (int, float))
                and float(specificity_lower) >= float(rule["pass_specificity_gate"])
            )
            module_results[module] = {
                "passed": passed,
                "cases": measured.get("cases"),
                "expected_cases": expected_cases,
                "invalid_cases": measured.get("invalid_cases"),
                "failure_sensitivity_ci": sensitivity,
                "failure_sensitivity_gate": rule["failure_sensitivity_gate"],
                "pass_specificity_ci": specificity,
                "pass_specificity_gate": rule["pass_specificity_gate"],
            }
        repetitions = result.get("observations", 0) / result.get("cases", 1) if result.get("cases") else 0
        checks.extend(
            [
                {"name": "all_modules", "passed": bool(module_results) and all(row["passed"] for row in module_results.values())},
                {"name": "invalid_cases", "passed": int(result.get("invalid_cases", 0)) <= maximum_invalid},
                {"name": "judge_repetitions", "passed": repetitions >= minimum_repetitions},
                {
                    "name": "repeat_stability",
                    "passed": isinstance(result.get("stable_repeated_case_fraction"), (int, float))
                    and float(result["stable_repeated_case_fraction"]) >= minimum_stability,
                },
            ]
        )
        judge_results[str(judge_id)] = {
            "passed": all(bool(check["passed"]) for check in checks),
            "checks": checks,
            "modules": module_results,
            "diagnostic_slices": {
                key: value
                for key, value in (result.get("slices") or {}).items()
                if key in {"severity", "language", "response_length", "response_style", "probe_type", "model_family_alias"}
            },
        }
    report = {
        "qualification_version": "2.0.0",
        "passed": bool(judge_results) and all(row["passed"] for row in judge_results.values()),
        "run_manifest_sha256": sha256_file(run / "manifest.json"),
        "bundle_verification": verification,
        "corpus_manifest_sha256": sha256_file(corpus_manifest_path),
        "blueprint_sha256": blueprint_sha,
        "blueprint_approval_sha256": corpus["blueprint_approval_sha256"],
        "source_suite": source_suite,
        "corpus_dataset_sha256": corpus["dataset_sha256"],
        "judge_configuration": manifest["judge"],
        "rubric_sha256": suite["rubric_sha256"],
        "judges": judge_results,
        "limitations": [
            "Qualification applies only to the exact recorded judge identities, revisions, prompt, rubric, schema, and sampling configuration.",
            "External approval of human-gold independence and competence remains required.",
        ],
    }
    atomic_json(output, report)
    return report
