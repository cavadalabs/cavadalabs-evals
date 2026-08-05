from __future__ import annotations

import json
import tomllib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .artifacts import verify_bundle
from .protocol import ProtocolError, atomic_json, sha256_file


def judge_signature(judge: Any) -> str:
    if not isinstance(judge, dict):
        return ""
    text_fields = ("requested_model", "expected_reported_model", "revision", "endpoint", "prompt_sha256", "response_schema")
    models = judge.get("models")
    if (
        not all(isinstance(judge.get(field), str) and judge[field] for field in text_fields)
        or not isinstance(judge.get("temperature"), (int, float))
        or isinstance(judge.get("temperature"), bool)
        or not isinstance(models, list)
        or not models
        or not all(
            isinstance(model, dict)
            and all(isinstance(model.get(field), str) and model[field] for field in ("id", "model", "expected_model", "revision"))
            for model in models
        )
        or judge.get("consensus") not in {"majority", "unanimous"}
    ):
        return ""
    fields = (*text_fields, "temperature", "models", "consensus")
    return json.dumps({field: judge.get(field) for field in fields}, sort_keys=True, separators=(",", ":"))


def judge_evidence_errors(
    qualification: Any,
    approval: Any,
    *,
    qualification_sha256: str,
    expected_judge: Any,
    rubric_sha256: str,
    now: datetime | None = None,
) -> list[str]:
    errors: list[str] = []
    hashes = ("run_manifest_sha256", "corpus_manifest_sha256", "blueprint_sha256", "corpus_dataset_sha256")
    judges = qualification.get("judges") if isinstance(qualification, dict) else None
    if (
        not isinstance(qualification, dict)
        or qualification.get("qualification_version") != "1.0.0"
        or qualification.get("passed") is not True
        or qualification.get("rubric_sha256") != rubric_sha256
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
    if (
        not isinstance(approval, dict)
        or approval.get("approval_version") != "1.0.0"
        or approval.get("scope") != "judge-qualification"
        or approval.get("status") != "passed"
        or approval.get("independent") is not True
        or approval.get("qualification_sha256") != qualification_sha256
        or not all(isinstance(approval.get(field), str) and approval[field].strip() for field in approval_fields)
    ):
        errors.append("judge independent approval is incomplete, unlinked, or did not pass")
        return errors
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
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ProtocolError(f"cannot read calibration evidence {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ProtocolError(f"calibration evidence must be an object: {path}")
    return value


def qualify_judge_run(run: Path, blueprint_path: Path, corpus_manifest_path: Path, output: Path) -> dict[str, Any]:
    run = run.resolve()
    output = output.resolve()
    if output.exists():
        raise ProtocolError(f"judge qualification output already exists: {output}")
    if output == run or run in output.parents:
        raise ProtocolError("judge qualification output must not mutate the finalized run bundle")
    verification = verify_bundle(run)
    if not verification["valid"]:
        raise ProtocolError("judge qualification requires a valid finalized run bundle")
    manifest = _json(run / "manifest.json")
    corpus = _json(corpus_manifest_path)
    try:
        with blueprint_path.open("rb") as handle:
            blueprint = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ProtocolError(f"cannot read judge qualification blueprint: {exc}") from exc
    suite = manifest.get("suite")
    if not isinstance(suite, dict) or suite.get("dataset_sha256") != corpus.get("dataset_sha256"):
        raise ProtocolError("run dataset does not match the calibration corpus manifest")
    if corpus.get("blueprint_sha256") != sha256_file(blueprint_path):
        raise ProtocolError("calibration corpus does not match the qualification blueprint")
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
        "qualification_version": "1.0.0",
        "passed": bool(judge_results) and all(row["passed"] for row in judge_results.values()),
        "run_manifest_sha256": sha256_file(run / "manifest.json"),
        "bundle_verification": verification,
        "corpus_manifest_sha256": sha256_file(corpus_manifest_path),
        "blueprint_sha256": sha256_file(blueprint_path),
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
