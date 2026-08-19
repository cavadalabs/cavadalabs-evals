from __future__ import annotations

import json
import re
import shutil
import tomllib
from datetime import datetime, timezone
from pathlib import Path
from shutil import copyfile as _snapshot_copyfile
from tempfile import TemporaryDirectory
from typing import Any, cast

from .artifacts import verify_bundle
from .protocol import ProtocolError, Suite, _read_jsonl, atomic_json, require_mutable_output_root, sha256_bytes, sha256_file


def judge_signature(judge: Any) -> str:
    if not isinstance(judge, dict):
        return ""
    text_fields = ("requested_model", "expected_reported_model", "revision", "endpoint", "prompt_sha256", "response_schema")
    models = judge.get("models")
    if (
        not all(isinstance(judge.get(field), str) and judge[field] for field in text_fields)
        or not isinstance(judge.get("temperature"), (int, float))
        or isinstance(judge.get("temperature"), bool)
        or not isinstance(judge.get("max_tokens"), int)
        or isinstance(judge.get("max_tokens"), bool)
        or judge["max_tokens"] < 1
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
    judge_repetitions = judge.get("judge_repetitions")
    if not isinstance(judge_repetitions, int) or isinstance(judge_repetitions, bool) or judge_repetitions < 1:
        return ""
    fields = (*text_fields, "temperature", "max_tokens", "judge_repetitions", "models", "consensus")
    return json.dumps({field: judge.get(field) for field in fields}, sort_keys=True, separators=(",", ":"))


def _evidence_error(root: Path | None, relative: Any, expected_hash: Any) -> str | None:
    if (
        root is None
        or not isinstance(relative, str)
        or not relative
        or not isinstance(expected_hash, str)
        or not re.fullmatch(r"[a-f0-9]{64}", expected_hash)
        or expected_hash == "0" * 64
    ):
        return "judge approver qualification path and non-placeholder SHA-256 are required"
    candidate = root / relative
    resolved = candidate.resolve()
    if Path(relative).is_absolute() or ".." in Path(relative).parts or not resolved.is_relative_to(root.resolve()):
        return "judge approver qualification evidence must stay inside its evidence package"
    if candidate.is_symlink() or not resolved.is_file():
        return "judge approver qualification evidence must be a regular package-local file"
    if sha256_file(resolved) != expected_hash:
        return "judge approver qualification evidence hash mismatch"
    return None


def judge_evidence_errors(
    qualification: Any,
    approval: Any,
    *,
    qualification_sha256: str,
    expected_judge: Any,
    rubric_sha256: str,
    expected_blueprint_sha256: str | None,
    approval_root: Path | None = None,
    now: datetime | None = None,
) -> list[str]:
    errors: list[str] = []
    hashes = ("run_manifest_sha256", "corpus_manifest_sha256", "blueprint_sha256", "corpus_dataset_sha256")
    judges = qualification.get("judges") if isinstance(qualification, dict) else None
    if (
        not isinstance(qualification, dict)
        or qualification.get("qualification_version") != "2.0.0"
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
    corpus_snapshot = qualification.get("corpus_manifest_snapshot") if isinstance(qualification, dict) else None
    try:
        corpus = json.loads(corpus_snapshot) if isinstance(corpus_snapshot, str) else None
        corpus_sha256 = sha256_bytes(corpus_snapshot.encode("utf-8")) if isinstance(corpus_snapshot, str) else None
    except (UnicodeEncodeError, json.JSONDecodeError):
        corpus = None
        corpus_sha256 = None
    if (
        not isinstance(corpus_snapshot, str)
        or not isinstance(corpus, dict)
        or corpus_sha256 != qualification.get("corpus_manifest_sha256")
        or corpus.get("blueprint_sha256") != qualification.get("blueprint_sha256")
    ):
        errors.append("judge qualification corpus and blueprint evidence do not reconcile")
    if expected_blueprint_sha256 is not None and (
        not isinstance(qualification, dict) or qualification.get("blueprint_sha256") != expected_blueprint_sha256
    ):
        errors.append("judge qualification does not match the suite-pinned blueprint")
    qualification_judge = qualification.get("judge_configuration") if isinstance(qualification, dict) else None
    if judge_signature(qualification_judge) != judge_signature(expected_judge) or not judge_signature(expected_judge):
        errors.append("judge qualification does not match the exact run configuration")
    approval_fields = (
        "approval_id",
        "approver_id",
        "conflicts",
        "decision_rationale",
        "approved_at",
        "expires_at",
    )
    if (
        not isinstance(approval, dict)
        or approval.get("approval_version") != "2.0.0"
        or approval.get("scope") != "judge-qualification"
        or approval.get("status") != "passed"
        or approval.get("independent") is not True
        or approval.get("qualification_sha256") != qualification_sha256
        or not all(isinstance(approval.get(field), str) and approval[field].strip() for field in approval_fields)
    ):
        errors.append("judge independent approval is incomplete, unlinked, or did not pass")
        return errors
    evidence_error = _evidence_error(
        approval_root,
        approval.get("approver_qualification_evidence"),
        approval.get("approver_qualification_evidence_sha256"),
    )
    if evidence_error:
        errors.append(evidence_error)
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
    source_run = run
    run = source_run.resolve()
    output = output.resolve()
    require_mutable_output_root(output.parent)
    if output.exists():
        raise ProtocolError(f"judge qualification output already exists: {output}")
    if output == run or run in output.parents:
        raise ProtocolError("judge qualification output must not mutate the finalized run bundle")
    if source_run.is_symlink() or not run.is_dir():
        raise ProtocolError("judge qualification requires a regular finalized run directory")
    with TemporaryDirectory(prefix="cavada-judge-qualification-") as temporary:
        snapshot = Path(temporary) / "run"
        shutil.copytree(run, snapshot, symlinks=True, copy_function=_snapshot_copyfile)
        return _qualify_judge_run_snapshot(snapshot, blueprint_path, corpus_manifest_path, output)


def _qualify_judge_run_snapshot(run: Path, blueprint_path: Path, corpus_manifest_path: Path, output: Path) -> dict[str, Any]:
    verification = verify_bundle(run)
    if not verification["valid"]:
        raise ProtocolError("judge qualification requires a valid finalized run bundle")
    run_bundle_sha256 = sha256_file(run / "bundle.json")
    run_manifest_sha256 = sha256_file(run / "manifest.json")
    manifest = _json(run / "manifest.json")
    if corpus_manifest_path.is_symlink() or not corpus_manifest_path.is_file():
        raise ProtocolError("calibration corpus manifest must be a regular file")
    try:
        corpus_raw = corpus_manifest_path.read_bytes()
        corpus_text = corpus_raw.decode("utf-8")
        corpus = json.loads(corpus_text)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtocolError(f"cannot read calibration evidence {corpus_manifest_path}: {exc}") from exc
    if not isinstance(corpus, dict):
        raise ProtocolError(f"calibration evidence must be an object: {corpus_manifest_path}")
    if blueprint_path.is_symlink() or not blueprint_path.is_file():
        raise ProtocolError("judge qualification blueprint must be a regular file")
    try:
        blueprint_raw = blueprint_path.read_bytes()
        blueprint = tomllib.loads(blueprint_raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ProtocolError(f"cannot read judge qualification blueprint: {exc}") from exc
    suite = manifest.get("suite")
    if not isinstance(suite, dict) or suite.get("dataset_sha256") != corpus.get("dataset_sha256"):
        raise ProtocolError("run dataset does not match the calibration corpus manifest")
    blueprint_sha256 = sha256_bytes(blueprint_raw)
    if corpus.get("blueprint_sha256") != blueprint_sha256:
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
    required = {
        "suite_snapshot.toml": suite.get("suite_config_sha256"),
        "dataset_snapshot.jsonl": suite.get("dataset_sha256"),
        "rubric_snapshot.md": suite.get("rubric_sha256"),
        "judgments.jsonl": (manifest.get("artifacts") or {}).get("judgments.jsonl"),
        "metrics.json": (manifest.get("artifacts") or {}).get("metrics.json"),
    }
    if any(
        not isinstance(expected, str)
        or not re.fullmatch(r"[a-f0-9]{64}", expected)
        or not (path := run / name).is_file()
        or path.is_symlink()
        or sha256_file(path) != expected
        for name, expected in required.items()
    ):
        raise ProtocolError("judge qualification run is missing exact hash-bound calibration evidence")
    if _json(run / "metrics.json") != metrics:
        raise ProtocolError("judge qualification metrics artifact differs from the run manifest")
    try:
        suite_config = tomllib.loads((run / "suite_snapshot.toml").read_text(encoding="utf-8"))
        rubric = (run / "rubric_snapshot.md").read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ProtocolError(f"cannot read judge qualification suite snapshots: {exc}") from exc
    cases = _read_jsonl(run / "dataset_snapshot.jsonl")
    judgments = _read_jsonl(run / "judgments.jsonl")
    if (
        not cases
        or not judgments
        or any(
            case.get("judge_gold_verdict") not in {"pass", "fail"}
            or not isinstance(case.get("category"), str)
            or not case["category"]
            for case in cases
        )
    ):
        raise ProtocolError("judge qualification requires complete gold cases and judgment evidence")
    snapshot_suite = Suite(
        run,
        suite_config,
        tuple(cases),
        rubric,
        run / "dataset_snapshot.jsonl",
        run / "rubric_snapshot.md",
    )
    suite_judge = suite_config.get("judge")
    if (
        not isinstance(suite_judge, dict)
        or not isinstance(suite_judge.get("qualification_blueprint"), str)
        or not suite_judge["qualification_blueprint"]
        or suite_judge.get("qualification_blueprint_sha256") != blueprint_sha256
    ):
        raise ProtocolError("judge qualification blueprint does not match the immutable suite snapshot pin")
    from .program import validate_judge_qualification_blueprint

    blueprint_errors = validate_judge_qualification_blueprint(blueprint_path, snapshot_suite, raw=blueprint_raw)
    if blueprint_errors:
        raise ProtocolError("invalid judge qualification blueprint:\n" + "\n".join(blueprint_errors))
    judge = manifest.get("judge")
    parameters = manifest.get("parameters")
    judge_models = judge.get("models") if isinstance(judge, dict) else None
    target_repetitions = parameters.get("repetitions") if isinstance(parameters, dict) else None
    judge_repetitions = parameters.get("judge_repetitions") if isinstance(parameters, dict) else None
    if (
        not isinstance(judge, dict)
        or not isinstance(judge_models, list)
        or not judge_models
        or not all(isinstance(model, dict) and isinstance(model.get("id"), str) and model["id"] for model in judge_models)
        or not isinstance(target_repetitions, int)
        or isinstance(target_repetitions, bool)
        or target_repetitions < 1
        or not isinstance(judge_repetitions, int)
        or isinstance(judge_repetitions, bool)
        or judge_repetitions < 1
        or judge.get("judge_repetitions") != judge_repetitions
    ):
        raise ProtocolError("judge qualification requires exact judge repetition evidence")
    case_ids = [case.get("id") for case in cases]
    ordered_judge_ids = [model["id"] for model in judge_models]
    if (
        any(not isinstance(case_id, str) or not case_id for case_id in case_ids)
        or len(set(case_ids)) != len(case_ids)
        or len(set(ordered_judge_ids)) != len(ordered_judge_ids)
    ):
        raise ProtocolError("judge qualification judgments do not match the exact scheduled judge grid")
    judge_indexes = {judge_id: index for index, judge_id in enumerate(ordered_judge_ids)}
    expected = {
        (case_id, repetition, judge_id, model_repetition, judge_index * judge_repetitions + model_repetition)
        for case_id in case_ids
        for repetition in range(1, target_repetitions + 1)
        for judge_index, judge_id in enumerate(ordered_judge_ids)
        for model_repetition in range(1, judge_repetitions + 1)
    }
    observed = set()
    for row in judgments:
        case_id, repetition, judge_id = row.get("case_id"), row.get("repetition"), row.get("judge_id")
        model_repetition, judge_repetition = row.get("model_repetition"), row.get("judge_repetition")
        if (
            not isinstance(case_id, str)
            or not case_id
            or not isinstance(judge_id, str)
            or not judge_id
            or case_id not in case_ids
            or judge_id not in judge_indexes
            or any(not isinstance(value, int) or isinstance(value, bool) for value in (repetition, model_repetition, judge_repetition))
        ):
            raise ProtocolError("judge qualification judgments do not match the exact scheduled judge grid")
        repetition, model_repetition, judge_repetition = cast(tuple[int, int, int], (repetition, model_repetition, judge_repetition))
        if (
            not 1 <= repetition <= target_repetitions
            or not 1 <= model_repetition <= judge_repetitions
            or judge_repetition != judge_indexes[judge_id] * judge_repetitions + model_repetition
        ):
            raise ProtocolError("judge qualification judgments do not match the exact scheduled judge grid")
        coordinate = (case_id, repetition, judge_id, model_repetition, judge_repetition)
        if coordinate in observed:
            raise ProtocolError("judge qualification judgments do not match the exact scheduled judge grid")
        observed.add(coordinate)
    if observed != expected:
        raise ProtocolError("judge qualification judgments do not match the exact scheduled judge grid")
    demonstrated_judge_repetitions = len({coordinate[3] for coordinate in observed})
    from .runner import _judge_calibration_summary

    calculated_calibration = _judge_calibration_summary(judgments, snapshot_suite)
    if calibration != calculated_calibration:
        raise ProtocolError("judge calibration metrics do not reconcile with the immutable judgments and gold dataset")
    if set(ordered_judge_ids) != set(calibration):
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
        checks.extend(
            [
                {"name": "all_modules", "passed": bool(module_results) and all(row["passed"] for row in module_results.values())},
                {"name": "invalid_cases", "passed": int(result.get("invalid_cases", 0)) <= maximum_invalid},
                {"name": "judge_repetitions", "passed": demonstrated_judge_repetitions >= minimum_repetitions},
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
        "run_manifest_sha256": run_manifest_sha256,
        "run_bundle_sha256": run_bundle_sha256,
        "bundle_verification": verification,
        "corpus_manifest_sha256": sha256_bytes(corpus_raw),
        "corpus_manifest_snapshot": corpus_text,
        "blueprint_sha256": blueprint_sha256,
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
