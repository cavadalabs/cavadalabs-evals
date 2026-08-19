from __future__ import annotations

import json
import math
import re
import tomllib
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path, PureWindowsPath
from tempfile import TemporaryDirectory
from typing import Any

from .artifacts import _read_regular, verify_bundle
from .calibration import judge_evidence_errors
from .metrics import METRIC_VERSION, deterministic_evaluation
from .protocol import SCHEMA_VERSION, ProtocolError, Suite, _closed_object_errors, apply_gates, atomic_json, load_suite, sha256_bytes, sha256_file, summarize
from .statistics import bootstrap_mean_interval, distribution, stratified_bootstrap_mean_interval

_HASH = re.compile(r"[a-f0-9]{64}")
_ENGAGEMENT_EVIDENCE = ("authorization", "conflict_assessment", "legal_applicability", "approver_qualification")
_REQUIRED_OFFICIAL_ARTIFACTS = {
    "requests.jsonl",
    "raw_responses.jsonl",
    "judgments.jsonl",
    "case_results.jsonl",
    "metrics.json",
    "timing.json",
    "failures.jsonl",
    "environment.json",
    "protocol_snapshot.md",
    "suite_snapshot.toml",
    "dataset_snapshot.jsonl",
    "rubric_snapshot.md",
    "implementation_evidence_manifest.json",
    "suite_evidence_manifest.json",
    "judge_qualification_snapshot.json",
    "judge_approval_snapshot.json",
    "engagement_snapshot.json",
    "engagement_evidence_manifest.json",
}
OFFICIAL_MANIFEST_FIELDS = {
    "protocol_version",
    "schema_version",
    "report_version",
    "metric_version",
    "adapter_contract_version",
    "run_id",
    "status",
    "official_requested",
    "official",
    "assurance",
    "model_claim_allowed",
    "benchmark_claim_allowed",
    "started_at",
    "finished_at",
    "resumed_at",
    "reproduction_command",
    "abort_reason",
    "suite",
    "target",
    "judge",
    "judge_qualification",
    "engagement",
    "external_judge_authorized",
    "external_authorization",
    "artifact_security",
    "parameters",
    "pricing",
    "source",
    "environment",
    "protocol_sha256",
    "metrics",
    "artifacts",
}
OFFICIAL_METRIC_FIELDS = {
    "total",
    "observations",
    "pass",
    "fail",
    "invalid",
    "error",
    "skipped",
    "pass_rate",
    "pass_rate_ci",
    "pass_rate_ci95",
    "officially_valid",
    "analysis_unit",
    "evaluation_cases",
    "target_observations",
    "case_level",
    "case_categories",
    "pass_rate_bootstrap_ci",
    "pass_rate_stratified_bootstrap_ci",
    "distribution_shift",
    "slices",
    "slice_disparities",
    "stability",
    "judge_calibration",
    "performance",
    "performance_by_phase",
    "budgets",
    "cost",
    "gate_failures",
    "aborted",
}


def _strict_json(raw: str) -> Any:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in items:
            if key in value:
                raise ValueError(f"duplicate JSON key: {key}")
            value[key] = item
        return value

    def constant(value: str) -> None:
        raise ValueError(f"non-finite JSON number: {value}")

    return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)


def _safe_path(root: Path, relative: Any, label: str) -> Path:
    if not isinstance(relative, str) or not relative:
        raise ProtocolError(f"{label} path is missing")
    path = Path(relative)
    windows = PureWindowsPath(relative)
    if (
        path.is_absolute()
        or windows.drive
        or ".." in path.parts
        or ".." in windows.parts
        or path.as_posix() != relative
        or windows.as_posix() != relative
    ):
        raise ProtocolError(f"{label} path is unsafe")
    candidate = root / path
    try:
        if root.is_symlink() or any((root / Path(*path.parts[:index])).is_symlink() for index in range(1, len(path.parts) + 1)):
            raise ProtocolError(f"{label} path is unsafe")
        candidate.resolve(strict=False).relative_to(root.resolve())
    except (OSError, ValueError) as exc:
        raise ProtocolError(f"{label} path is unsafe") from exc
    return candidate


def _pinned_file(root: Path, owner: Any, field: str, label: str) -> tuple[str, bytes] | None:
    if not isinstance(owner, dict):
        return None
    relative, expected = owner.get(field), owner.get(f"{field}_sha256")
    if relative in {None, ""} and expected in {None, ""}:
        return None
    if not isinstance(expected, str) or _HASH.fullmatch(expected) is None:
        raise ProtocolError(f"{label} requires a pinned SHA-256")
    path = _safe_path(root, relative, label)
    try:
        raw = _read_regular(root, path.relative_to(root))
    except (OSError, ValueError) as exc:
        raise ProtocolError(f"{label} must be a regular package-local file") from exc

    if sha256_bytes(raw) != expected:
        raise ProtocolError(f"{label} hash mismatch")
    return str(relative), raw


def suite_snapshot_files(suite: Suite) -> dict[str, bytes]:
    """Return the closed, hash-pinned files needed to revalidate an official suite."""
    snapshots: dict[str, bytes] = {}

    def add(owner: Any, field: str, label: str, *, record: bool = False) -> dict[str, Any] | None:
        pinned = _pinned_file(suite.root, owner, field, label)
        if pinned is None:
            return None
        relative, raw = pinned
        if relative in snapshots and snapshots[relative] != raw:
            raise ProtocolError(f"{label} conflicts with another suite snapshot")
        snapshots[relative] = raw
        if not record:
            return None
        try:
            value = _strict_json(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise ProtocolError(f"{label} must be valid JSON") from exc
        if not isinstance(value, dict):
            raise ProtocolError(f"{label} must be a JSON object")
        return value

    def store(path: Path, label: str, expected: str | None = None) -> bytes:
        try:
            relative = path.resolve().relative_to(suite.root.resolve()).as_posix()
        except ValueError as exc:
            raise ProtocolError(f"{label} escapes the suite") from exc
        try:
            raw = _read_regular(suite.root, Path(relative))
        except OSError as exc:
            raise ProtocolError(f"{label} must be a regular suite-local file") from exc
        if expected is not None and sha256_bytes(raw) != expected:
            raise ProtocolError(f"{label} hash mismatch")
        if relative in snapshots and snapshots[relative] != raw:
            raise ProtocolError(f"{label} conflicts with another suite snapshot")
        snapshots[relative] = raw
        return raw

    calibration = suite.config.get("calibration")
    integrity = suite.config.get("dataset_integrity")
    add(suite.config.get("judge"), "qualification_blueprint", "judge qualification blueprint")
    blueprint_approval = add(
        suite.config.get("judge"),
        "qualification_blueprint_approval",
        "judge qualification blueprint approval",
        record=True,
    )
    add(blueprint_approval, "approver_qualification_evidence", "judge blueprint approver qualification evidence")
    report = add(calibration, "evidence", "calibration report", record=True)
    approval = add(calibration, "independent_review_evidence", "calibration independent approval", record=True)
    semantic = add(integrity, "semantic_review_evidence", "semantic contamination evidence", record=True)
    for field, label in (
        ("analysis_plan", "calibration analysis plan"),
        ("human_label_evidence", "calibration human-label evidence"),
        ("holdout_manifest", "calibration holdout manifest"),
        ("pilot_audit", "calibration pilot audit"),
        ("statistical_review", "calibration statistical review"),
        ("semantic_contamination_evidence", "calibration semantic-contamination evidence"),
    ):
        add(report, field, label)
    campaign = add(report, "pilot_campaign", "calibration pilot campaign", record=True)
    if campaign is not None and isinstance(report, dict):
        campaign_path = _safe_path(suite.root, report.get("pilot_campaign"), "calibration pilot campaign")
        campaign_root = campaign_path.parent
        for field, label in (
            ("judge_qualification", "pilot judge qualification"),
            ("judge_independent_approval", "pilot judge independent approval"),
            ("transcript_review", "pilot transcript review"),
        ):
            record = campaign.get(field)
            if not isinstance(record, dict) or not isinstance(record.get("path"), str) or not isinstance(record.get("sha256"), str):
                raise ProtocolError(f"{label} path and SHA-256 are required")
            store(_safe_path(campaign_root, record["path"], label), label, str(record["sha256"]))
        runs = campaign.get("runs")
        if not isinstance(runs, list):
            raise ProtocolError("pilot campaign runs must be an array")
        for index, record in enumerate(runs, 1):
            relative = record.get("path") if isinstance(record, dict) else None
            run_root = _safe_path(campaign_root, relative, f"pilot run {index}")
            if run_root.is_symlink() or not run_root.is_dir():
                raise ProtocolError(f"pilot run {index} must be a regular suite-local directory")
            verification = verify_bundle(run_root)
            if not verification["valid"]:
                raise ProtocolError(f"pilot run {index} bundle is invalid")
            bundle_raw = store(run_root / "bundle.json", f"pilot run {index} bundle")
            try:
                bundle = _strict_json(bundle_raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
                raise ProtocolError(f"pilot run {index} bundle is invalid JSON") from exc
            files = bundle.get("files") if isinstance(bundle, dict) else None
            if not isinstance(files, dict):
                raise ProtocolError(f"pilot run {index} bundle file set is malformed")
            store(run_root / "checksums.txt", f"pilot run {index} checksums")
            if (run_root / "signature.json").exists():
                store(run_root / "signature.json", f"pilot run {index} signature")
            for relative_file, digest in files.items():
                if not isinstance(digest, str) or _HASH.fullmatch(digest) is None:
                    raise ProtocolError(f"pilot run {index} contains a malformed artifact digest")
                store(
                    _safe_path(run_root, relative_file, f"pilot run {index} artifact"),
                    f"pilot run {index} artifact",
                    digest,
                )
    add(approval, "approver_qualification_evidence", "calibration approver qualification evidence")
    for field, label in (
        ("comparison_corpus", "semantic comparison corpus"),
        ("candidate_pairs_evidence", "semantic candidate-pair evidence"),
        ("reviewer_evidence", "semantic independent-review evidence"),
    ):
        add(semantic, field, label)

    target = suite.config.get("target")
    add(target, "responses", "recorded target responses")
    add(target, "system_prompt", "target system prompt")
    for case in suite.cases:
        values = [case.get("input"), *(message.get("content") for message in case.get("messages", []) if isinstance(message, dict))]
        for value in values:
            if not isinstance(value, list):
                continue
            for part in value:
                if isinstance(part, dict) and part.get("type") in {"image", "audio", "video", "document"}:
                    add(part, "asset", f"case {case.get('id')} asset")
    return dict(sorted(snapshots.items()))


def engagement_snapshot_files(path: Path) -> tuple[bytes, dict[str, bytes]]:
    try:
        raw = _read_regular(path.parent, Path(path.name))
        record = _strict_json(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ProtocolError("engagement must be a readable JSON object") from exc
    if not isinstance(record, dict):
        raise ProtocolError("engagement must be a readable JSON object")
    snapshots: dict[str, bytes] = {}
    for name in _ENGAGEMENT_EVIDENCE:
        pinned = _pinned_file(path.parent, record, f"{name}_evidence", f"engagement {name} evidence")
        if pinned is not None:
            relative, evidence = pinned
            if relative in snapshots and snapshots[relative] != evidence:
                raise ProtocolError(f"engagement {name} evidence conflicts with another snapshot")
            snapshots[relative] = evidence
    return raw, dict(sorted(snapshots.items()))


def _finite(value: Any) -> bool:
    if isinstance(value, float):
        return math.isfinite(value)
    if isinstance(value, dict):
        return all(isinstance(key, str) and _finite(item) for key, item in value.items())
    if isinstance(value, list):
        return all(_finite(item) for item in value)
    return True


def _object(path: Path, label: str) -> dict[str, Any]:
    try:
        value = _strict_json(_read_regular(path.parent, Path(path.name)).decode("utf-8"))
    except ValueError as exc:
        raise ProtocolError(f"{label} is invalid: {exc}") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise ProtocolError(f"{label} must be a readable JSON object") from exc
    if not isinstance(value, dict) or not _finite(value):
        raise ProtocolError(f"{label} must be a finite JSON object")
    return value


def _jsonl(path: Path) -> list[dict[str, Any]]:
    try:
        lines = _read_regular(path.parent, Path(path.name)).decode("utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as exc:
        raise ProtocolError(f"{path.name} must be a regular UTF-8 JSONL file") from exc
    rows: list[dict[str, Any]] = []
    for line_number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            value = _strict_json(line)
        except ValueError as exc:
            raise ProtocolError(f"invalid {path.name} line {line_number}: {exc}") from exc
        except json.JSONDecodeError as exc:
            raise ProtocolError(f"invalid {path.name} line {line_number}") from exc
        if not isinstance(value, dict) or not _finite(value):
            raise ProtocolError(f"invalid {path.name} line {line_number}: expected a finite JSON object")
        rows.append(value)
    return rows


def _materialize_files(root: Path, manifest_path: Path, blob_root: Path, label: str) -> dict[str, str]:
    manifest = _object(manifest_path, f"{label} manifest")
    materialized: dict[str, str] = {}
    for relative, digest in manifest.items():
        if not isinstance(digest, str) or _HASH.fullmatch(digest) is None:
            raise ProtocolError(f"{label} manifest contains a malformed digest")
        try:
            raw = _read_regular(blob_root, Path(digest))
        except OSError:
            raw = b""
        if sha256_bytes(raw) != digest:
            raise ProtocolError(f"{label} blob {digest} is missing or corrupt")
        destination = _safe_path(root, relative, label)
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists() and destination.read_bytes() != raw:
            raise ProtocolError(f"{label} path conflicts with another snapshot")
        destination.write_bytes(raw)
        materialized[str(relative)] = digest
    entries = list(blob_root.iterdir()) if blob_root.is_dir() and not blob_root.is_symlink() else []
    if any(path.is_symlink() or not path.is_file() for path in entries):
        raise ProtocolError(f"{label} blob set must contain only direct regular files")
    declared = {path.name for path in entries}
    if declared != set(materialized.values()):
        raise ProtocolError(f"{label} blob set is not closed")
    return materialized


def _materialize_suite(run_dir: Path) -> tuple[TemporaryDirectory[str], Suite]:
    temporary = TemporaryDirectory(prefix="cavada-behavior-suite-")
    root = Path(temporary.name)
    try:
        config_raw = _read_regular(run_dir, Path("suite_snapshot.toml"))
        config = tomllib.loads(config_raw.decode("utf-8"))
        dataset = _safe_path(root, config.get("dataset", "dataset.jsonl"), "suite dataset")
        rubric = _safe_path(root, config.get("rubric", "rubric.md"), "suite rubric")
        for destination, source in (
            (root / "suite.toml", run_dir / "suite_snapshot.toml"),
            (dataset, run_dir / "dataset_snapshot.jsonl"),
            (rubric, run_dir / "rubric_snapshot.md"),
        ):
            try:
                raw = config_raw if source.name == "suite_snapshot.toml" else _read_regular(run_dir, source.relative_to(run_dir))
            except (OSError, ValueError) as exc:
                raise ProtocolError(f"{source.name} must be a regular snapshot") from exc
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(raw)
        expected = _materialize_files(root, run_dir / "suite_evidence_manifest.json", run_dir / "suite_evidence", "suite evidence")
        suite = load_suite(root, official=True)
        observed = {relative: sha256_bytes(raw) for relative, raw in suite_snapshot_files(suite).items()}
        if observed != expected:
            raise ProtocolError("suite evidence manifest does not match the closed official reference set")
        return temporary, suite
    except Exception:
        temporary.cleanup()
        raise


def _dotted(value: Any, path: str) -> Any:
    current = value
    for part in path.split("."):
        if isinstance(current, dict):
            current = current.get(part)
        elif isinstance(current, list) and part.isdigit() and int(part) < len(current):
            current = current[int(part)]
        else:
            current = None
    return current


def _answer(suite: Suite, raw: dict[str, Any]) -> tuple[str, str]:
    target = suite.config.get("target") or {}
    if target.get("kind", "json") == "openai":
        answer = _dotted(raw, "choices.0.message.content")
        if answer is None:
            try:
                answer = raw["choices"][0]["message"]["content"]
            except (KeyError, IndexError, TypeError):
                answer = None
        reported = raw.get("model")
    else:
        answer = _dotted(raw, str(target.get("response_field", "answer")))
        reported = _dotted(raw, str(target.get("reported_model_field", "model")))
    if not isinstance(answer, str):
        raise ProtocolError("target response has no configured response string")
    return answer, str(reported or "")


def _keys(rows: list[dict[str, Any]], label: str, failures: list[str]) -> set[tuple[str, int]]:
    seen: set[tuple[str, int]] = set()
    for row in rows:
        case_id, repetition = row.get("case_id"), row.get("repetition")
        if not isinstance(case_id, str) or not isinstance(repetition, int) or isinstance(repetition, bool):
            failures.append(f"{label} contains a malformed observation identity")
            continue
        key = case_id, repetition
        if key in seen:
            failures.append(f"{label} contains duplicate observation {case_id}/{repetition}")
        seen.add(key)
    return seen


def _ledger_errors(suite: Suite, manifest: dict[str, Any], run_dir: Path) -> list[str]:
    from .runner import _judge_result, _judge_system_prompt, build_judge_payload, build_target_payload, target_case_prompt

    failures: list[str] = []
    parameters_value = manifest.get("parameters")
    parameters: dict[str, Any] = parameters_value if isinstance(parameters_value, dict) else {}
    repetitions = parameters.get("repetitions")
    if not isinstance(repetitions, int) or isinstance(repetitions, bool) or repetitions < 1:
        return ["official manifest repetitions are invalid"]
    requests = _jsonl(run_dir / "requests.jsonl")
    responses = _jsonl(run_dir / "raw_responses.jsonl")
    judgments = _jsonl(run_dir / "judgments.jsonl")
    results = _jsonl(run_dir / "case_results.jsonl")
    expected = {(str(case["id"]), repetition) for case in suite.cases for repetition in range(1, repetitions + 1)}
    target_requests = [row for row in requests if row.get("kind") == "target"]
    judge_requests = [row for row in requests if row.get("kind") == "judge"]
    for label, rows in (("case results", results), ("target requests", target_requests), ("target responses", responses)):
        if _keys(rows, label, failures) != expected:
            failures.append(f"{label} do not exactly match the scheduled observations")

    response_by_key = {(str(row.get("case_id")), int(row.get("repetition", 0))): row for row in responses}
    target_request_by_key = {(str(row.get("case_id")), int(row.get("repetition", 0))): row for row in target_requests}
    judgments_by_key: dict[tuple[str, int], list[dict[str, Any]]] = {}
    for row in judgments:
        key = str(row.get("case_id")), int(row.get("repetition", 0))
        judgments_by_key.setdefault(key, []).append(row)
    judge_value = manifest.get("judge")
    judge: dict[str, Any] = judge_value if isinstance(judge_value, dict) else {}
    models_value = judge.get("models")
    models: list[Any] = models_value if isinstance(models_value, list) else []
    specs = {str(item.get("id")): item for item in models if isinstance(item, dict)}
    judge_repetitions = parameters.get("judge_repetitions")
    repetitions_per_judge = judge_repetitions if isinstance(judge_repetitions, int) and not isinstance(judge_repetitions, bool) else 0
    expected_judgments = repetitions_per_judge * len(specs)
    request_judge_ids = {
        (row.get("case_id"), row.get("repetition"), row.get("judge_id"), row.get("judge_repetition")) for row in judge_requests
    }
    output_judge_ids = {
        (row.get("case_id"), row.get("repetition"), row.get("judge_id"), row.get("judge_repetition")) for row in judgments
    }
    if len(request_judge_ids) != len(judge_requests) or request_judge_ids != output_judge_ids:
        failures.append("judge request and output ledgers do not exactly reconcile")
    judge_request_by_id = {
        (str(row.get("case_id")), int(row.get("repetition", 0)), str(row.get("judge_id")), int(row.get("judge_repetition", 0))): row
        for row in judge_requests
    }

    cases = {str(case["id"]): case for case in suite.cases}
    target_value = manifest.get("target")
    target: dict[str, Any] = target_value if isinstance(target_value, dict) else {}
    for result in results:
        key = str(result.get("case_id")), int(result.get("repetition", 0))
        response = response_by_key.get(key)
        target_request = target_request_by_key.get(key)
        case = cases.get(key[0])
        raw = response.get("response") if isinstance(response, dict) else None
        if case is None or not isinstance(raw, dict) or not isinstance(target_request, dict):
            failures.append(f"scheduled observation {key[0]}/{key[1]} has missing or malformed target evidence")
            continue
        assert isinstance(response, dict)
        expected_metadata = {
            "category": case["category"],
            "risk_domain": case["risk_domain"],
            "severity": case["severity"],
            "language": case.get("language", "missing"),
            "locale": case.get("locale", "missing"),
            "split": case.get("split", "missing"),
            "operating_condition": case.get("operating_condition", "missing"),
            "distribution_shift_reference_id": case.get("distribution_shift_reference_id"),
            "scenario_id": case.get("scenario_group_id") or case.get("scenario_id"),
            "performance_phase": case.get("performance_phase", "steady"),
        }
        changed_metadata = sorted(field for field, expected_value in expected_metadata.items() if result.get(field) != expected_value)
        if changed_metadata:
            failures.append(f"case result metadata differs from suite evidence for {key[0]}/{key[1]}: {changed_metadata}")
        try:
            answer, reported = _answer(suite, raw)
            target_config = suite.config.get("target") or {}
            deterministic = deterministic_evaluation(
                case,
                answer,
                target_raw=raw,
                retrieved_ids=_dotted(raw, str(target_config.get("retrieved_ids_field", "retrieved_ids"))) or [],
                tool_calls=_dotted(raw, str(target_config.get("tools_field", "tool_calls"))) or [],
            )
        except ProtocolError as exc:
            failures.append(str(exc))
            continue
        if reported != target.get("expected_reported_model") or response.get("reported_model") != reported:
            failures.append(f"target identity mismatch in observation {key[0]}/{key[1]}")
        try:
            expected_target_payload = build_target_payload(
                suite,
                target_case_prompt(case, str((suite.config.get("target") or {}).get("kind", "json"))),
                target.get("request_model") if isinstance(target.get("request_model"), str) else None,
                recorded_responses_sha256=(
                    target.get("recorded_responses_sha256") if isinstance(target.get("recorded_responses_sha256"), str) else None
                ),
            )
        except (OSError, ProtocolError, ValueError) as exc:
            failures.append(f"target payload cannot be reconstructed for {key[0]}/{key[1]}: {exc}")
        else:
            if target_request.get("payload") != expected_target_payload:
                failures.append(f"target request differs from suite snapshots for {key[0]}/{key[1]}")
        target_transport = response.get("transport")
        if not isinstance(target_transport, dict) or target_transport.get("request_id") != target_request.get("request_id"):
            failures.append(f"target transport does not bind its request for {key[0]}/{key[1]}")
        if isinstance(target_transport, dict):
            projected = {
                "target_latency_ms": target_transport.get("total_ms"),
                "target_headers_ms": target_transport.get("headers_ms"),
                "target_response_bytes": target_transport.get("response_bytes"),
            }
            if "ttft_ms" in target_transport:
                projected["ttft_ms"] = target_transport["ttft_ms"]
            if isinstance(target_transport.get("inter_chunk_ms"), dict):
                projected["inter_chunk_ms"] = target_transport["inter_chunk_ms"]
            usage = raw.get("usage")
            if isinstance(usage, dict):
                projected["input_tokens"] = usage.get("prompt_tokens")
                projected["output_tokens"] = usage.get("completion_tokens")
                output_tokens = usage.get("completion_tokens")
                latency_ms = target_transport.get("total_ms")
                if isinstance(output_tokens, (int, float)) and isinstance(latency_ms, (int, float)) and latency_ms > 0:
                    projected["output_tokens_per_second"] = float(output_tokens) / (float(latency_ms) / 1000)
            performance_fields = {
                "target_latency_ms",
                "target_headers_ms",
                "target_response_bytes",
                "ttft_ms",
                "inter_chunk_ms",
                "input_tokens",
                "output_tokens",
                "output_tokens_per_second",
            }
            changed = sorted(
                field
                for field in performance_fields
                if (field in result) != (field in projected) or result.get(field) != projected.get(field)
            )
            if changed:
                failures.append(f"case result performance projection differs from raw evidence for {key[0]}/{key[1]}: {changed}")
        if result.get("deterministic") != deterministic:
            failures.append(f"deterministic result differs from raw evidence for {key[0]}/{key[1]}")
        selected = judgments_by_key.get(key, [])
        if not deterministic["hard_pass"]:
            if result.get("status") != "fail" or result.get("reason") != "deterministic check failed" or selected:
                failures.append(f"deterministic failure was overridden for {key[0]}/{key[1]}")
            continue
        if len(selected) != expected_judgments:
            failures.append(f"observation {key[0]}/{key[1]} lacks exact judge evidence")
            continue
        observed_models = {(row.get("judge_id"), row.get("model_repetition")) for row in selected}
        expected_models = {(judge_id, model_repetition) for judge_id in specs for model_repetition in range(1, repetitions_per_judge + 1)}
        if observed_models != expected_models:
            failures.append(f"observation {key[0]}/{key[1]} lacks the exact multi-judge repetition matrix")
        verdicts: list[str] = []
        scores: list[int] = []
        for row in selected:
            spec = specs.get(str(row.get("judge_id")))
            judgment = row.get("judgment")
            raw_judge = row.get("raw")
            request = judge_request_by_id.get(
                (key[0], key[1], str(row.get("judge_id")), int(row.get("judge_repetition", 0)))
            )
            if not isinstance(spec, dict) or not isinstance(judgment, dict) or not isinstance(raw_judge, dict) or not isinstance(request, dict):
                failures.append(f"malformed judge evidence for {key[0]}/{key[1]}")
                continue
            if (
                row.get("requested_model") != spec.get("model")
                or request.get("requested_model") != spec.get("model")
                or row.get("judge_revision") != spec.get("revision")
                or request.get("judge_revision") != spec.get("revision")
            ):
                failures.append(f"judge evidence differs from manifest configuration for {key[0]}/{key[1]}")
            try:
                expected_judge_payload = build_judge_payload(suite, str(spec.get("model", "")), case, answer, raw)
            except (OSError, ProtocolError, ValueError) as exc:
                failures.append(f"judge payload cannot be reconstructed for {key[0]}/{key[1]}: {exc}")
            else:
                if request.get("payload") != expected_judge_payload:
                    failures.append(f"judge request differs from suite and response snapshots for {key[0]}/{key[1]}")
            judge_transport = row.get("transport")
            if not isinstance(judge_transport, dict) or judge_transport.get("request_id") != request.get("request_id"):
                failures.append(f"judge transport does not bind its request for {key[0]}/{key[1]}")
            try:
                parsed, content = _judge_result(raw_judge)
            except ProtocolError:
                parsed, content = None, None
            if parsed != judgment or row.get("raw_content") != content:
                failures.append(f"judge projection differs from raw output for {key[0]}/{key[1]}")
                continue
            if raw_judge.get("model") != row.get("reported_model") or row.get("reported_model") != spec.get("expected_model"):
                failures.append(f"judge identity mismatch for {key[0]}/{key[1]}")
            verdicts.append(str(judgment["verdict"]))
            score = judgment.get("score")
            if isinstance(score, int) and not isinstance(score, bool):
                scores.append(score)
        passes, fails = verdicts.count("pass"), verdicts.count("fail")
        consensus = judge.get("consensus")
        expected_status = "invalid" if len(verdicts) != expected_judgments or passes == fails or (consensus == "unanimous" and passes and fails) else ("pass" if passes > fails else "fail")
        if result.get("status") != expected_status:
            failures.append(f"case result disagrees with judge evidence for {key[0]}/{key[1]}")
        if expected_status in {"pass", "fail"}:
            agreement = max(passes, fails) / len(verdicts)
            score = sum(scores) / len(scores) if len(scores) == expected_judgments else None
            if result.get("judge_agreement") != agreement or result.get("score") != score:
                failures.append(f"judge score or agreement differs for {key[0]}/{key[1]}")

    request_ids = [row.get("request_id") for row in requests]
    if any(not isinstance(value, str) or not value for value in request_ids) or len(request_ids) != len(set(request_ids)):
        failures.append("request ledger contains missing or duplicate request IDs")
    expected_prompt_hash = sha256_bytes(_judge_system_prompt(suite).encode("utf-8"))
    if judge.get("prompt_sha256") != expected_prompt_hash:
        failures.append("judge prompt hash differs from the rubric snapshot")
    if (run_dir / "engine_results.jsonl").is_file() and _jsonl(run_dir / "engine_results.jsonl"):
        failures.append("official behavior verification does not support external metric-engine evidence")
    return failures


def _official_metrics_structure_errors(metrics: Any) -> list[str]:
    failures = _closed_object_errors(metrics, OFFICIAL_METRIC_FIELDS, "official metrics")
    if not isinstance(metrics, dict):
        return failures
    ci_fields = {"lower", "upper", "confidence"}
    distribution_fields = {"count", "min", "max", "mean", "median", "stdev", "p50", "p90", "p95", "p99"}
    summary_fields = {
        "total",
        "observations",
        "pass",
        "fail",
        "invalid",
        "error",
        "skipped",
        "pass_rate",
        "pass_rate_ci",
        "pass_rate_ci95",
        "officially_valid",
    }

    def closed(value: Any, fields: set[str], label: str) -> None:
        if isinstance(value, dict):
            failures.extend(_closed_object_errors(value, fields, label))

    def interval(value: Any, label: str, *, bootstrap: bool = False, stratified: bool = False) -> None:
        fields = ci_fields | ({"samples", "seed"} if bootstrap else set()) | ({"strata"} if stratified else set())
        closed(value, fields, label)

    def summary(value: Any, label: str) -> None:
        if not isinstance(value, dict):
            return
        closed(value, summary_fields, label)
        interval(value.get("pass_rate_ci"), f"{label}.pass_rate_ci")
        closed(value.get("pass_rate_ci95"), {"lower", "upper"}, f"{label}.pass_rate_ci95")

    def distribution(value: Any, label: str) -> None:
        closed(value, distribution_fields, label)

    interval(metrics.get("pass_rate_ci"), "official metrics.pass_rate_ci")
    closed(metrics.get("pass_rate_ci95"), {"lower", "upper"}, "official metrics.pass_rate_ci95")
    interval(metrics.get("pass_rate_bootstrap_ci"), "official metrics.pass_rate_bootstrap_ci", bootstrap=True)
    interval(
        metrics.get("pass_rate_stratified_bootstrap_ci"),
        "official metrics.pass_rate_stratified_bootstrap_ci",
        bootstrap=True,
        stratified=True,
    )
    summary(metrics.get("case_level"), "official metrics.case_level")
    categories = metrics.get("case_categories")
    category_fields = {"category", "total", "pass", "fail", "invalid", "error", "pass_rate", "ci95_lower", "ci95_upper", "confidence"}
    if isinstance(categories, list):
        for index, category in enumerate(categories):
            failures.extend(_closed_object_errors(category, category_fields, f"official metrics.case_categories[{index}]"))
    slices = metrics.get("slices")
    if isinstance(slices, dict):
        for dimension, values in slices.items():
            if isinstance(values, dict):
                for value, measured in values.items():
                    summary(measured, f"official metrics.slices.{dimension}.{value}")
    stability = metrics.get("stability")
    closed(stability, {"case_pass_fraction", "stable_case_fraction", "judge_agreement", "judge_score"}, "official metrics.stability")
    if isinstance(stability, dict):
        for field in ("case_pass_fraction", "judge_agreement", "judge_score"):
            distribution(stability.get(field), f"official metrics.stability.{field}")
    calibration_fields = {
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

    def calibration(value: Any, label: str, *, with_slices: bool) -> None:
        if not isinstance(value, dict):
            return
        closed(value, calibration_fields | ({"slices"} if with_slices else set()), label)
        interval(value.get("failure_sensitivity_ci"), f"{label}.failure_sensitivity_ci")
        interval(value.get("pass_specificity_ci"), f"{label}.pass_specificity_ci")
        nested = value.get("slices")
        if with_slices and isinstance(nested, dict):
            for dimension, values in nested.items():
                if isinstance(values, dict):
                    for slice_value, measured in values.items():
                        calibration(measured, f"{label}.slices.{dimension}.{slice_value}", with_slices=False)

    calibrations = metrics.get("judge_calibration")
    if isinstance(calibrations, dict):
        for judge_id, result in calibrations.items():
            calibration(result, f"official metrics.judge_calibration.{judge_id}", with_slices=True)
    performance = metrics.get("performance")
    performance_distributions = {
        "target_latency_ms",
        "target_response_bytes",
        "input_tokens",
        "output_tokens",
        "ttft_ms",
        "output_tokens_per_second",
    }
    closed(
        performance,
        performance_distributions
        | {"elapsed_seconds", "observations_per_second", "target_calls_per_second", "observation_success_rate", "observation_error_rate"},
        "official metrics.performance",
    )
    if isinstance(performance, dict):
        for field in performance_distributions:
            distribution(performance.get(field), f"official metrics.performance.{field}")
    phases = metrics.get("performance_by_phase")
    closed(phases, {"cold", "warmup", "steady", "soak"}, "official metrics.performance_by_phase")
    if isinstance(phases, dict):
        for phase, value in phases.items():
            distribution(value, f"official metrics.performance_by_phase.{phase}")
    closed(metrics.get("budgets"), {"target_calls", "judge_calls", "total_tokens", "exhausted"}, "official metrics.budgets")
    closed(
        metrics.get("cost"),
        {"currency", "source", "effective_at", "input_tokens", "output_tokens", "judge_input_tokens", "judge_output_tokens", "estimated_total"},
        "official metrics.cost",
    )
    gates = metrics.get("gate_failures")
    if isinstance(gates, list):
        for index, gate in enumerate(gates):
            failures.extend(_closed_object_errors(gate, {"category", "metric", "minimum", "actual"}, f"official metrics.gate_failures[{index}]"))
    shift = metrics.get("distribution_shift")
    closed(shift, {"declared_pairs", "valid_pairs", "invalid_pairs", "comparison", "by_category"}, "official metrics.distribution_shift")
    comparison_fields = {
        "cases",
        "baseline_pass_rate",
        "candidate_pass_rate",
        "absolute_delta",
        "relative_delta",
        "delta_ci",
        "mcnemar",
        "wins",
        "ties",
        "losses",
    }

    def comparison(value: Any, label: str) -> None:
        if not isinstance(value, dict):
            return
        closed(value, comparison_fields, label)
        interval(value.get("delta_ci"), f"{label}.delta_ci", bootstrap=True)
        closed(value.get("mcnemar"), {"baseline_only", "candidate_only", "discordant", "p_value"}, f"{label}.mcnemar")

    if isinstance(shift, dict):
        comparison(shift.get("comparison"), "official metrics.distribution_shift.comparison")
        categories_value = shift.get("by_category")
        if isinstance(categories_value, dict):
            for category, value in categories_value.items():
                comparison(value, f"official metrics.distribution_shift.by_category.{category}")
    return failures


def _official_manifest_structure_errors(manifest: Any) -> list[str]:
    failures = _closed_object_errors(manifest, OFFICIAL_MANIFEST_FIELDS, "official manifest")
    if not isinstance(manifest, dict):
        return failures
    missing = sorted((OFFICIAL_MANIFEST_FIELDS - {"resumed_at"}) - set(manifest))
    if missing:
        failures.append(f"official manifest is missing fields: {missing}")
    if manifest.get("schema_version") != SCHEMA_VERSION:
        failures.append(f"official manifest schema_version must be {SCHEMA_VERSION}")
    if manifest.get("metric_version") != METRIC_VERSION:
        failures.append(f"official manifest metric_version must be {METRIC_VERSION}")
    object_fields = {
        "suite": {"name", "version", "status", "dataset_sha256", "rubric_sha256", "suite_config_sha256", "data_classification", "profile"},
        "target": {"label", "expected_reported_model", "revision", "endpoint", "request_model", "kind", "capabilities", "recorded_responses_sha256"},
        "judge": {"requested_model", "expected_reported_model", "revision", "endpoint", "prompt_sha256", "response_schema", "temperature", "models", "consensus"},
        "judge_qualification": {"qualification_sha256", "approval_sha256", "approval_id", "approver_id", "approved_at", "expires_at"},
        "engagement": {
            "engagement_id",
            "sha256",
            "status",
            "cavadalabs_roles",
            "jurisdictions",
            "permitted_claims",
            "prohibited_claims",
            "execution_owner_id",
            "commercial_owner_id",
            "approved_at",
            "expires_at",
            "authorization_evidence_sha256",
            "conflict_assessment_evidence_sha256",
            "legal_applicability_evidence_sha256",
            "approver_qualification_evidence_sha256",
        },
        "external_authorization": {"authorization_id", "approver", "purpose", "destinations", "expires_at"},
        "artifact_security": {"classification", "retention", "storage_attestation", "encryption_state", "immutability_state"},
        "parameters": {
            "mode",
            "preset",
            "preset_version",
            "repetitions",
            "judge_repetitions",
            "max_cases",
            "selected_cases",
            "timeout_seconds",
            "max_target_calls",
            "max_judge_calls",
            "max_total_tokens",
            "max_elapsed_seconds",
            "max_estimated_cost",
            "concurrency",
            "requests_per_second",
            "progress_events",
            "case_order_policy",
            "case_order_sha256",
            "cache",
        },
        "pricing": {"currency", "source", "effective_at", "input_per_million", "output_per_million", "judge_input_per_million", "judge_output_per_million"},
        "source": {"commit", "dirty", "status_sha256", "implementation_sha256"},
        "environment": {"python", "platform", "hardware", "uv_lock_sha256"},
    }
    exact_fields = set(object_fields) - {"external_authorization", "pricing"}
    for field, allowed in object_fields.items():
        value = manifest.get(field)
        if value is not None:
            failures.extend(_closed_object_errors(value, allowed, f"official manifest.{field}"))
            required = allowed
            if field == "pricing":
                required = {"currency", "source", "effective_at", "input_per_million", "output_per_million"}
            missing_nested = sorted(required - set(value)) if isinstance(value, dict) else []
            if missing_nested:
                failures.append(f"official manifest.{field} is missing fields: {missing_nested}")
        elif field in exact_fields:
            failures.append(f"official manifest.{field} must be an object")
    judge = manifest.get("judge")
    if isinstance(judge, dict) and isinstance(judge.get("models"), list):
        for index, model in enumerate(judge["models"]):
            failures.extend(_closed_object_errors(model, {"id", "model", "expected_model", "revision"}, f"official manifest.judge.models[{index}]"))
        identifiers = [model.get("id") for model in judge["models"] if isinstance(model, dict)]
        if len(identifiers) != len(judge["models"]) or len(identifiers) != len(set(map(str, identifiers))):
            failures.append("official manifest judge model ids must be present and unique")
    authorization = manifest.get("external_authorization")
    if isinstance(authorization, dict) and isinstance(authorization.get("destinations"), list):
        for index, destination in enumerate(authorization["destinations"]):
            failures.extend(_closed_object_errors(destination, {"host", "region", "purpose"}, f"official manifest.external_authorization.destinations[{index}]"))
    security = manifest.get("artifact_security")
    if isinstance(security, dict) and isinstance(security.get("storage_attestation"), dict):
        failures.extend(
            _closed_object_errors(
                security["storage_attestation"],
                {
                    "attestation_id",
                    "approver",
                    "encryption_at_rest",
                    "immutability",
                    "access_policy_reference",
                    "audit_log_reference",
                    "retention_policy_reference",
                    "backup_restore_reference",
                    "effective_at",
                    "expires_at",
                },
                "official manifest.artifact_security.storage_attestation",
            )
        )
    parameters = manifest.get("parameters")
    if isinstance(parameters, dict) and parameters.get("cache") is not None:
        failures.extend(_closed_object_errors(parameters["cache"], {"target", "judge"}, "official manifest.parameters.cache"))
    environment = manifest.get("environment")
    if isinstance(environment, dict) and environment.get("hardware") is not None:
        failures.extend(
            _closed_object_errors(
                environment["hardware"],
                {"machine", "processor", "cpu_count", "memory_bytes", "gpus", "gpu_inventory_source"},
                "official manifest.environment.hardware",
            )
        )
    if isinstance(manifest.get("metrics"), dict):
        failures.extend(_official_metrics_structure_errors(manifest["metrics"]))
    return failures


def _official_errors(run_dir: Path, manifest: dict[str, Any], bundle: dict[str, Any], now: datetime) -> list[str]:
    failures = _official_manifest_structure_errors(manifest)
    if manifest.get("status") != "passed" or manifest.get("official") is not True or manifest.get("official_requested") is not True or manifest.get("abort_reason") != "":
        failures.append("manifest is not a completed non-aborted official behavior run")
    parameters = manifest.get("parameters")
    if not isinstance(parameters, dict) or parameters.get("preset") != "reference" or parameters.get("mode") != "official":
        failures.append("official behavior runs require the reference preset and official mode")
    source_value = manifest.get("source")
    source = source_value if isinstance(source_value, dict) else {}
    if (
        not isinstance(source_value, dict)
        or re.fullmatch(r"[a-f0-9]{40}|[a-f0-9]{64}", str(source.get("commit", ""))) is None
        or source.get("dirty") is not False
        or _HASH.fullmatch(str(source.get("status_sha256", ""))) is None
        or _HASH.fullmatch(str(source.get("implementation_sha256", ""))) is None
    ):
        failures.append("official source evidence must identify a clean immutable commit and status")
    elif source["status_sha256"] != sha256_bytes(b""):
        failures.append("clean official source evidence requires the empty git status digest")
    try:
        started = datetime.fromisoformat(str(manifest.get("started_at", "")).replace("Z", "+00:00"))
        finished = datetime.fromisoformat(str(manifest.get("finished_at", "")).replace("Z", "+00:00"))
        if started.tzinfo is None or finished.tzinfo is None or not started <= finished <= now:
            failures.append("run timestamps are invalid or inconsistent")
    except ValueError:
        failures.append("run timestamps are invalid or inconsistent")

    artifacts = manifest.get("artifacts")
    bundle_files = bundle.get("files")
    if not isinstance(artifacts, dict) or not isinstance(bundle_files, dict):
        return failures + ["official artifact maps are malformed"]
    if not _REQUIRED_OFFICIAL_ARTIFACTS <= set(artifacts):
        failures.append(f"official run is missing required artifacts: {sorted(_REQUIRED_OFFICIAL_ARTIFACTS - set(artifacts))}")
    if any(bundle_files.get(name) != digest for name, digest in artifacts.items()):
        failures.append("manifest artifact map differs from bundle.json")

    suite_temporary: TemporaryDirectory[str] | None = None
    try:
        suite_temporary, suite = _materialize_suite(run_dir)
        target_config = suite.config.get("target") or {}
        report_config = suite.config.get("report") or {}
        conformance_fixture = report_config.get("assurance") == "conformance-fixture"
        if not conformance_fixture:
            failures.append(
                "official behavior evidence remains fail-closed until judge qualification run and corpus support bytes are reconstructible"
            )
        expected_assurance = "conformance-fixture" if conformance_fixture else "official"
        expected_claim_allowed = not conformance_fixture
        if conformance_fixture and (
            target_config.get("kind") != "recorded"
            or report_config.get("model_claim_allowed") is not False
            or report_config.get("benchmark_claim_allowed") is not False
        ):
            failures.append("conformance fixtures must use recorded targets and prohibit claims")
        if (
            manifest.get("assurance") != expected_assurance
            or manifest.get("model_claim_allowed") is not expected_claim_allowed
            or manifest.get("benchmark_claim_allowed") is not expected_claim_allowed
        ):
            failures.append("manifest assurance and claim flags differ from reconstructed suite semantics")
        judge_value = manifest.get("judge")
        judge_manifest = judge_value if isinstance(judge_value, dict) else {}
        judge_host = urllib.parse.urlparse(str(judge_manifest.get("endpoint", ""))).hostname
        if conformance_fixture and judge_host not in {"127.0.0.1", "localhost", "::1"}:
            failures.append("conformance fixtures require a loopback judge")
        suite_value = manifest.get("suite")
        suite_manifest: dict[str, Any] = suite_value if isinstance(suite_value, dict) else {}
        expected_suite = {
            "name": suite.name,
            "version": suite.version,
            "status": suite.status,
            "dataset_sha256": sha256_file(suite.dataset_path),
            "rubric_sha256": sha256_file(suite.rubric_path),
            "suite_config_sha256": sha256_file(suite.root / "suite.toml"),
            "data_classification": suite.config.get("data_classification"),
            "profile": suite.config.get("profile", "text-generation"),
        }
        if suite_manifest != expected_suite:
            failures.append("manifest suite differs from reconstructed official snapshots")
        protocol_hash = manifest.get("protocol_sha256")
        if not isinstance(protocol_hash, str) or protocol_hash != sha256_file(run_dir / "protocol_snapshot.md"):
            failures.append("protocol snapshot differs from the manifest digest")
        if manifest.get("environment") != _object(run_dir / "environment.json", "environment evidence"):
            failures.append("manifest environment differs from environment.json")

        with TemporaryDirectory(prefix="cavada-behavior-implementation-") as implementation_root_text:
            implementation_root = Path(implementation_root_text)
            implementation_files = _materialize_files(
                implementation_root,
                run_dir / "implementation_evidence_manifest.json",
                run_dir / "implementation_evidence",
                "implementation evidence",
            )
            if not implementation_files or any(not path.endswith(".py") for path in implementation_files):
                failures.append("implementation evidence must be a non-empty Python source closure")
            else:
                from .runner import _python_source_digest

                if _python_source_digest(implementation_root) != source.get("implementation_sha256"):
                    failures.append("implementation evidence does not match the manifest source digest")

        qualification = _object(run_dir / "judge_qualification_snapshot.json", "judge qualification snapshot")
        approval = _object(run_dir / "judge_approval_snapshot.json", "judge approval snapshot")
        qualification_value = manifest.get("judge_qualification")
        qualification_manifest: dict[str, Any] = qualification_value if isinstance(qualification_value, dict) else {}
        if qualification_manifest.get("qualification_sha256") != sha256_file(run_dir / "judge_qualification_snapshot.json") or qualification_manifest.get(
            "approval_sha256"
        ) != sha256_file(run_dir / "judge_approval_snapshot.json"):
            failures.append("judge evidence snapshots differ from the manifest")
        failures.extend(
            judge_evidence_errors(
                qualification,
                approval,
                qualification_sha256=sha256_file(run_dir / "judge_qualification_snapshot.json"),
                expected_judge=manifest.get("judge"),
                rubric_sha256=sha256_file(suite.rubric_path),
                expected_blueprint_sha256=(suite.config.get("judge") or {}).get("qualification_blueprint_sha256"),
                expected_blueprint_approval_sha256=(suite.config.get("judge") or {}).get(
                    "qualification_blueprint_approval_sha256"
                ),
                now=now,
            )
        )

        with TemporaryDirectory(prefix="cavada-behavior-engagement-") as engagement_root_text:
            engagement_root = Path(engagement_root_text)
            engagement_path = engagement_root / "engagement.json"
            engagement_path.write_bytes((run_dir / "engagement_snapshot.json").read_bytes())
            _materialize_files(
                engagement_root,
                run_dir / "engagement_evidence_manifest.json",
                run_dir / "engagement_evidence",
                "engagement evidence",
            )
            from .release import verified_engagement

            target_value = manifest.get("target")
            target = target_value if isinstance(target_value, dict) else {}
            engagement = verified_engagement(
                engagement_path,
                suite,
                expected_model=str(target.get("expected_reported_model", "")),
                model_revision=str(target.get("revision", "")),
                now=now,
            )
            if manifest.get("engagement") != engagement:
                failures.append("manifest engagement differs from reconstructed evidence and claim scope")

        metrics = _object(run_dir / "metrics.json", "run metrics")
        failures.extend(_official_metrics_structure_errors(metrics))
        if manifest.get("metrics") != metrics:
            failures.append("manifest metrics differ from metrics.json")
        if metrics.get("officially_valid") is not True or metrics.get("aborted") is not False or metrics.get("gate_failures") != [] or any(
            metrics.get(field) != 0 for field in ("invalid", "error", "skipped")
        ):
            failures.append("official metrics contain abort, invalid, error, skipped, or gate failure evidence")
        results = _jsonl(run_dir / "case_results.jsonl")
        from .runner import _distribution_shift_summary, _judge_calibration_summary, _scenario_analysis_rows, _usage_tokens

        statistics_config = suite.config.get("statistics") or {}
        confidence = float(statistics_config.get("confidence", 0.95))
        bootstrap_samples = int(statistics_config.get("bootstrap_samples", 10_000))
        bootstrap_seed = int(statistics_config.get("seed", 0))
        case_metrics, case_categories = summarize(results, confidence=confidence)
        scenarios = _scenario_analysis_rows(results, suite.cases)
        analysis = scenarios if scenarios is not None else results
        calculated, categories = summarize(analysis, confidence=confidence)
        for field in ("total", "observations", "pass", "fail", "invalid", "error", "skipped", "pass_rate", "pass_rate_ci", "pass_rate_ci95", "officially_valid"):
            if metrics.get(field) != calculated.get(field):
                failures.append(f"metrics {field} does not reconcile with case_results.jsonl")
        if metrics.get("analysis_unit") != ("scenario" if scenarios is not None else "case") or metrics.get("evaluation_cases") != case_metrics["total"] or metrics.get(
            "target_observations"
        ) != case_metrics["observations"]:
            failures.append("metric analysis unit or observation counts do not reconcile")
        if scenarios is not None:
            if _jsonl(run_dir / "scenario_results.jsonl") != scenarios or metrics.get("case_level") != case_metrics or metrics.get("case_categories") != case_categories:
                failures.append("scenario and case-level metrics do not reconcile")
        reconstructed: dict[str, Any] = {
            **calculated,
            "analysis_unit": "scenario" if scenarios is not None else "case",
            "evaluation_cases": case_metrics["total"],
            "target_observations": case_metrics["observations"],
        }
        if scenarios is not None:
            reconstructed.update({"case_level": case_metrics, "case_categories": case_categories})
        statuses_by_case: dict[str, list[str]] = {}
        for row in analysis:
            statuses_by_case.setdefault(str(row["case_id"]), []).append(str(row["status"]))
        binary = [
            1.0 if set(statuses) == {"pass"} else 0.0
            for statuses in statuses_by_case.values()
            if set(statuses) <= {"pass", "fail"}
        ]
        reconstructed["pass_rate_bootstrap_ci"] = (
            bootstrap_mean_interval(binary, confidence=confidence, samples=bootstrap_samples, seed=bootstrap_seed)
            if binary
            else {"lower": 0.0, "upper": 0.0, "confidence": confidence, "samples": bootstrap_samples, "seed": bootstrap_seed}
        )
        category_binary: dict[str, list[float]] = {}
        for case_id, statuses in statuses_by_case.items():
            selected = [row for row in analysis if str(row.get("case_id")) == case_id]
            if selected and set(statuses) <= {"pass", "fail"}:
                category_binary.setdefault(str(selected[0]["category"]), []).append(1.0 if set(statuses) == {"pass"} else 0.0)
        reconstructed["pass_rate_stratified_bootstrap_ci"] = stratified_bootstrap_mean_interval(
            category_binary,
            confidence=confidence,
            samples=bootstrap_samples,
            seed=bootstrap_seed,
        )
        shift = _distribution_shift_summary(
            results,
            suite.cases,
            confidence=confidence,
            samples=bootstrap_samples,
            seed=bootstrap_seed,
        )
        if shift is not None:
            reconstructed["distribution_shift"] = shift
        reconstructed["slices"] = {
            dimension: {
                value: summarize([row for row in analysis if str(row.get(dimension, "missing")) == value], confidence=confidence)[0]
                for value in sorted({str(row.get(dimension, "missing")) for row in analysis})
            }
            for dimension in ("risk_domain", "severity", "language", "locale", "split", "operating_condition")
        }
        reconstructed["slice_disparities"] = {
            dimension: max((float(item["pass_rate"]) for item in values.values()), default=0.0)
            - min((float(item["pass_rate"]) for item in values.values()), default=0.0)
            for dimension, values in reconstructed["slices"].items()
        }
        result_statuses: dict[str, list[str]] = {}
        for row in results:
            result_statuses.setdefault(str(row["case_id"]), []).append(str(row["status"]))
        repetition_rates = [
            sum(status == "pass" for status in valid) / len(valid)
            for statuses in result_statuses.values()
            if (valid := [status for status in statuses if status in {"pass", "fail"}])
        ]
        reconstructed["stability"] = {
            "case_pass_fraction": distribution(repetition_rates),
            "stable_case_fraction": sum(value in {0.0, 1.0} for value in repetition_rates) / len(repetition_rates) if repetition_rates else 0.0,
            "judge_agreement": distribution(row["judge_agreement"] for row in results if isinstance(row.get("judge_agreement"), (int, float))),
            "judge_score": distribution(row["score"] for row in results if isinstance(row.get("score"), (int, float))),
        }
        judgments = _jsonl(run_dir / "judgments.jsonl")
        reconstructed["judge_calibration"] = _judge_calibration_summary(judgments, suite)
        timing = _object(run_dir / "timing.json", "timing evidence")
        timing_fields = {"started_at", "finished_at", "elapsed_seconds"}
        failures.extend(_closed_object_errors(timing, timing_fields, "timing evidence"))
        if set(timing) != timing_fields:
            failures.append(f"timing evidence is missing fields: {sorted(timing_fields - set(timing))}")
        elapsed = 1.0
        try:
            timing_started = datetime.fromisoformat(str(timing.get("started_at", "")).replace("Z", "+00:00"))
            timing_finished = datetime.fromisoformat(str(timing.get("finished_at", "")).replace("Z", "+00:00"))
            reconstructed_elapsed = (timing_finished - timing_started).total_seconds()
            declared_elapsed = timing.get("elapsed_seconds")
            if (
                timing_started.tzinfo is None
                or timing_finished.tzinfo is None
                or timing_started.utcoffset() != timezone.utc.utcoffset(None)
                or timing_finished.utcoffset() != timezone.utc.utcoffset(None)
                or timing.get("started_at") != manifest.get("started_at")
                or timing.get("finished_at") != manifest.get("finished_at")
                or not isinstance(declared_elapsed, (int, float))
                or isinstance(declared_elapsed, bool)
                or not math.isfinite(float(declared_elapsed))
                or declared_elapsed != reconstructed_elapsed
                or reconstructed_elapsed <= 0
            ):
                failures.append("timing evidence does not reconstruct from the manifest timestamps")
            else:
                elapsed = reconstructed_elapsed
        except (TypeError, ValueError):
            failures.append("timing evidence does not contain valid timezone-aware timestamps")
        requests = _jsonl(run_dir / "requests.jsonl")
        responses = _jsonl(run_dir / "raw_responses.jsonl")
        target_requests = [row for row in requests if row.get("kind") == "target"]
        judge_requests = [row for row in requests if row.get("kind") == "judge"]
        reconstructed["performance"] = {
            "target_latency_ms": distribution(row["target_latency_ms"] for row in results if isinstance(row.get("target_latency_ms"), (int, float))),
            "target_response_bytes": distribution(row["target_response_bytes"] for row in results if isinstance(row.get("target_response_bytes"), (int, float))),
            "input_tokens": distribution(row["input_tokens"] for row in results if isinstance(row.get("input_tokens"), (int, float))),
            "output_tokens": distribution(row["output_tokens"] for row in results if isinstance(row.get("output_tokens"), (int, float))),
            "ttft_ms": distribution(row["ttft_ms"] for row in results if isinstance(row.get("ttft_ms"), (int, float))),
            "output_tokens_per_second": distribution(
                row["output_tokens_per_second"] for row in results if isinstance(row.get("output_tokens_per_second"), (int, float))
            ),
            "elapsed_seconds": elapsed,
            "observations_per_second": len(results) / elapsed,
            "target_calls_per_second": len(target_requests) / elapsed,
            "observation_success_rate": sum(row.get("status") in {"pass", "fail"} for row in results) / len(results) if results else 0.0,
            "observation_error_rate": sum(row.get("status") == "error" for row in results) / len(results) if results else 0.0,
        }
        reconstructed["performance_by_phase"] = {
            phase: distribution(
                row["target_latency_ms"]
                for row in results
                if row.get("performance_phase") == phase and isinstance(row.get("target_latency_ms"), (int, float))
            )
            for phase in ("cold", "warmup", "steady", "soak")
        }
        token_totals = {"target_input": 0.0, "target_output": 0.0, "judge_input": 0.0, "judge_output": 0.0}
        for rows, kind in ((responses, "target"), (judgments, "judge")):
            for row in rows:
                raw = row.get("response") or row.get("raw") or {}
                if isinstance(raw, dict):
                    input_tokens, output_tokens = _usage_tokens(raw)
                    token_totals[f"{kind}_input"] += input_tokens
                    token_totals[f"{kind}_output"] += output_tokens
        reconstructed["budgets"] = {
            "target_calls": len(target_requests),
            "judge_calls": len(judge_requests),
            "total_tokens": sum(token_totals.values()),
            "exhausted": False,
        }
        pricing_value = suite.config.get("pricing")
        pricing = pricing_value if isinstance(pricing_value, dict) else None
        if manifest.get("pricing") != pricing:
            failures.append("manifest pricing differs from the suite snapshot")
        if pricing is not None:
            reconstructed["cost"] = {
                "currency": pricing.get("currency"),
                "source": pricing.get("source"),
                "effective_at": pricing.get("effective_at"),
                "input_tokens": token_totals["target_input"],
                "output_tokens": token_totals["target_output"],
                "judge_input_tokens": token_totals["judge_input"],
                "judge_output_tokens": token_totals["judge_output"],
                "estimated_total": sum(
                    token_totals[f"{kind}_{direction}"] * float(pricing.get(f"{prefix}_per_million", 0)) / 1_000_000
                    for kind, direction, prefix in (
                        ("target", "input", "input"),
                        ("target", "output", "output"),
                        ("judge", "input", "judge_input"),
                        ("judge", "output", "judge_output"),
                    )
                ),
            }
        reconstructed["aborted"] = False
        semantic_metric_fields = {
            "pass_rate_bootstrap_ci",
            "pass_rate_stratified_bootstrap_ci",
            "slices",
            "slice_disparities",
            "stability",
            "judge_calibration",
            "performance",
            "performance_by_phase",
            "budgets",
            *( ["case_level", "case_categories"] if scenarios is not None else [] ),
            *( ["distribution_shift"] if shift is not None else [] ),
            *( ["cost"] if pricing is not None else [] ),
        }
        for field in semantic_metric_fields:
            if metrics.get(field) != reconstructed.get(field):
                failures.append(f"metrics {field} does not reconcile with immutable evidence")
        for absent in ({"case_level", "case_categories"} if scenarios is None else set()) | ({"distribution_shift"} if shift is None else set()) | ({"cost"} if pricing is None else set()):
            if absent in metrics:
                failures.append(f"metrics {absent} exists without reconstructible evidence")
        expected_gates = apply_gates(suite, reconstructed, categories)
        if metrics.get("gate_failures") != expected_gates or expected_gates:
            failures.append("gate results do not reconcile with reconstructed official evidence")
        failures.extend(_ledger_errors(suite, manifest, run_dir))
        expected_failures = [row for row in results if row.get("status") != "pass"]
        actual_failures = _jsonl(run_dir / "failures.jsonl")
        def canonical(row: dict[str, Any]) -> str:
            return json.dumps(row, sort_keys=True, separators=(",", ":"))

        if sorted(map(canonical, actual_failures)) != sorted(map(canonical, expected_failures)):
            failures.append("failure ledger does not reconcile with case_results.jsonl")
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError, ProtocolError, ValueError, TypeError) as exc:
        failures.append(f"official semantic reconstruction failed: {exc}")
    finally:
        if suite_temporary is not None:
            suite_temporary.cleanup()
    return list(dict.fromkeys(failures))


def verify_behavior_run(
    run_dir: Path,
    *,
    signing_key_env: str = "CAVADA_EVAL_SIGNING_KEY",
    write_result: bool = False,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Verify bundle integrity and, for any official claim, reconstruct behavior semantics."""
    integrity = verify_bundle(run_dir, signing_key_env=signing_key_env)
    failures = list(integrity["failures"])
    semantic_required = False
    semantic_failures: list[str] = []
    assurance: Any = None
    model_claim_allowed: Any = None
    benchmark_claim_allowed: Any = None
    if not failures:
        try:
            manifest = _object(run_dir / "manifest.json", "run manifest")
            assurance = manifest.get("assurance")
            model_claim_allowed = manifest.get("model_claim_allowed")
            benchmark_claim_allowed = manifest.get("benchmark_claim_allowed")
            semantic_required = manifest.get("official") is True or manifest.get("official_requested") is True
            semantic_required = semantic_required or assurance in {"official", "conformance-fixture"}
            semantic_required = semantic_required or model_claim_allowed is True or benchmark_claim_allowed is True
            semantic_required = semantic_required or (
                "official" in manifest and manifest.get("official") is not False
            ) or ("official_requested" in manifest and manifest.get("official_requested") is not False)
            if semantic_required:
                bundle = _object(run_dir / "bundle.json", "run bundle")
                semantic_failures = _official_errors(run_dir, manifest, bundle, now or datetime.now(timezone.utc))
        except ProtocolError as exc:
            semantic_failures = [str(exc)]
    failures.extend(semantic_failures)
    result = {
        **integrity,
        "valid": not failures,
        "failures": failures,
        "integrity_valid": integrity["valid"],
        "semantic": {"required": semantic_required, "valid": not semantic_failures, "failures": semantic_failures},
        "assurance": assurance,
        "model_claim_allowed": model_claim_allowed,
        "benchmark_claim_allowed": benchmark_claim_allowed,
    }
    if write_result:
        atomic_json(run_dir / "verification.json", result)
    return result
