from __future__ import annotations

import argparse
import gzip
import json
import os
import shlex
import shutil
import sys
import tarfile
import tempfile
import tomllib
from pathlib import Path
from urllib.parse import urlsplit

from .annotations import annotation_agreement, export_annotation_package, ingest_adjudications, ingest_annotations
from .artifacts import verify_bundle, write_bundle
from .calibration import qualify_judge_run
from .comparison import compare_runs
from .compliance import generate_control_report
from .external import import_external_results
from .pairwise import pairwise_runs
from .performance import (
    PERFORMANCE_PROTOCOL_FILENAME,
    compare_performance_runs,
    load_performance_engagement,
    load_performance_execution_record,
    load_performance_plan,
    load_performance_runtime,
    performance_plan_summary,
    performance_run_preflight,
    run_performance_campaign,
    verify_performance_comparison,
    verify_performance_source_bundle,
)
from .performance_release import export_public_performance
from .pilot import audit_pilot_campaign
from .profiles import benchmark_preset, canonical_preset, preset_summary, profile_summary, stratified_cases
from .program import load_program_registry
from .protocol import ProtocolError, audit_suite, contains_secret_like, load_suite, promote_suite, require_mutable_output_root, sha256_bytes, sha256_file
from .public_verify import verify_public_bundle
from .release import verified_public_release
from .retention import ACTIONS as RETENTION_ACTIONS
from .retention import retention_record
from .runner import run

EXIT_PASS = 0
EXIT_GATE_FAILURE = 1
EXIT_CONFIGURATION = 2
EXIT_INTEGRITY = 3
EXIT_TRANSPORT = 4
EXIT_BUDGET = 5
EXIT_CANCELLED = 130

_PUBLIC_BEHAVIOR_METRICS = (
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
    "gate_failures",
    "aborted",
)


def _run_arguments(command: argparse.ArgumentParser) -> None:
    command.add_argument("suite")
    command.add_argument("--endpoint", required=True)
    command.add_argument("--model-label", required=True)
    command.add_argument("--expected-model", required=True)
    command.add_argument("--model-revision", default="")
    command.add_argument("--request-model")
    command.add_argument("--judge-endpoint", required=True)
    command.add_argument("--judge-model", required=True)
    command.add_argument("--expected-judge-model")
    command.add_argument("--judge-revision", default="")
    command.add_argument("--target-key-env", default="TARGET_API_KEY")
    command.add_argument("--judge-key-env", default="JUDGE_API_KEY")
    command.add_argument("--preset", choices=("smoke", "quick", "standard", "reference", "full"))
    command.add_argument("--repetitions", type=int)
    command.add_argument("--judge-repetitions", type=int)
    command.add_argument("--max-cases", type=int)
    command.add_argument("--timeout", type=float, default=90)
    command.add_argument("--official", action="store_true")
    command.add_argument("--allow-external-judge", action="store_true")
    command.add_argument("--signing-key-env", default="CAVADA_EVAL_SIGNING_KEY")
    command.add_argument("--signing-key-id", default="")
    command.add_argument(
        "--mode",
        choices=("smoke", "regression", "candidate", "official", "redteam", "performance", "load", "soak", "offline", "monitoring"),
    )
    command.add_argument("--max-target-calls", type=int, default=0)
    command.add_argument("--max-judge-calls", type=int, default=0)
    command.add_argument("--max-total-tokens", type=int, default=0)
    command.add_argument("--max-elapsed-seconds", type=float, default=0)
    command.add_argument("--max-estimated-cost", type=float, default=0)
    command.add_argument("--non-inferiority-margin", type=float)
    command.add_argument("--external-authorization", default="")
    command.add_argument("--storage-attestation", default="")
    command.add_argument("--judge-qualification", default="")
    command.add_argument("--judge-approval", default="")
    command.add_argument("--engagement", default="")
    command.add_argument("--concurrency", type=int, default=1)
    command.add_argument("--requests-per-second", type=float, default=0)
    command.add_argument("--progress", action="store_true")
    command.add_argument("--output-root")


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="cavada-eval", description="CavadaLabs reproducible AI evaluation protocol")
    root.add_argument("--version", action="version", version="cavadalabs-evals 0.3.0")
    commands = root.add_subparsers(dest="command", required=True)

    init = commands.add_parser("init", help="Create a new draft suite from the secure template")
    init.add_argument("name")
    init.add_argument("--suites-root", default="suites")

    commands.add_parser("doctor", help="Check the local repository and security-sensitive settings")

    listing = commands.add_parser("list", help="List local suites")
    listing.add_argument("--suites-root")

    commands.add_parser("profiles", help="List benchmark profiles and built-in official support")
    commands.add_parser("presets", help="List the versioned smoke, quick, standard, and reference execution presets")

    program = commands.add_parser("program", help="Validate and show the modular evaluation program registry")
    program.add_argument("--registry", default="program/registry.toml")

    validate = commands.add_parser("validate", help="Validate suite schema and integrity")
    validate.add_argument("suite")
    validate.add_argument("--official", action="store_true")

    annotations = commands.add_parser("annotations", help="Export an identity-blinded human annotation package")
    annotations.add_argument("suite")
    annotations.add_argument("run_dir")
    annotations.add_argument("output")
    annotations.add_argument("linkage_output")

    annotations_ingest = commands.add_parser("annotations-ingest", help="Validate and preserve a completed reviewer package")
    annotations_ingest.add_argument("package")
    annotations_ingest.add_argument("linkage")
    annotations_ingest.add_argument("output")
    annotations_ingest.add_argument("--reviewer-id", required=True)
    annotations_ingest.add_argument("--qualification-evidence", required=True)
    annotations_ingest.add_argument("--conflicts", required=True)

    annotations_agreement = commands.add_parser("annotations-agreement", help="Compute blinded reviewer agreement and disagreements")
    annotations_agreement.add_argument("left")
    annotations_agreement.add_argument("right")
    annotations_agreement.add_argument("output")

    annotations_adjudicate = commands.add_parser("annotations-adjudicate", help="Validate and preserve completed adjudications")
    annotations_adjudicate.add_argument("agreement")
    annotations_adjudicate.add_argument("left")
    annotations_adjudicate.add_argument("right")
    annotations_adjudicate.add_argument("output")
    annotations_adjudicate.add_argument("--adjudicator-id", required=True)
    annotations_adjudicate.add_argument("--qualification-evidence", required=True)
    annotations_adjudicate.add_argument("--conflicts", required=True)

    judge_qualify = commands.add_parser("judge-qualify", help="Apply preregistered gates to a verified judge calibration run")
    judge_qualify.add_argument("run")
    judge_qualify.add_argument("blueprint")
    judge_qualify.add_argument("corpus_manifest")
    judge_qualify.add_argument("output")

    pilot_audit = commands.add_parser("pilot-audit", help="Verify a complete multi-family target pilot campaign")
    pilot_audit.add_argument("campaign")
    pilot_audit.add_argument("output")

    audit = commands.add_parser("audit", help="Print suite composition, coverage, and hashes")
    audit.add_argument("suite")

    estimate = commands.add_parser("estimate", help="Estimate calls before execution without network access")
    estimate.add_argument("suite")
    estimate.add_argument("--preset", choices=("smoke", "quick", "standard", "reference", "full"))
    estimate.add_argument("--repetitions", type=int)
    estimate.add_argument("--judge-repetitions", type=int)

    execute = commands.add_parser("run", help="Run an immutable benchmark")
    _run_arguments(execute)

    resume = commands.add_parser("resume", help="Reject resume attempts because run directories are immutable")
    resume.add_argument("legacy_arguments", nargs=argparse.REMAINDER, help=argparse.SUPPRESS)

    redteam = commands.add_parser("redteam", help="Run a tagged fixed red-team suite without changing scoring semantics")
    _run_arguments(redteam)

    compare = commands.add_parser("compare", help="Create a paired statistical comparison of compatible runs")
    compare.add_argument("baseline")
    compare.add_argument("candidate")
    compare.add_argument("--output", required=True)
    compare.add_argument("--bootstrap-samples", type=int, default=10_000)
    compare.add_argument("--seed", type=int, default=0)
    compare.add_argument("--non-inferiority-margin", type=float)

    pairwise = commands.add_parser("pairwise", help="Run blind A/B and B/A judge comparisons for two compatible runs")
    pairwise.add_argument("baseline")
    pairwise.add_argument("candidate")
    pairwise.add_argument("suite")
    pairwise.add_argument("--output", required=True)
    pairwise.add_argument("--judge-endpoint", required=True)
    pairwise.add_argument("--judge-model", required=True)
    pairwise.add_argument("--expected-judge-model", required=True)
    pairwise.add_argument("--judge-revision", required=True)
    pairwise.add_argument("--judge-key-env", default="JUDGE_API_KEY")
    pairwise.add_argument("--timeout", type=float, default=90)
    pairwise.add_argument("--signing-key-env", default="CAVADA_EVAL_SIGNING_KEY")

    report = commands.add_parser("report", help="Verify a run and print its generated report paths")
    report.add_argument("run")

    verify = commands.add_parser("verify", help="Verify artifact integrity and supported semantic projections")
    verify.add_argument("run")
    verify.add_argument("--signing-key-env", default="CAVADA_EVAL_SIGNING_KEY")
    verify.add_argument("--source-run", action="append", default=[], help="Exact source run for comparison semantic verification; repeat in comparison order")

    promote = commands.add_parser("promote", help="Promote a suite by one validated lifecycle state")
    promote.add_argument("suite")
    promote.add_argument("--to", required=True)
    promote.add_argument("--actor", required=True)
    promote.add_argument("--evidence", required=True)

    export = commands.add_parser("export", help="Export a verified public or restricted run bundle")
    export.add_argument("run")
    export.add_argument("output")
    export.add_argument("--public", action="store_true")
    export.add_argument("--engagement", default="")
    export.add_argument("--release-approval", default="")

    controls = commands.add_parser("controls", help="Generate a control-evidence report without a combined compliance score")
    controls.add_argument("run")
    controls.add_argument("--catalog", default="standards/control_catalog.toml")
    controls.add_argument("--records")
    controls.add_argument("--output", required=True)

    external = commands.add_parser("import-external", help="Validate and bundle results from a pinned external benchmark adapter")
    external.add_argument("source")
    external.add_argument("output")

    retention = commands.add_parser("retention-record", help="Create a hashed lifecycle evidence record without mutating a finalized run")
    retention.add_argument("run")
    retention.add_argument("output")
    retention.add_argument("--action", required=True, choices=sorted(RETENTION_ACTIONS))
    retention.add_argument("--actor", required=True)
    retention.add_argument("--evidence", required=True)

    perf = commands.add_parser("perf", help="Run generation-only LLM serving performance benchmarks")
    perf_commands = perf.add_subparsers(dest="perf_command", required=True)
    perf_validate = perf_commands.add_parser("validate", help="Validate a performance plan without network access")
    perf_validate.add_argument("plan", nargs="?")
    perf_validate.add_argument("--preset", choices=("smoke", "quick", "standard", "reference", "full"))
    perf_validate.add_argument("--runtime")
    perf_validate.add_argument("--system-evidence")
    perf_validate.add_argument("--execution-record")
    perf_validate.add_argument("--engagement")
    perf_validate.add_argument("--official", action="store_true")
    perf_run = perf_commands.add_parser("run", help="Run a validated performance campaign against an external endpoint")
    perf_run.add_argument("plan", nargs="?")
    perf_run.add_argument("runtime")
    perf_run.add_argument("--preset", choices=("smoke", "quick", "standard", "reference", "full"))
    perf_run.add_argument("--output-root")
    perf_run.add_argument("--signing-key-env", default="CAVADA_EVAL_SIGNING_KEY")
    perf_run.add_argument("--signing-key-id", default="")
    perf_run.add_argument("--system-evidence")
    perf_run.add_argument("--execution-record")
    perf_run.add_argument("--engagement")
    perf_run.add_argument("--official", action="store_true")
    perf_compare = perf_commands.add_parser("compare", help="Compare exact compatible performance runs")
    perf_compare.add_argument("runs", nargs="+")
    perf_compare.add_argument("--output", required=True)
    perf_compare.add_argument("--signing-key-env", default="CAVADA_EVAL_SIGNING_KEY")
    perf_export = perf_commands.add_parser("export", help="Create a sanitized, independently verifiable public performance bundle")
    perf_export.add_argument("run")
    perf_export.add_argument("output")
    perf_export.add_argument("--release-approval")
    return root


def _repository_root(start: Path | None = None) -> Path:
    origin = start.resolve() if start else Path.cwd().resolve()
    for candidate in [origin, *origin.parents, Path.cwd().resolve(), *Path.cwd().resolve().parents]:
        config = candidate / "pyproject.toml"
        if config.is_file() and 'name = "cavadalabs-evals"' in config.read_text(encoding="utf-8"):
            return candidate
    packaged = Path(__file__).resolve().parent / "_resources"
    return packaged if packaged.is_dir() else Path(__file__).resolve().parents[2]


def _doctor(repo: Path) -> dict[str, object]:
    packaged = repo == Path(__file__).resolve().parent / "_resources"
    schema_errors: list[str] = []
    schema_paths = sorted((repo / "schemas").glob("*.json"))
    for path in schema_paths:
        try:
            json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            schema_errors.append(f"{path.name}: {exc}")
    telemetry = {
        "DEEPEVAL_TELEMETRY_OPT_OUT": os.getenv("DEEPEVAL_TELEMETRY_OPT_OUT"),
        "DEEPEVAL_DISABLE_DOTENV": os.getenv("DEEPEVAL_DISABLE_DOTENV"),
        "DEEPEVAL_DISABLE_LEGACY_KEYFILE": os.getenv("DEEPEVAL_DISABLE_LEGACY_KEYFILE"),
        "DEEPEVAL_UPDATE_WARNING_OPT_IN": os.getenv("DEEPEVAL_UPDATE_WARNING_OPT_IN"),
        "ERROR_REPORTING": os.getenv("ERROR_REPORTING"),
    }
    expected = {
        "DEEPEVAL_TELEMETRY_OPT_OUT": "true",
        "DEEPEVAL_DISABLE_DOTENV": "1",
        "DEEPEVAL_DISABLE_LEGACY_KEYFILE": "1",
        "DEEPEVAL_UPDATE_WARNING_OPT_IN": "false",
        "ERROR_REPORTING": "false",
    }
    unsafe = [name for name, value in telemetry.items() if value is not None and value.casefold() != expected[name]]
    behavior_protocol = (repo / "PROTOCOL.md").is_file()
    performance_protocol = (repo / PERFORMANCE_PROTOCOL_FILENAME).is_file()
    program_error = ""
    try:
        with (repo / "program" / "registry.toml").open("rb") as handle:
            registry = tomllib.load(handle)
        suites = registry.get("suites")
        if not isinstance(suites, list) or not all(isinstance(item, dict) for item in suites):
            raise ProtocolError("program registry requires [[suites]] entries")
        by_status: dict[str, int] = {}
        for suite in suites:
            status = str(suite.get("status", "missing"))
            by_status[status] = by_status.get(status, 0) + 1
        official_capable = sum(suite.get("official_capable") is True for suite in suites)
        program_summary: object = {
            "suites": len(suites),
            "by_status": by_status,
            "official_capable": official_capable,
            "deep_validation": "run `cavada-eval program`",
        }
    except (OSError, tomllib.TOMLDecodeError, ProtocolError) as exc:
        program_error = str(exc)
        program_summary = {"error": program_error}
        official_capable = 0
    development_ready = (
        bool(schema_paths)
        and not schema_errors
        and not unsafe
        and not program_error
        and behavior_protocol
        and performance_protocol
        and (packaged or ((repo / ".git").exists() and (repo / "uv.lock").is_file()))
    )
    return {
        "repository": str(repo),
        "installation": "wheel" if packaged else "source-checkout",
        "python": sys.version.split()[0],
        "schemas": {"count": len(schema_paths), "errors": schema_errors},
        "git": (repo / ".git").exists(),
        "uv_lock": (repo / "uv.lock").is_file(),
        "protocol": behavior_protocol,
        "performance_protocol": performance_protocol,
        "program": program_summary,
        "telemetry_environment": telemetry,
        "unsafe_explicit_telemetry_settings": unsafe,
        "development_ready": development_ready,
        "official_ready": development_ready and official_capable > 0,
        "ready": development_ready,
    }


def _execute(args: argparse.Namespace) -> int:
    preset_name = canonical_preset(args.preset)
    preset = benchmark_preset(preset_name) if preset_name else None
    repetitions = int(args.repetitions if args.repetitions is not None else preset["repetitions"] if preset else 1)
    judge_repetitions = int(args.judge_repetitions if args.judge_repetitions is not None else preset["judge_repetitions"] if preset else 1)
    max_cases = int(args.max_cases if args.max_cases is not None else preset["max_cases"] if preset else 0)
    mode = str(args.mode if args.mode is not None else preset["mode"] if preset else "candidate")
    resolved_official = bool(args.official or mode == "official")
    suite = load_suite(args.suite, official=resolved_official)
    repo_root = _repository_root(suite.root)
    packaged = repo_root == Path(__file__).resolve().parent / "_resources"
    run_dir = run(
        suite,
        repo_root=repo_root,
        endpoint=args.endpoint,
        model_label=args.model_label,
        expected_model=args.expected_model,
        model_revision=args.model_revision,
        request_model=args.request_model,
        judge_endpoint=args.judge_endpoint,
        judge_model=args.judge_model,
        expected_judge_model=args.expected_judge_model,
        judge_revision=args.judge_revision,
        target_key_env=args.target_key_env,
        judge_key_env=args.judge_key_env,
        repetitions=repetitions,
        judge_repetitions=judge_repetitions,
        max_cases=max_cases,
        timeout=args.timeout,
        official=resolved_official,
        allow_external_judge=args.allow_external_judge,
        signing_key_env=args.signing_key_env,
        signing_key_id=args.signing_key_id,
        mode="redteam" if args.command == "redteam" else mode,
        preset=preset_name,
        max_target_calls=args.max_target_calls,
        max_judge_calls=args.max_judge_calls,
        max_total_tokens=args.max_total_tokens,
        max_elapsed_seconds=args.max_elapsed_seconds,
        max_estimated_cost=args.max_estimated_cost,
        non_inferiority_margin=args.non_inferiority_margin,
        external_authorization=args.external_authorization,
        storage_attestation=args.storage_attestation,
        concurrency=args.concurrency,
        requests_per_second=args.requests_per_second,
        progress=args.progress,
        judge_qualification=args.judge_qualification,
        judge_approval=args.judge_approval,
        engagement=args.engagement,
        output_root=Path(args.output_root) if args.output_root else Path.cwd() if packaged else None,
    )
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    print(run_dir)
    if manifest["status"] == "passed":
        return EXIT_PASS
    if str(manifest.get("abort_reason", "")).startswith("budget exhausted"):
        return EXIT_BUDGET
    metrics = manifest.get("metrics") or {}
    if not metrics.get("officially_valid", True):
        return EXIT_INTEGRITY
    if metrics.get("error") and not (metrics.get("pass") or metrics.get("fail")):
        return EXIT_TRANSPORT
    return EXIT_GATE_FAILURE


def _resume(_args: argparse.Namespace) -> int:
    raise ProtocolError("runs are immutable and cannot be resumed; start a new run")


def _public_behavior_summary(raw: bytes, gates: list[dict[str, object]]) -> dict[str, object]:
    try:
        source = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ProtocolError("source public summary is invalid JSON") from exc
    if not isinstance(source, dict) or not isinstance(source.get("metrics"), dict):
        raise ProtocolError("source public summary is malformed")
    metrics = source["metrics"]
    fields = (*_PUBLIC_BEHAVIOR_METRICS, *(("case_level", "case_categories") if metrics.get("analysis_unit") == "scenario" else ()))
    projected = {
        field: ({key: metrics.get(key) for key in fields} if field == "metrics" else source.get(field))
        for field in ("protocol_version", "report_version", "run_id", "status", "suite", "target", "metrics", "categories", "limitations")
    }
    projected["gates"] = gates
    return projected


def _export(run_dir: Path, output: Path, public: bool, *, engagement: str = "", release_approval: str = "") -> None:
    if output.resolve().is_relative_to(run_dir.resolve()):
        raise ProtocolError("export output must be outside the immutable run directory")
    require_mutable_output_root(output.parent)
    release_record = None
    source_bundle: dict[str, object] | None = None
    source_content: dict[str, bytes] = {}
    manifest: dict[str, object] | None = None
    public_gates: list[dict[str, object]] = []
    source_snapshot: tempfile.TemporaryDirectory[str] | None = None
    source_root = run_dir
    if public:
        if not engagement or not release_approval:
            raise ProtocolError("public export requires --engagement and --release-approval")
        release_record = verified_public_release(run_dir, Path(engagement), Path(release_approval))
        bundle_raw = (run_dir / "bundle.json").read_bytes()
        if sha256_bytes(bundle_raw) != release_record["bundle_sha256"]:
            raise ProtocolError("source bundle changed after public release verification")
        source_bundle_value = json.loads(bundle_raw)
        if not isinstance(source_bundle_value, dict) or not isinstance(source_bundle_value.get("files"), dict):
            raise ProtocolError("source run bundle is malformed")
        source_bundle = source_bundle_value["files"]
        manifest_raw = (run_dir / "manifest.json").read_bytes()
        if (
            sha256_bytes(manifest_raw) != release_record["manifest_sha256"]
            or source_bundle.get("manifest.json") != release_record["manifest_sha256"]
        ):
            raise ProtocolError("source manifest changed after public release verification")
        manifest_value = json.loads(manifest_raw)
        if not isinstance(manifest_value, dict):
            raise ProtocolError("source run manifest is malformed")
        manifest = manifest_value
        suite_snapshot_raw = (run_dir / "suite_snapshot.toml").read_bytes()
        suite_manifest_value = manifest.get("suite")
        suite_manifest = suite_manifest_value if isinstance(suite_manifest_value, dict) else {}
        if (
            source_bundle.get("suite_snapshot.toml") != sha256_bytes(suite_snapshot_raw)
            or suite_manifest.get("suite_config_sha256") != sha256_bytes(suite_snapshot_raw)
        ):
            raise ProtocolError("source suite snapshot changed after public release verification")
        try:
            suite_config = tomllib.loads(suite_snapshot_raw.decode("utf-8"))
        except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
            raise ProtocolError("source suite snapshot is invalid") from exc
        statistics_value = suite_config.get("statistics")
        statistics = statistics_value if isinstance(statistics_value, dict) else {}
        confidence = float(statistics.get("confidence", 0.95))
        public_gates = [
            {
                "category": gate.get("category"),
                "metric": gate.get("metric", "pass_rate_ci.lower"),
                "min": gate.get("min"),
                "confidence": confidence,
            }
            for gate in suite_config.get("gates", [])
            if isinstance(gate, dict)
        ]
    else:
        source_snapshot = tempfile.TemporaryDirectory()
        source_root = Path(source_snapshot.name) / "run"
        shutil.copytree(run_dir, source_root, symlinks=True)
        if not verify_bundle(source_root)["valid"]:
            raise ProtocolError("cannot export an invalid bundle")
    if output.exists():
        raise ProtocolError(f"refusing to overwrite export: {output}")
    public_names = {
        "report_public.html",
        "report_public.pdf",
        "summary.json",
        "category_results.csv",
        "figures/overall_scores.svg",
        "figures/category_scores.svg",
        "figures/latency.svg",
        "figures/status_distribution.svg",
        "figures/stability.svg",
        "figures/failure_severity.svg",
        "figures/slice_disparity.svg",
        "figures/judge_calibration.svg",
        "figures/latency_cdf.svg",
        "figures/distribution_shift.svg",
    }
    selected = [
        path
        for path in sorted(source_root.rglob("*"))
        if path.is_file() and not path.is_symlink() and (not public or path.relative_to(source_root).as_posix() in public_names)
    ]
    if release_record is not None:
        assert source_bundle is not None
        for path in selected:
            relative = path.relative_to(source_root).as_posix()
            raw = path.read_bytes()
            expected = source_bundle.get(relative)
            if not isinstance(expected, str) or sha256_bytes(raw) != expected:
                raise ProtocolError(f"public export artifact differs from the approved source bundle: {relative}")
            source_content[relative] = raw
    if public:
        assert manifest is not None
        restricted = {str(run_dir.resolve()), str(Path.home())}
        for section_value in (manifest.get("target"), manifest.get("judge")):
            section = section_value if isinstance(section_value, dict) else {}
            for field in ("endpoint", "api_key_env"):
                if section.get(field):
                    restricted.add(str(section[field]))
            hostname = urlsplit(str(section.get("endpoint", ""))).hostname
            if hostname:
                restricted.add(hostname)
        restricted = {value for value in restricted if len(value) >= 6}
        for path in selected:
            relative = path.relative_to(source_root).as_posix()
            text = source_content[relative].decode("utf-8", errors="ignore")
            if any(value in text for value in restricted) or "/Users/" in text or "/home/" in text or contains_secret_like(text):
                raise ProtocolError(f"public export contains restricted evidence: {relative}")
    temporary_export = tempfile.TemporaryDirectory() if release_record is not None else None
    try:
        archive_root = source_root
        if temporary_export is not None:
            assert release_record is not None
            assert source_bundle is not None
            archive_root = Path(temporary_export.name)
            for path in selected:
                relative = path.relative_to(source_root).as_posix()
                destination = archive_root / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                if relative == "summary.json":
                    destination.write_text(
                        json.dumps(_public_behavior_summary(source_content[relative], public_gates), indent=2, sort_keys=True) + "\n",
                        encoding="utf-8",
                    )
                else:
                    destination.write_bytes(source_content[relative])
            release_record["public_files"] = {
                path.relative_to(archive_root).as_posix(): sha256_file(path)
                for path in sorted(archive_root.rglob("*"))
                if path.is_file() and not path.is_symlink()
            }
            (archive_root / "public_release.json").write_text(
                json.dumps(release_record, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            write_bundle(archive_root)
            verify_public_bundle(archive_root)
            selected = [path for path in sorted(archive_root.rglob("*")) if path.is_file() and not path.is_symlink()]
        with output.open("xb") as compressed_file, gzip.GzipFile(filename="", mode="wb", fileobj=compressed_file, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w") as archive:
                for path in selected:
                    info = archive.gettarinfo(str(path), arcname=path.relative_to(archive_root).as_posix())
                    info.uid = info.gid = info.mtime = 0
                    info.uname = info.gname = ""
                    info.mode = 0o644
                    with path.open("rb") as source:
                        archive.addfile(info, source)
    except BaseException:
        output.unlink(missing_ok=True)
        raise
    finally:
        if temporary_export is not None:
            temporary_export.cleanup()
        if source_snapshot is not None:
            source_snapshot.cleanup()


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        repo = _repository_root()
        if args.command == "init":
            if not args.name or any(character not in "abcdefghijklmnopqrstuvwxyz0123456789-_." for character in args.name):
                raise ProtocolError("suite name must use lowercase letters, digits, dash, underscore, or dot")
            destination = Path(args.suites_root).resolve() / args.name
            if destination.exists():
                raise ProtocolError(f"suite already exists: {destination}")
            shutil.copytree(repo / "suites" / "template", destination)
            config = destination / "suite.toml"
            config.write_text(config.read_text(encoding="utf-8").replace('name = "replace-me-v1"', f'name = "{args.name}"'), encoding="utf-8")
            print(destination)
            return EXIT_PASS
        if args.command == "doctor":
            result = _doctor(repo)
            print(json.dumps(result, indent=2, sort_keys=True))
            return EXIT_PASS if result["ready"] else EXIT_CONFIGURATION
        if args.command == "list":
            suites_root = Path(args.suites_root).resolve() if args.suites_root else repo / "suites"
            if not suites_root.is_dir():
                raise ProtocolError(f"suite directory does not exist: {suites_root}")
            rows = []
            for path in sorted(suites_root.iterdir()):
                if path.is_dir() and (path / "suite.toml").is_file():
                    try:
                        with (path / "suite.toml").open("rb") as handle:
                            metadata = tomllib.load(handle)
                        required = ("name", "version", "status")
                        if not all(isinstance(metadata.get(field), str) and metadata[field].strip() for field in required):
                            raise ProtocolError(f"suite.toml requires non-empty {required}")
                        rows.append(
                            {
                                "name": metadata["name"],
                                "version": metadata["version"],
                                "status": metadata["status"],
                                "path": str(path),
                                "validation": "metadata-only; run `cavada-eval validate`",
                            }
                        )
                    except (OSError, tomllib.TOMLDecodeError, ProtocolError) as exc:
                        rows.append({"path": str(path), "status": "invalid", "error": str(exc)})
            print(json.dumps(rows, indent=2, ensure_ascii=False))
            return EXIT_PASS
        if args.command == "profiles":
            print(json.dumps(profile_summary(), indent=2))
            return EXIT_PASS
        if args.command == "presets":
            print(json.dumps(preset_summary(), indent=2))
            return EXIT_PASS
        if args.command == "program":
            registry_path = Path(args.registry)
            if not registry_path.is_absolute():
                registry_path = repo / registry_path
            program_registry = load_program_registry(registry_path, repo_root=repo)
            print(json.dumps(program_registry, indent=2, ensure_ascii=False))
            return EXIT_PASS
        if args.command == "perf":
            if args.perf_command == "export":
                result = export_public_performance(
                    Path(args.run),
                    Path(args.output),
                    approval_path=Path(args.release_approval) if args.release_approval else None,
                )
                print(json.dumps({"output": str(Path(args.output)), "assurance": result["assurance"]}, indent=2))
                return EXIT_PASS
            preset_name = canonical_preset(args.preset) if args.perf_command in {"validate", "run"} else ""
            if preset_name:
                preset_plan = (repo / str(benchmark_preset(preset_name)["performance_plan"])).resolve()
                if args.plan and Path(args.plan).resolve() != preset_plan:
                    raise ProtocolError(f"--preset {preset_name} requires plan {preset_plan}")
                plan_path = preset_plan
            elif args.perf_command in {"validate", "run"}:
                if not args.plan:
                    raise ProtocolError("performance plan is required unless --preset is used")
                plan_path = Path(args.plan)
            if args.perf_command == "validate":
                plan = load_performance_plan(plan_path)
                if args.runtime:
                    runtime = load_performance_runtime(args.runtime)
                    result = performance_plan_summary(plan, runtime)
                    evidence, evidence_raw, _ = performance_run_preflight(
                        plan,
                        runtime,
                        repo_root=repo,
                        system_evidence_path=Path(args.system_evidence) if args.system_evidence else None,
                        official=args.official,
                    )
                    result["official_requested"] = args.official
                    result["system_evidence"] = (
                        {"configuration_id": evidence["configuration_id"], "sha256": sha256_bytes(evidence_raw)}
                        if evidence is not None and evidence_raw is not None
                        else None
                    )
                    if args.official:
                        if not args.execution_record:
                            raise ProtocolError("official performance requires --execution-record")
                        if not args.engagement:
                            raise ProtocolError("official performance requires --engagement")
                    execution_record = (
                        load_performance_execution_record(
                            Path(args.execution_record),
                            protocol_sha256=sha256_file(repo / PERFORMANCE_PROTOCOL_FILENAME),
                            plan_sha256=plan.sha256,
                            workload_sha256=plan.workload_sha256,
                            runtime_sha256=runtime.sha256,
                            system_evidence_sha256=sha256_bytes(evidence_raw) if evidence_raw is not None else None,
                        )[0]
                        if args.execution_record
                        else None
                    )
                    result["execution_record"] = execution_record
                    if args.engagement and (execution_record is None or evidence is None or evidence_raw is None):
                        raise ProtocolError("performance --engagement requires --execution-record and --system-evidence")
                    result["engagement"] = (
                        load_performance_engagement(
                            Path(args.engagement),
                            protocol_sha256=sha256_file(repo / PERFORMANCE_PROTOCOL_FILENAME),
                            plan_sha256=plan.sha256,
                            workload_sha256=plan.workload_sha256,
                            runtime_sha256=runtime.sha256,
                            system_evidence_sha256=sha256_bytes(evidence_raw),
                            configuration_id=str(evidence["configuration_id"]),
                            execution_record=execution_record,
                        )[0]
                        if args.engagement and execution_record is not None and evidence is not None and evidence_raw is not None
                        else None
                    )
                else:
                    if args.system_evidence or args.execution_record or args.engagement or args.official:
                        raise ProtocolError("--system-evidence, --execution-record, --engagement, and --official require --runtime")
                    result = performance_plan_summary(plan)
                print(json.dumps(result, indent=2, ensure_ascii=False))
                return EXIT_PASS
            if args.perf_command == "run":
                output = run_performance_campaign(
                    load_performance_plan(plan_path),
                    load_performance_runtime(args.runtime),
                    repo_root=repo,
                    output_root=Path(args.output_root) if args.output_root else None,
                    signing_key_env=args.signing_key_env,
                    signing_key_id=args.signing_key_id,
                    system_evidence_path=Path(args.system_evidence) if args.system_evidence else None,
                    execution_record_path=Path(args.execution_record) if args.execution_record else None,
                    engagement_path=Path(args.engagement) if args.engagement else None,
                    official=args.official,
                )
                manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
                counts = manifest["cells"]
                print(
                    json.dumps(
                        {
                            "run_dir": str(output),
                            "report_html": str(output / "report.html"),
                            "report_pdf": str(output / "report.pdf"),
                            "cells_csv": str(output / "cells.csv"),
                            "verify_command": shlex.join(["uv", "run", "cavada-eval", "verify", str(output)]),
                            "status": manifest["status"],
                            "invalid_loadgen": counts.get("invalid_loadgen", 0),
                            "slo_failed": counts["slo_failed"],
                        },
                        indent=2,
                    )
                )
                return EXIT_PASS if manifest["status"] == "completed" and manifest["cells"]["slo_failed"] == 0 else EXIT_GATE_FAILURE
            result = compare_performance_runs(
                [Path(path) for path in args.runs],
                Path(args.output),
                signing_key_env=args.signing_key_env,
            )
            comparison_output = Path(args.output)
            verify_command = ["uv", "run", "cavada-eval", "verify", str(comparison_output)]
            for source_run in args.runs:
                verify_command.extend(("--source-run", source_run))
            print(
                json.dumps(
                    {
                        "baseline": result["baseline"],
                        "shared_cells": result["shared_cells"],
                        "report_html": str(comparison_output / "report.html"),
                        "report_pdf": str(comparison_output / "report.pdf"),
                        "comparison_csv": str(comparison_output / "comparison.csv"),
                        "verify_command": shlex.join(verify_command),
                    },
                    indent=2,
                )
            )
            return EXIT_PASS
        if args.command == "validate":
            print(json.dumps(audit_suite(load_suite(args.suite, official=args.official)), ensure_ascii=False, indent=2))
            return EXIT_PASS
        if args.command == "annotations":
            result = export_annotation_package(
                load_suite(args.suite), Path(args.run_dir), Path(args.output), Path(args.linkage_output)
            )
            print(json.dumps(result, indent=2, ensure_ascii=False))
            return EXIT_PASS
        if args.command == "annotations-ingest":
            result = ingest_annotations(
                Path(args.package),
                Path(args.linkage),
                Path(args.output),
                reviewer_id=args.reviewer_id,
                qualification_evidence=args.qualification_evidence,
                conflicts=args.conflicts,
            )
            print(json.dumps(result, indent=2, ensure_ascii=False))
            return EXIT_PASS
        if args.command == "annotations-agreement":
            result = annotation_agreement(Path(args.left), Path(args.right), Path(args.output))
            print(json.dumps(result, indent=2, ensure_ascii=False))
            return EXIT_PASS
        if args.command == "annotations-adjudicate":
            result = ingest_adjudications(
                Path(args.agreement),
                Path(args.left),
                Path(args.right),
                Path(args.output),
                adjudicator_id=args.adjudicator_id,
                qualification_evidence=args.qualification_evidence,
                conflicts=args.conflicts,
            )
            print(json.dumps(result, indent=2, ensure_ascii=False))
            return EXIT_PASS
        if args.command == "judge-qualify":
            result = qualify_judge_run(
                Path(args.run), Path(args.blueprint), Path(args.corpus_manifest), Path(args.output)
            )
            print(json.dumps({"passed": result["passed"], "output": str(Path(args.output))}, indent=2))
            return EXIT_PASS if result["passed"] else EXIT_GATE_FAILURE
        if args.command == "pilot-audit":
            result = audit_pilot_campaign(Path(args.campaign), Path(args.output))
            print(json.dumps({"passed": result["passed"], "output": str(Path(args.output))}, indent=2))
            return EXIT_PASS if result["passed"] else EXIT_GATE_FAILURE
        if args.command == "audit":
            print(json.dumps(audit_suite(load_suite(args.suite)), ensure_ascii=False, indent=2))
            return EXIT_PASS
        if args.command == "estimate":
            suite = load_suite(args.suite)
            preset_name = canonical_preset(args.preset)
            preset = benchmark_preset(preset_name) if preset_name else None
            repetitions = int(args.repetitions if args.repetitions is not None else preset["repetitions"] if preset else 1)
            judge_repetitions = int(args.judge_repetitions if args.judge_repetitions is not None else preset["judge_repetitions"] if preset else 1)
            selected = stratified_cases(suite.cases, int(preset["max_cases"])) if preset else suite.cases
            if repetitions < 1 or judge_repetitions < 1:
                raise ProtocolError("repetitions must be positive")
            executable = [case for case in selected if (case.get("review") or {}).get("status") != "rejected"]
            target_calls = len(executable) * repetitions
            additional_judges = ((getattr(suite, "config", {}) or {}).get("judge") or {}).get("additional_models") or []
            judge_count = 1 + len(additional_judges)
            print(
                json.dumps(
                    {
                        "preset": preset_name or None,
                        "preset_version": preset["version"] if preset else None,
                        "selected_cases": len(selected),
                        "executable_cases": len(executable),
                        "skipped_rejected_cases": len(selected) - len(executable),
                        "target_calls": target_calls,
                        "maximum_judge_calls": target_calls * judge_repetitions * judge_count,
                        "network_used": False,
                    },
                    indent=2,
                )
            )
            return EXIT_PASS
        if args.command in {"run", "redteam"}:
            return _execute(args)
        if args.command == "resume":
            return _resume(args)
        if args.command == "compare":
            result = compare_runs(
                Path(args.baseline),
                Path(args.candidate),
                Path(args.output),
                samples=args.bootstrap_samples,
                seed=args.seed,
                non_inferiority_margin=args.non_inferiority_margin,
            )
            overall = result.get("overall")
            categories = result.get("categories")
            if not isinstance(categories, list) or not all(isinstance(row, dict) for row in categories):
                raise ProtocolError("comparison produced invalid category metrics")
            print(json.dumps(overall if isinstance(overall, dict) else categories, indent=2))
            non_inferiority = [
                value
                for value in [
                    overall.get("non_inferiority") if isinstance(overall, dict) else None,
                    *(row.get("non_inferiority") for row in categories if isinstance(row, dict)),
                ]
                if isinstance(value, dict)
            ]
            return EXIT_PASS if all(bool(value.get("passed")) for value in non_inferiority) else EXIT_GATE_FAILURE
        if args.command == "pairwise":
            pairwise_result = pairwise_runs(
                Path(args.baseline),
                Path(args.candidate),
                load_suite(args.suite),
                Path(args.output),
                judge_endpoint=args.judge_endpoint,
                judge_model=args.judge_model,
                expected_judge_model=args.expected_judge_model,
                judge_revision=args.judge_revision,
                judge_key_env=args.judge_key_env,
                timeout=args.timeout,
                signing_key_env=args.signing_key_env,
            )
            print(json.dumps(pairwise_result["metrics"], indent=2))
            if pairwise_result["metrics"]["error"]:
                return EXIT_TRANSPORT
            return EXIT_PASS if pairwise_result["metrics"]["invalid"] == 0 else EXIT_GATE_FAILURE
        if args.command == "report":
            run_dir = Path(args.run)
            verification = verify_bundle(run_dir)
            if not verification["valid"]:
                raise ProtocolError("run bundle verification failed")
            paths = [str(run_dir / name) for name in ("report.html", "report.pdf", "report_public.html", "report_public.pdf") if (run_dir / name).is_file()]
            print(json.dumps({"verification": verification, "reports": paths}, indent=2))
            return EXIT_PASS
        if args.command == "verify":
            run = Path(args.run)
            if (run / "comparison.json").is_file():
                try:
                    result = verify_performance_comparison(
                        run,
                        source_run_dirs=[Path(path) for path in args.source_run] or None,
                        signing_key_env=args.signing_key_env,
                    )
                except ProtocolError as exc:
                    print(
                        json.dumps(
                            {"valid": False, "semantic_valid": False, "type": "performance-comparison", "error": str(exc)},
                            indent=2,
                        )
                    )
                    return EXIT_INTEGRITY
            elif (run / "public_release.json").is_file() or (run / "public_manifest.json").is_file():
                if args.source_run:
                    raise ProtocolError("--source-run is only valid for performance comparisons")
                try:
                    result = verify_public_bundle(run, signing_key_env=args.signing_key_env)
                except ProtocolError as exc:
                    print(json.dumps({"valid": False, "semantic_valid": False, "error": str(exc)}, indent=2))
                    return EXIT_INTEGRITY
            elif all((run / name).is_file() for name in ("manifest.json", "runtime_snapshot.toml", "cells.jsonl")):
                if args.source_run:
                    raise ProtocolError("--source-run is only valid for performance comparisons")
                try:
                    result = verify_performance_source_bundle(run, signing_key_env=args.signing_key_env)
                except ProtocolError as exc:
                    print(json.dumps({"valid": False, "semantic_valid": False, "type": "performance", "error": str(exc)}, indent=2))
                    return EXIT_INTEGRITY
            else:
                if args.source_run:
                    raise ProtocolError("--source-run is only valid for performance comparisons")
                result = verify_bundle(run, signing_key_env=args.signing_key_env)
            if result["valid"] and (run / "report.html").is_file():
                result = {**result, "report_html": str(run / "report.html")}
            print(json.dumps(result, indent=2))
            return EXIT_PASS if result["valid"] else EXIT_INTEGRITY
        if args.command == "promote":
            print(json.dumps(promote_suite(load_suite(args.suite), args.to, actor=args.actor, evidence=args.evidence), indent=2))
            return EXIT_PASS
        if args.command == "export":
            _export(
                Path(args.run),
                Path(args.output),
                args.public,
                engagement=args.engagement,
                release_approval=args.release_approval,
            )
            print(Path(args.output))
            return EXIT_PASS
        if args.command == "controls":
            catalog = Path(args.catalog)
            if not catalog.is_absolute() and not catalog.is_file():
                catalog = repo / catalog
            report = generate_control_report(Path(args.run), catalog, Path(args.output), records_path=Path(args.records) if args.records else None)
            print(json.dumps(report["status_counts"], indent=2))
            return EXIT_PASS
        if args.command == "import-external":
            imported = import_external_results(Path(args.source), Path(args.output))
            print(json.dumps(imported, indent=2))
            return EXIT_PASS
        if args.command == "retention-record":
            record = retention_record(Path(args.run), Path(args.output), action=args.action, actor=args.actor, evidence=args.evidence)
            print(json.dumps(record, indent=2))
            return EXIT_PASS
        raise ProtocolError(f"unsupported command: {args.command}")
    except KeyboardInterrupt:
        print("CANCELLED", file=sys.stderr)
        return EXIT_CANCELLED
    except ProtocolError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        folded = str(exc).casefold()
        if "budget exhausted" in folded:
            return EXIT_BUDGET
        if any(marker in folded for marker in ("cannot reach", "http 4", "http 5", "timeout", "stream from")):
            return EXIT_TRANSPORT
        return EXIT_CONFIGURATION


if __name__ == "__main__":
    raise SystemExit(main())
