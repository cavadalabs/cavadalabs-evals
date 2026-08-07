from __future__ import annotations

import argparse
import io
import json
import os
import shutil
import sys
import tarfile
import webbrowser
from pathlib import Path

from .annotations import annotation_agreement, export_annotation_package, ingest_adjudications, ingest_annotations
from .artifacts import verify_bundle
from .calibration import qualify_judge_run
from .comparison import compare_runs
from .compliance import generate_control_report
from .demo import run_demo
from .external import import_external_results
from .pairwise import pairwise_runs
from .performance import (
    compare_performance_runs,
    load_performance_plan,
    load_performance_runtime,
    performance_plan_summary,
    run_performance_campaign,
)
from .pilot import audit_pilot_campaign
from .profiles import benchmark_preset, canonical_preset, preset_summary, profile_summary, stratified_cases
from .program import load_program_registry
from .protocol import ProtocolError, audit_suite, load_suite, promote_suite, sha256_file
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
    command.add_argument("--external-authorization", default="")
    command.add_argument("--storage-attestation", default="")
    command.add_argument("--judge-qualification", default="")
    command.add_argument("--judge-approval", default="")
    command.add_argument("--engagement", default="")
    command.add_argument("--concurrency", type=int, default=1)
    command.add_argument("--requests-per-second", type=float, default=0)
    command.add_argument("--progress", action="store_true")


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="cavada-eval", description="CavadaLabs reproducible AI evaluation protocol")
    root.add_argument("--version", action="version", version="cavadalabs-evals 0.3.1")
    commands = root.add_subparsers(dest="command", required=True)

    init = commands.add_parser("init", help="Create a new draft suite from the secure template")
    init.add_argument("name")
    init.add_argument("--suites-root", default="suites")

    demo = commands.add_parser("demo", help="Run the complete deterministic offline demo")
    demo.add_argument("--open", action="store_true", help="Open the generated public report in the default browser")

    commands.add_parser("doctor", help="Check the local repository and security-sensitive settings")

    listing = commands.add_parser("list", help="List local suites")
    listing.add_argument("--suites-root", default="suites")

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

    resume = commands.add_parser("resume", help="Resume an unfinalized run after a crash without duplicating observations")
    resume.add_argument("run")
    resume.add_argument("suite")
    resume.add_argument("--endpoint", required=True)
    resume.add_argument("--judge-endpoint", required=True)
    resume.add_argument("--target-key-env", default="TARGET_API_KEY")
    resume.add_argument("--judge-key-env", default="JUDGE_API_KEY")
    resume.add_argument("--external-authorization", default="")
    resume.add_argument("--storage-attestation", default="")
    resume.add_argument("--judge-qualification", default="")
    resume.add_argument("--judge-approval", default="")
    resume.add_argument("--engagement", default="")
    resume.add_argument("--signing-key-env", default="CAVADA_EVAL_SIGNING_KEY")
    resume.add_argument("--signing-key-id", default="")
    resume.add_argument("--progress", action="store_true")

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

    verify = commands.add_parser("verify", help="Verify every artifact hash and optional bundle signature")
    verify.add_argument("run")
    verify.add_argument("--signing-key-env", default="CAVADA_EVAL_SIGNING_KEY")

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
    perf_run = perf_commands.add_parser("run", help="Run a validated performance campaign against an external endpoint")
    perf_run.add_argument("plan", nargs="?")
    perf_run.add_argument("runtime")
    perf_run.add_argument("--preset", choices=("smoke", "quick", "standard", "reference", "full"))
    perf_run.add_argument("--output-root")
    perf_run.add_argument("--signing-key-env", default="CAVADA_EVAL_SIGNING_KEY")
    perf_run.add_argument("--signing-key-id", default="")
    perf_compare = perf_commands.add_parser("compare", help="Compare exact compatible performance runs")
    perf_compare.add_argument("runs", nargs="+")
    perf_compare.add_argument("--output", required=True)
    perf_compare.add_argument("--signing-key-env", default="CAVADA_EVAL_SIGNING_KEY")
    return root


def _repository_root(start: Path | None = None) -> Path:
    origin = start.resolve() if start else Path.cwd().resolve()
    for candidate in [origin, *origin.parents, Path.cwd().resolve(), *Path.cwd().resolve().parents]:
        config = candidate / "pyproject.toml"
        if config.is_file() and 'name = "cavadalabs-evals"' in config.read_text(encoding="utf-8"):
            return candidate
    return Path(__file__).resolve().parents[2]


def _doctor(repo: Path) -> dict[str, object]:
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
    program_error = ""
    try:
        program = load_program_registry(repo / "program" / "registry.toml", repo_root=repo)
        program_summary: object = program["summary"]
    except ProtocolError as exc:
        program_error = str(exc)
        program_summary = {"error": program_error}
    return {
        "repository": str(repo),
        "python": sys.version.split()[0],
        "schemas": {"count": len(schema_paths), "errors": schema_errors},
        "git": (repo / ".git").exists(),
        "uv_lock": (repo / "uv.lock").is_file(),
        "protocol": (repo / "PROTOCOL.md").is_file(),
        "program": program_summary,
        "telemetry_environment": telemetry,
        "unsafe_explicit_telemetry_settings": unsafe,
        "ready": bool(schema_paths)
        and not schema_errors
        and not unsafe
        and not program_error
        and (repo / ".git").exists()
        and (repo / "uv.lock").is_file()
        and (repo / "PROTOCOL.md").is_file(),
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
        external_authorization=args.external_authorization,
        storage_attestation=args.storage_attestation,
        concurrency=args.concurrency,
        requests_per_second=args.requests_per_second,
        progress=args.progress,
        judge_qualification=args.judge_qualification,
        judge_approval=args.judge_approval,
        engagement=args.engagement,
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


def _resume(args: argparse.Namespace) -> int:
    run_dir = Path(args.run).resolve()
    try:
        manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ProtocolError("resume requires a valid run manifest") from exc
    parameters = manifest.get("parameters") or {}
    suite = load_suite(args.suite, official=bool(manifest.get("official_requested")))
    output = run(
        suite,
        repo_root=_repository_root(suite.root),
        endpoint=args.endpoint,
        model_label=str(manifest["target"]["label"]),
        expected_model=str(manifest["target"]["expected_reported_model"]),
        model_revision=str(manifest["target"]["revision"]),
        request_model=manifest["target"].get("request_model"),
        judge_endpoint=args.judge_endpoint,
        judge_model=str(manifest["judge"]["requested_model"]),
        expected_judge_model=str(manifest["judge"]["expected_reported_model"]),
        judge_revision=str(manifest["judge"]["revision"]),
        target_key_env=args.target_key_env,
        judge_key_env=args.judge_key_env,
        repetitions=int(parameters["repetitions"]),
        judge_repetitions=int(parameters["judge_repetitions"]),
        max_cases=int(parameters.get("max_cases", 0)),
        timeout=float(parameters.get("timeout_seconds", 90)),
        official=bool(manifest.get("official_requested")),
        allow_external_judge=False,
        signing_key_env=args.signing_key_env,
        signing_key_id=args.signing_key_id,
        mode=str(parameters.get("mode", "candidate")),
        preset=str(parameters.get("preset", "")),
        max_target_calls=int(parameters.get("max_target_calls", 0)),
        max_judge_calls=int(parameters.get("max_judge_calls", 0)),
        max_total_tokens=int(parameters.get("max_total_tokens", 0)),
        max_elapsed_seconds=float(parameters.get("max_elapsed_seconds", 0)),
        max_estimated_cost=float(parameters.get("max_estimated_cost", 0)),
        external_authorization=args.external_authorization,
        storage_attestation=args.storage_attestation,
        resume_dir=run_dir,
        concurrency=int(parameters.get("concurrency", 1)),
        requests_per_second=float(parameters.get("requests_per_second", 0)),
        progress=args.progress,
        judge_qualification=args.judge_qualification,
        judge_approval=args.judge_approval,
        engagement=args.engagement,
    )
    print(output)
    final = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
    return EXIT_PASS if final["status"] == "passed" else EXIT_GATE_FAILURE


def _export(run_dir: Path, output: Path, public: bool, *, engagement: str = "", release_approval: str = "") -> None:
    release_record = None
    if public:
        if not engagement or not release_approval:
            raise ProtocolError("public export requires --engagement and --release-approval")
        release_record = verified_public_release(run_dir, Path(engagement), Path(release_approval))
    elif not verify_bundle(run_dir)["valid"]:
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
        for path in sorted(run_dir.rglob("*"))
        if path.is_file() and not path.is_symlink() and (not public or path.relative_to(run_dir).as_posix() in public_names)
    ]
    if release_record is not None:
        release_record["public_files"] = {path.relative_to(run_dir).as_posix(): sha256_file(path) for path in selected}
    with tarfile.open(output, "w:gz") as archive:
        for path in selected:
            archive.add(path, arcname=path.relative_to(run_dir).as_posix(), recursive=False)
        if release_record is not None:
            payload = (json.dumps(release_record, indent=2, sort_keys=True) + "\n").encode()
            info = tarfile.TarInfo("public_release.json")
            info.size = len(payload)
            info.mode = 0o644
            archive.addfile(info, io.BytesIO(payload))


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
        if args.command == "demo":
            result = run_demo(repo, artifact_root=Path.cwd())
            if args.open:
                webbrowser.open(Path(str(result["report"])).resolve().as_uri())
            print(json.dumps(result, indent=2, ensure_ascii=False))
            return EXIT_PASS
        if args.command == "list":
            rows = []
            for path in sorted(Path(args.suites_root).resolve().iterdir()):
                if path.is_dir() and (path / "suite.toml").is_file():
                    try:
                        suite = load_suite(path)
                        rows.append({"name": suite.name, "version": suite.version, "status": suite.status, "path": str(path)})
                    except ProtocolError as exc:
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
                else:
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
                )
                manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
                print(output)
                return EXIT_PASS if manifest["status"] == "completed" and manifest["cells"]["slo_failed"] == 0 else EXIT_GATE_FAILURE
            result = compare_performance_runs(
                [Path(path) for path in args.runs],
                Path(args.output),
                signing_key_env=args.signing_key_env,
            )
            print(json.dumps({"baseline": result["baseline"], "shared_cells": result["shared_cells"]}, indent=2))
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
            target_calls = len(selected) * repetitions
            print(
                json.dumps(
                    {
                        "preset": preset_name or None,
                        "preset_version": preset["version"] if preset else None,
                        "cases": len(selected),
                        "target_calls": target_calls,
                        "maximum_judge_calls": target_calls * judge_repetitions,
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
            if not isinstance(overall, dict):
                raise ProtocolError("comparison produced invalid overall metrics")
            print(json.dumps(overall, indent=2))
            non_inferiority = overall.get("non_inferiority")
            return EXIT_PASS if not isinstance(non_inferiority, dict) or bool(non_inferiority.get("passed")) else EXIT_GATE_FAILURE
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
            result = verify_bundle(Path(args.run), signing_key_env=args.signing_key_env)
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
            report = generate_control_report(Path(args.run), Path(args.catalog), Path(args.output), records_path=Path(args.records) if args.records else None)
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
