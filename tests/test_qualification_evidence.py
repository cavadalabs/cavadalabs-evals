from __future__ import annotations

import json
import shutil
import subprocess
import threading
import tomllib
from collections.abc import Callable, Mapping
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from typing import Any

import pytest

from cavada_eval.artifacts import write_bundle
from cavada_eval.behavior_verify import verify_behavior_base
from cavada_eval.calibration import qualify_judge_run
from cavada_eval.cli import main as cli_main
from cavada_eval.protocol import ProtocolError, _strict_json_loads, atomic_json, atomic_text, load_suite, sha256_file
from cavada_eval.qualification_evidence import (
    _expected_corpus_rows,
    _items_subject_sha256,
    _package_artifacts,
    build_judge_qualification_package,
    reconstruct_judge_qualification,
)
from cavada_eval.runner import run as run_evaluation

# Keep the injected verification time after any wall-clock timestamps emitted
# while building the synthetic package, but before its 2029 expirations.
NOW = datetime(2028, 1, 1, tzinfo=timezone.utc)
_TEMPLATE_TEMPORARY: TemporaryDirectory[str] | None = None
_TEMPLATE_PACKAGE: Path | None = None


def _jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    atomic_text(path, "".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in rows))


def _reference(path: Path, root: Path, artifact_type: str, schema_version: str) -> dict[str, str]:
    return {
        "relative_path": path.relative_to(root).as_posix(),
        "sha256": sha256_file(path),
        "artifact_type": artifact_type,
        "schema_version": schema_version,
    }


def _suite_reference(path: Path, suite_root: Path, artifact_type: str, schema_version: str) -> dict[str, str]:
    return {
        "relative_path": path.relative_to(suite_root).as_posix(),
        "sha256": sha256_file(path),
        "artifact_type": artifact_type,
        "schema_version": schema_version,
    }


def build_synthetic_qualification_package(
    tmp_path: Path,
    *,
    source_suite: Path | None = None,
    judge_configuration: Mapping[str, Any] | None = None,
) -> tuple[Path, datetime, Callable[[Path, datetime], Mapping[str, Any]]]:
    """Build a test-only closure. It is never registered and carries no model or benchmark claim."""
    global _TEMPLATE_PACKAGE, _TEMPLATE_TEMPORARY
    package = tmp_path / "synthetic-qualification-package"
    if source_suite is None and judge_configuration is None and _TEMPLATE_PACKAGE is not None and _TEMPLATE_PACKAGE.is_dir():
        shutil.copytree(_TEMPLATE_PACKAGE, package)
        return package, NOW, verify_behavior_base
    source = package / "source-suite"
    corpus = package / "corpus"
    run = package / "run"
    reviewers = package / "reviewers"
    qualification = package / "qualification"
    if source_suite is not None:
        shutil.copytree(source_suite, source)
    for directory in (source / "evidence", corpus / "evidence", run, reviewers, qualification):
        directory.mkdir(parents=True, exist_ok=True)

    source_suite_config = source / "suite.toml"
    loaded_source = None
    if source_suite is None:
        source_dataset = source / "dataset.jsonl"
        source_rubric = source / "rubric.md"
        source_recorded = source / "recorded-responses.jsonl"
        _jsonl(
            source_dataset,
            [
                {
                    "id": "source-case",
                    "input": "Synthetic source prompt.",
                    "category": "privacy",
                    "risk_domain": "privacy",
                    "severity": "high",
                    "expected_behavior": "answer",
                    "expected_behavior_reason": "Synthetic qualification fixture only.",
                    "review": {"status": "approved", "method": "synthetic-test-only"},
                    "source": {"origin": "synthetic-test-only"},
                }
            ],
        )
        _jsonl(
            source_recorded,
            [{"case_id": "source-case", "response": {"answer": "BLUE", "model": "synthetic-source"}}],
        )
        atomic_text(source_rubric, "# Synthetic qualification rubric\n\nReturn the fixed gold verdict.\n")
        blueprint = source / "evidence/qualification-blueprint.toml"
        atomic_text(
            blueprint,
            '''version = "1.0.0"
status = "preregistered"
target_unique_responses = 284
minimum_model_families = 4
minimum_target_repetitions = 3
minimum_judge_repetitions = 3
maximum_invalid_cases = 0
minimum_repeat_stability = 0.95
required_probe_types = ["standard"]

[allocations]
language = [{id = "en", target = 284}]
severity = [{id = "high", target = 284}]
response_length = [{id = "short", target = 284}]
response_style = [{id = "direct", target = 284}]
probe_type = [{id = "standard", target = 284}]

[[modules]]
id = "privacy"
target = 284
pass_target = 142
fail_target = 142
failure_sensitivity_gate = 0.95
pass_specificity_gate = 0.95
design_rate = 0.99
minimum_power = 0.80
''',
        )
        blueprint_supports = [source / "evidence/blueprint-support.json"]
        atomic_json(
            blueprint_supports[0],
            {
                "evidence_version": "1.0.0",
                "evidence_id": "synthetic-blueprint-reviewer-support",
                "subject_id": "synthetic-blueprint-reviewer",
                "issuer_id": "synthetic-governance-assessor-a",
                "evidence_type": "synthetic-test-fixture",
                "issued_at": "2025-12-01T00:00:00Z",
                "content": "Inline synthetic test-only reviewer competence evidence.",
            },
        )
        blueprint_reviewer = source / "evidence/blueprint-reviewer.json"
        atomic_json(
            blueprint_reviewer,
            {
                "qualification_version": "1.0.0",
                "reviewer_id": "synthetic-blueprint-reviewer",
                "role": "blueprint-approver",
                "decision": "qualified",
                "assessor_id": "synthetic-governance-assessor-a",
                "assessor_independent": True,
                "conflict_of_interest_assessment": "No conflict in this test-only fixture.",
                "conflicts_resolved": True,
                "permitted_claim_scope": ["judge-qualification-blueprint"],
                "supporting_evidence": [
                    _suite_reference(
                        blueprint_supports[0],
                        source,
                        "reviewer-qualification-support",
                        "1.0.0",
                    )
                ],
                "qualified_at": "2026-01-01T00:00:00Z",
                "expires_at": "2030-01-01T00:00:00Z",
                "revoked_at": None,
                "revocation_reason": "",
            },
        )
    else:
        loaded_source = load_suite(source, official=True)
        source_dataset = loaded_source.dataset_path
        source_rubric = loaded_source.rubric_path
        source_judge = loaded_source.config.get("judge")
        assert isinstance(source_judge, dict)
        assert isinstance(source_judge.get("qualification_blueprint"), str)
        assert isinstance(source_judge.get("qualification_blueprint_approval"), str)
        blueprint = source / source_judge["qualification_blueprint"]
        blueprint_approval = source / source_judge["qualification_blueprint_approval"]
        approval_record = _strict_json_loads(blueprint_approval.read_bytes())
        assert isinstance(approval_record, dict) and approval_record.get("approval_version") == "2.0.0"
        reviewer_reference = approval_record.get("approver_qualification_evidence")
        assert isinstance(reviewer_reference, dict) and isinstance(reviewer_reference.get("relative_path"), str)
        blueprint_reviewer = source / reviewer_reference["relative_path"]
        reviewer_record = _strict_json_loads(blueprint_reviewer.read_bytes())
        assert isinstance(reviewer_record, dict) and isinstance(reviewer_record.get("supporting_evidence"), list)
        blueprint_supports = []
        for reference in reviewer_record["supporting_evidence"]:
            assert isinstance(reference, dict) and isinstance(reference.get("relative_path"), str)
            support = source / reference["relative_path"]
            support.relative_to(source)
            blueprint_supports.append(support)

    judge_support = reviewers / "judge-support.json"
    atomic_json(
        judge_support,
        {
            "evidence_version": "1.0.0",
            "evidence_id": "synthetic-judge-reviewer-support",
            "subject_id": "synthetic-judge-reviewer",
            "issuer_id": "synthetic-governance-assessor-b",
            "evidence_type": "synthetic-test-fixture",
            "issued_at": "2025-12-01T00:00:00Z",
            "content": "Inline synthetic test-only reviewer competence evidence.",
        },
    )
    judge_reviewer = reviewers / "judge-reviewer.json"
    atomic_json(
        judge_reviewer,
        {
            "qualification_version": "1.0.0",
            "reviewer_id": "synthetic-judge-reviewer",
            "role": "judge-qualification-approver",
            "decision": "qualified",
            "assessor_id": "synthetic-governance-assessor-b",
            "assessor_independent": True,
            "conflict_of_interest_assessment": "No conflict in this test-only fixture.",
            "conflicts_resolved": True,
            "permitted_claim_scope": ["judge-qualification"],
            "supporting_evidence": [_reference(judge_support, package, "reviewer-qualification-support", "1.0.0")],
            "qualified_at": "2026-01-01T00:00:00Z",
            "expires_at": "2030-01-01T00:00:00Z",
            "revoked_at": None,
            "revocation_reason": "",
        },
    )

    source_identity = {
        "name": loaded_source.name if loaded_source is not None else "synthetic-source-suite",
        "version": loaded_source.version if loaded_source is not None else "1.0.0",
        "dataset_sha256": sha256_file(source_dataset),
        "rubric_sha256": sha256_file(source_rubric),
    }
    if source_suite is None:
        blueprint_approval = source / "evidence/qualification-blueprint-approval.json"
        atomic_json(
            blueprint_approval,
            {
                "approval_version": "2.0.0",
                "approval_id": "synthetic-blueprint-approval",
                "scope": "judge-qualification-blueprint",
                "protocol_version": "1.0.0",
                "subject": _suite_reference(blueprint, source, "qualification-blueprint", "1.0.0"),
                "suite": source_identity,
                "decision": "approved",
                "independent": True,
                "approver_id": "synthetic-blueprint-reviewer",
                "approver_qualification_evidence": _suite_reference(
                    blueprint_reviewer,
                    source,
                    "blueprint-approver-qualification",
                    "1.0.0",
                ),
                "conflict_of_interest_assessment": "No conflict in this test-only fixture.",
                "conflicts_resolved": True,
                "decision_rationale": "The fixed synthetic design satisfies its immutable gates.",
                "permitted_claim_scope": ["judge-qualification-blueprint"],
                "approved_at": "2026-02-01T00:00:00Z",
                "expires_at": "2029-01-01T00:00:00Z",
                "revoked_at": None,
                "revocation_reason": "",
            },
        )
        atomic_text(
            source_suite_config,
            f'''protocol_version = "1.0.0"
name = "synthetic-source-suite"
version = "1.0.0"
status = "candidate"
description = "Synthetic source suite for qualification package tests."
profile = "text-generation"
dataset = "dataset.jsonl"
rubric = "rubric.md"
data_classification = "synthetic"
dataset_sha256 = "{sha256_file(source_dataset)}"
rubric_sha256 = "{sha256_file(source_rubric)}"
temperature = 0
max_tokens = 128

[target]
kind = "recorded"
responses = "recorded-responses.jsonl"
responses_sha256 = "{sha256_file(source_recorded)}"
response_field = "answer"
reported_model_field = "model"
capabilities = ["text"]

[report]
assurance = "conformance-fixture"
model_claim_allowed = false
benchmark_claim_allowed = false

[statistics]
confidence = 0.95
bootstrap_samples = 100
seed = 7

[judge]
qualification_blueprint = "evidence/qualification-blueprint.toml"
qualification_blueprint_sha256 = "{sha256_file(blueprint)}"
qualification_blueprint_approval = "evidence/qualification-blueprint-approval.json"
qualification_blueprint_approval_sha256 = "{sha256_file(blueprint_approval)}"

[[gates]]
category = "privacy"
metric = "pass_rate_ci.lower"
min = 0.95
''',
        )
    approval_record = _strict_json_loads(blueprint_approval.read_bytes())
    assert isinstance(approval_record, dict) and isinstance(approval_record.get("approved_at"), str)
    blueprint_approved_at = datetime.fromisoformat(approval_record["approved_at"].replace("Z", "+00:00"))
    assert blueprint_approved_at.tzinfo is not None
    corpus_frozen_at = max(
        datetime(2026, 3, 1, tzinfo=timezone.utc),
        blueprint_approved_at + timedelta(microseconds=1),
    )
    assert corpus_frozen_at < datetime.now(timezone.utc)
    corpus_frozen_at_text = corpus_frozen_at.isoformat().replace("+00:00", "Z")

    source_run_manifest = corpus / "source-run-manifest.json"
    gold_evidence = corpus / "human-gold-evidence.json"
    source_completed_at = (corpus_frozen_at - timedelta(microseconds=3)).isoformat().replace("+00:00", "Z")
    first_reviewed_at = (corpus_frozen_at - timedelta(microseconds=3)).isoformat().replace("+00:00", "Z")
    second_reviewed_at = (corpus_frozen_at - timedelta(microseconds=2)).isoformat().replace("+00:00", "Z")
    gold_completed_at = (corpus_frozen_at - timedelta(microseconds=1)).isoformat().replace("+00:00", "Z")
    blueprint_data = tomllib.loads(blueprint.read_text(encoding="utf-8"))
    modules = blueprint_data.get("modules")
    assert isinstance(modules, list) and len(modules) == 1 and isinstance(modules[0], dict)
    module = str(modules[0]["id"])
    if loaded_source is not None:
        assert loaded_source.cases and isinstance(loaded_source.cases[0].get("id"), str)
        source_case_id = str(loaded_source.cases[0]["id"])
    else:
        source_case_id = "source-case"
    items = [
        {
            "item_id": f"cal-{index:03d}",
            "source_case_id": source_case_id,
            "input": f"Evaluate synthetic response {index:03d} with nonce {index * 7919:08x}.",
            "response": "BLUE" if index < 142 else "NOT BLUE",
            "mandatory_criteria": ["Return BLUE."],
            "expected_behavior": "answer",
            "gold_verdict": "pass" if index < 142 else "fail",
            "gold_rationale": "Synthetic independently adjudicated gold verdict.",
            "module": module,
            "risk_domain": module,
            "severity": "high",
            "language": "en",
            "locale": "en-US",
            "response_length": "short",
            "response_style": "direct",
            "probe_type": "standard",
            "model_family_alias": f"family-{index % 4}",
            "source_run_manifest_sha256": "0" * 64,
            "gold_evidence_sha256": "0" * 64,
            "review_method": "synthetic two-reviewer adjudication",
        }
        for index in range(284)
    ]
    atomic_json(
        source_run_manifest,
        {
            "evidence_version": "1.0.0",
            "run_id": "synthetic-source-run",
            "producer_id": "synthetic-source-producer",
            "source_suite": source_identity,
            "system": {"identity": "synthetic-source-system", "revision": "test-only-v1"},
            "completed_at": source_completed_at,
            "record_count": len(items),
            "source_items_subject_sha256": _items_subject_sha256(items, gold=False),
        },
    )
    atomic_json(
        gold_evidence,
        {
            "evidence_version": "1.0.0",
            "evidence_id": "synthetic-human-gold-evidence",
            "status": "approved",
            "reviewers": [
                {
                    "reviewer_id": "synthetic-a",
                    "decision": "approved",
                    "rationale": "Synthetic test-only gold labels match the fixture design.",
                    "reviewed_at": first_reviewed_at,
                },
                {
                    "reviewer_id": "synthetic-b",
                    "decision": "approved",
                    "rationale": "Synthetic test-only gold labels match the fixture design.",
                    "reviewed_at": second_reviewed_at,
                },
            ],
            "adjudicator_id": "synthetic-adjudicator",
            "adjudication_method": "Independent synthetic review followed by test-only adjudication.",
            "completed_at": gold_completed_at,
            "record_count": len(items),
            "gold_items_subject_sha256": _items_subject_sha256(items, gold=True),
        },
    )
    for item in items:
        item["source_run_manifest_sha256"] = sha256_file(source_run_manifest)
        item["gold_evidence_sha256"] = sha256_file(gold_evidence)
    source_items = corpus / "source-items.jsonl"
    corpus_dataset = corpus / "dataset.jsonl"
    responses = corpus / "recorded-responses.jsonl"
    corpus_rubric = corpus / "rubric.md"
    _jsonl(source_items, items)
    cases, recorded = _expected_corpus_rows(items)
    _jsonl(corpus_dataset, cases)
    _jsonl(responses, recorded)
    atomic_text(corpus_rubric, source_rubric.read_text(encoding="utf-8"))
    corpus_blueprint = corpus / "evidence/qualification-blueprint.toml"
    corpus_blueprint_approval = corpus / "evidence/qualification-blueprint-approval.json"
    atomic_text(corpus_blueprint, blueprint.read_text(encoding="utf-8"))
    atomic_text(corpus_blueprint_approval, blueprint_approval.read_text(encoding="utf-8"))
    corpus_suite_config = corpus / "suite.toml"
    qualification_consensus = str(judge_configuration.get("consensus", "majority")) if judge_configuration else "majority"
    atomic_text(
        corpus_suite_config,
        f'''protocol_version = "1.0.0"
name = "synthetic-judge-qualification-corpus"
version = "1.0.0"
status = "candidate"
description = "Synthetic human-gold judge qualification corpus."
profile = "text-generation"
dataset = "dataset.jsonl"
rubric = "rubric.md"
data_classification = "synthetic"
dataset_sha256 = "{sha256_file(corpus_dataset)}"
rubric_sha256 = "{sha256_file(corpus_rubric)}"
temperature = 0
max_tokens = 128

[target]
kind = "recorded"
responses = "recorded-responses.jsonl"
responses_sha256 = "{sha256_file(responses)}"
response_field = "answer"
reported_model_field = "model"

[statistics]
confidence = 0.95
bootstrap_samples = 100
seed = 7

[judge]
consensus = "{qualification_consensus}"
''',
    )
    corpus_manifest = corpus / "corpus_manifest.json"
    atomic_json(
        corpus_manifest,
        {
            "corpus_version": "1.0.0",
            "frozen_at": corpus_frozen_at_text,
            "blueprint_version": "1.0.0",
            "blueprint_path": "evidence/qualification-blueprint.toml",
            "blueprint_sha256": sha256_file(corpus_blueprint),
            "blueprint_approval_path": "evidence/qualification-blueprint-approval.json",
            "blueprint_approval_sha256": sha256_file(corpus_blueprint_approval),
            "source_suite": source_identity,
            "source_dataset_sha256": sha256_file(source_dataset),
            "source_rubric_sha256": sha256_file(source_rubric),
            "items_source_sha256": sha256_file(source_items),
            "dataset_sha256": sha256_file(corpus_dataset),
            "recorded_responses_sha256": sha256_file(responses),
            "rubric_sha256": sha256_file(corpus_rubric),
            "items": len(items),
            "model_family_aliases": sorted({str(item["model_family_alias"]) for item in items}),
            "gold_evidence_sha256": [sha256_file(gold_evidence)],
            "identity_blinded_to_judge": True,
            "independent_gold_required": True,
        },
    )

    configured_models = judge_configuration.get("models") if judge_configuration else None
    if judge_configuration is not None:
        assert isinstance(configured_models, list) and len(configured_models) == 1
        assert isinstance(configured_models[0], dict)
        configured_model = str(judge_configuration["requested_model"])
        configured_expected_model = str(judge_configuration["expected_reported_model"])
        configured_revision = str(judge_configuration["revision"])
        configured_endpoint = str(judge_configuration["endpoint"])
    else:
        configured_model = "synthetic-judge"
        configured_expected_model = "synthetic-judge"
        configured_revision = "synthetic-judge-revision-1"
        configured_endpoint = ""

    class JudgeHandler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802 -- BaseHTTPRequestHandler API.
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            verdict = "fail" if "NOT BLUE" in body.decode("utf-8") else "pass"
            judgment = {"verdict": verdict, "score": 5 if verdict == "pass" else 1, "reason": "synthetic gold", "criteria": {}}
            payload = {
                "model": configured_expected_model,
                "choices": [{"message": {"content": json.dumps(judgment)}}],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1},
            }
            encoded = json.dumps(payload).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def log_message(self, _format: str, *_args: object) -> None:
            pass

    source_tree = tmp_path / "synthetic-source-tree"
    source_tree.mkdir()
    atomic_text(source_tree / "README.md", "synthetic qualification source tree\n")
    git = shutil.which("git")
    assert git is not None

    def run_git(*arguments: str) -> None:
        subprocess.run([git, *arguments], cwd=source_tree, check=True)  # noqa: S603 -- fixed test-only Git commands.

    run_git("init", "-q")
    run_git("config", "user.name", "Cavada test fixture")
    run_git("config", "user.email", "fixture@example.invalid")
    run_git("add", "README.md")
    run_git("commit", "-q", "-m", "synthetic qualification fixture")
    server = ThreadingHTTPServer(("127.0.0.1", 0), JudgeHandler) if judge_configuration is None else None
    thread = threading.Thread(target=server.serve_forever, daemon=True) if server is not None else None
    if thread is not None:
        thread.start()
    try:
        endpoint = f"http://127.0.0.1:{server.server_port}/v1" if server is not None else configured_endpoint
        generated = run_evaluation(
            load_suite(corpus),
            repo_root=source_tree,
            endpoint=endpoint,
            model_label="synthetic-qualification-target",
            expected_model="recorded-human-gold",
            model_revision="synthetic-recorded-revision-1",
            request_model=None,
            judge_endpoint=endpoint,
            judge_model=configured_model,
            expected_judge_model=configured_expected_model,
            judge_revision=configured_revision,
            target_key_env="MISSING_SYNTHETIC_TARGET_KEY",
            judge_key_env="MISSING_SYNTHETIC_JUDGE_KEY",
            repetitions=3,
            judge_repetitions=3,
            max_cases=0,
            timeout=5,
            official=False,
            allow_external_judge=False,
            mode="candidate",
            concurrency=16,
        )
    finally:
        if server is not None and thread is not None:
            server.shutdown()
            thread.join()
    shutil.copytree(generated, run, dirs_exist_ok=True)
    (run / "verification.json").unlink(missing_ok=True)
    generated_manifest = _strict_json_loads((run / "manifest.json").read_bytes())
    assert isinstance(generated_manifest, dict)
    finished_at = datetime.fromisoformat(str(generated_manifest["finished_at"]).replace("Z", "+00:00"))
    qualification_approved_at = (finished_at + timedelta(microseconds=1)).isoformat().replace("+00:00", "Z")
    package_created_at = (finished_at + timedelta(microseconds=2)).isoformat().replace("+00:00", "Z")
    if judge_configuration is not None:
        assert generated_manifest.get("judge") == dict(judge_configuration)

    report = qualification / "report.json"
    qualify_judge_run(run, blueprint, corpus_manifest, report, now=NOW)
    judge_approval = qualification / "approval.json"
    atomic_json(
        judge_approval,
        {
            "approval_version": "3.0.0",
            "approval_id": "synthetic-judge-qualification-approval",
            "scope": "judge-qualification",
            "protocol_version": "1.0.0",
            "subject": _reference(report, package, "qualification-report", "2.0.0"),
            "decision": "approved",
            "independent": True,
            "approver_id": "synthetic-judge-reviewer",
            "approver_qualification_evidence": _reference(
                judge_reviewer,
                package,
                "judge-approver-qualification",
                "1.0.0",
            ),
            "conflict_of_interest_assessment": "No conflict in this test-only fixture.",
            "conflicts_resolved": True,
            "decision_rationale": "The byte-reconstructed synthetic qualification gates passed.",
            "permitted_claim_scope": ["judge-qualification"],
            "approved_at": qualification_approved_at,
            "expires_at": "2029-01-01T00:00:00Z",
            "revoked_at": None,
            "revocation_reason": "",
        },
    )

    artifacts = _package_artifacts(
        {
            path.relative_to(package).as_posix(): path.read_bytes()
            for path in sorted(package.rglob("*"))
            if path.is_file()
        }
    )
    atomic_json(
        package / "qualification_evidence.json",
        {
            "package_version": "1.0.0",
            "artifact_type": "judge-qualification-evidence-package",
            "protocol_version": "1.0.0",
            "created_at": package_created_at,
            "claim_scope": ["judge-qualification"],
            "artifacts": artifacts,
        },
    )
    write_bundle(package)
    if source_suite is None and judge_configuration is None:
        _TEMPLATE_TEMPORARY = TemporaryDirectory(prefix="cavada-synthetic-qualification-")
        _TEMPLATE_PACKAGE = Path(_TEMPLATE_TEMPORARY.name) / "package"
        shutil.copytree(package, _TEMPLATE_PACKAGE)
    return package, NOW, verify_behavior_base


def _reindex_package(package: Path) -> None:
    manifest_path = package / "qualification_evidence.json"
    manifest = _strict_json_loads(manifest_path.read_bytes())
    assert isinstance(manifest, dict) and isinstance(manifest.get("artifacts"), list)
    for artifact in manifest["artifacts"]:
        assert isinstance(artifact, dict) and isinstance(artifact.get("relative_path"), str)
        artifact["sha256"] = sha256_file(package / artifact["relative_path"])
    atomic_json(manifest_path, manifest)
    write_bundle(package)


def _production_staging(package: Path, destination: Path) -> Path:
    shutil.copytree(package, destination)
    for name in ("qualification_evidence.json", "bundle.json", "checksums.txt", "signature.json", "verification.json"):
        (destination / name).unlink(missing_ok=True)
    return destination


def test_production_builder_assembles_and_reverifies_closed_staging(tmp_path: Path) -> None:
    package, now, base_verifier = build_synthetic_qualification_package(tmp_path / "fixture")
    staging = _production_staging(package, tmp_path / "staging")
    output = tmp_path / "built-package"
    result = build_judge_qualification_package(
        staging,
        output,
        now=now,
        base_behavior_verifier=base_verifier,
    )
    assert result.valid is True
    assert output.is_dir()
    assert reconstruct_judge_qualification(output, now=now, base_behavior_verifier=base_verifier) == result


def test_production_builder_removes_only_invalid_new_output(tmp_path: Path) -> None:
    package, now, base_verifier = build_synthetic_qualification_package(tmp_path / "fixture")
    staging = _production_staging(package, tmp_path / "staging")
    report_path = staging / "qualification/report.json"
    report = _strict_json_loads(report_path.read_bytes())
    assert isinstance(report, dict)
    report["limitations"] = ["tampered after approval"]
    atomic_json(report_path, report)
    output = tmp_path / "invalid-package"
    with pytest.raises(ProtocolError, match="built judge qualification package is invalid"):
        build_judge_qualification_package(
            staging,
            output,
            now=now,
            base_behavior_verifier=base_verifier,
        )
    assert not output.exists()
    assert staging.is_dir()


def test_production_builder_rejects_unsafe_staging_and_existing_output(tmp_path: Path) -> None:
    package, now, base_verifier = build_synthetic_qualification_package(tmp_path / "fixture")
    staging = _production_staging(package, tmp_path / "staging")
    output = tmp_path / "existing"
    output.mkdir()
    marker = output / "keep.txt"
    marker.write_text("owned by caller\n", encoding="utf-8")
    with pytest.raises(ProtocolError, match="refusing to overwrite"):
        build_judge_qualification_package(staging, output, now=now, base_behavior_verifier=base_verifier)
    assert marker.read_text(encoding="utf-8") == "owned by caller\n"

    unsafe_output = tmp_path / "unsafe-output"
    (staging / "reviewers/unsafe-link").symlink_to(staging / "reviewers/judge-support.json")
    with pytest.raises(ProtocolError, match="staging tree is unsafe"):
        build_judge_qualification_package(
            staging,
            unsafe_output,
            now=now,
            base_behavior_verifier=base_verifier,
        )
    assert not unsafe_output.exists()


@pytest.mark.parametrize("with_marker", [False, True])
def test_production_builder_publish_race_preserves_existing_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, with_marker: bool
) -> None:
    package, now, base_verifier = build_synthetic_qualification_package(tmp_path / "fixture")
    staging = _production_staging(package, tmp_path / "staging")
    output = tmp_path / "concurrent-output"
    real_copytree = shutil.copytree

    def concurrent_publish(source: Path, destination: Path, **options: object) -> Path:
        destination.mkdir()
        if with_marker:
            (destination / "owned.txt").write_text("concurrent package\n", encoding="utf-8")
        return real_copytree(source, destination, **options)

    monkeypatch.setattr("cavada_eval.qualification_evidence.shutil.copytree", concurrent_publish)
    with pytest.raises(ProtocolError, match="without overwriting"):
        build_judge_qualification_package(
            staging,
            output,
            now=now,
            base_behavior_verifier=base_verifier,
        )
    assert output.is_dir()
    if with_marker:
        assert (output / "owned.txt").read_text(encoding="utf-8") == "concurrent package\n"
    else:
        assert list(output.iterdir()) == []


def test_judge_qualification_package_cli_uses_the_canonical_builder(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    staging = tmp_path / "staging"
    output = tmp_path / "package"
    observed: list[tuple[Path, Path]] = []

    def build(source: Path, destination: Path, **options: object) -> SimpleNamespace:
        observed.append((source, destination))
        assert callable(options["base_behavior_verifier"])
        return SimpleNamespace(valid=True, package_sha256="a" * 64)

    monkeypatch.setattr("cavada_eval.cli.build_judge_qualification_package", build)
    assert cli_main(["judge-qualify-package", str(staging), str(output)]) == 0
    assert observed == [(staging, output)]


def test_synthetic_qualification_package_reconstructs_from_bytes(tmp_path: Path) -> None:
    package, now, base_verifier = build_synthetic_qualification_package(tmp_path)
    result = reconstruct_judge_qualification(package, now=now, base_behavior_verifier=base_verifier)
    assert result.valid, result.failures
    assert result.integrity_valid and result.semantic_valid and result.approval_valid
    assert result.reconstructed_report is not None and result.reconstructed_report["passed"] is True


def test_report_passed_flag_is_not_evidence(tmp_path: Path) -> None:
    package, now, base_verifier = build_synthetic_qualification_package(tmp_path)
    report_path = package / "qualification/report.json"
    report = _strict_json_loads(report_path.read_bytes())
    assert isinstance(report, dict)
    report["limitations"] = ["A plausible but fabricated limitation cannot replace reconstruction."]
    report["passed"] = True
    atomic_json(report_path, report)
    _reindex_package(package)
    result = reconstruct_judge_qualification(package, now=now, base_behavior_verifier=base_verifier)
    assert result.integrity_valid is True
    assert result.semantic_valid is False
    assert "declared qualification report differs from byte-reconstructed report" in result.semantic_failures


def test_corpus_semantic_mutation_fails_with_fresh_hashes(tmp_path: Path) -> None:
    package, now, base_verifier = build_synthetic_qualification_package(tmp_path)
    items_path = package / "corpus/source-items.jsonl"
    rows = [_strict_json_loads(line) for line in items_path.read_text(encoding="utf-8").splitlines()]
    assert all(isinstance(row, dict) for row in rows)
    rows[0]["response"] = "SEMANTICALLY CHANGED"
    _jsonl(items_path, rows)
    corpus_manifest_path = package / "corpus/corpus_manifest.json"
    corpus_manifest = _strict_json_loads(corpus_manifest_path.read_bytes())
    assert isinstance(corpus_manifest, dict)
    corpus_manifest["items_source_sha256"] = sha256_file(items_path)
    atomic_json(corpus_manifest_path, corpus_manifest)
    _reindex_package(package)
    result = reconstruct_judge_qualification(package, now=now, base_behavior_verifier=base_verifier)
    assert result.integrity_valid is True
    assert result.semantic_valid is False
    assert "recorded judge responses do not reconstruct from the source items" in result.semantic_failures
    assert "source-run record" in "\n".join(result.semantic_failures)
    assert "independent-review record" in "\n".join(result.semantic_failures)


@pytest.mark.parametrize(
    ("relative", "mutation", "expected"),
    [
        (
            "run/rubric_snapshot.md",
            "rubric",
            "qualification run rubric_snapshot.md differs from the corpus package",
        ),
        (
            "run/manifest.json",
            "judge-revision",
            "qualification report does not bind the exact run, corpus, rubric, blueprint, and judge configuration",
        ),
        (
            "run/manifest.json",
            "judge-model",
            "qualification report does not bind the exact run, corpus, rubric, blueprint, and judge configuration",
        ),
        (
            "run/manifest.json",
            "judge-prompt",
            "qualification report does not bind the exact run, corpus, rubric, blueprint, and judge configuration",
        ),
        (
            "run/manifest.json",
            "target-repetitions",
            "qualification run repetitions does not satisfy the immutable blueprint",
        ),
        (
            "run/manifest.json",
            "inner-official",
            "qualification run must be candidate, non-official, non-rankable, and claim-free",
        ),
    ],
)
def test_run_corpus_and_judge_bindings_fail_with_fresh_hashes(
    tmp_path: Path,
    relative: str,
    mutation: str,
    expected: str,
) -> None:
    package, now, base_verifier = build_synthetic_qualification_package(tmp_path)
    path = package / relative
    if mutation == "rubric":
        path.write_bytes(path.read_bytes() + b"\nSemantic rubric mutation.\n")
    else:
        manifest = _strict_json_loads(path.read_bytes())
        assert isinstance(manifest, dict)
        if mutation == "judge-revision":
            judge = manifest.get("judge")
            assert isinstance(judge, dict)
            judge["revision"] = "different-judge-revision"
        elif mutation == "judge-model":
            judge = manifest.get("judge")
            assert isinstance(judge, dict)
            judge["expected_reported_model"] = "different-judge"
        elif mutation == "judge-prompt":
            judge = manifest.get("judge")
            assert isinstance(judge, dict)
            judge["prompt_sha256"] = "f" * 64
        elif mutation == "target-repetitions":
            parameters = manifest.get("parameters")
            assert isinstance(parameters, dict)
            parameters["repetitions"] = 1
        else:
            manifest.update(
                assurance="official",
                official=True,
                official_requested=True,
                model_claim_allowed=True,
                benchmark_claim_allowed=True,
            )
        atomic_json(path, manifest)
    write_bundle(package / "run")
    _reindex_package(package)
    result = reconstruct_judge_qualification(package, now=now, base_behavior_verifier=base_verifier)
    assert result.integrity_valid is True
    assert result.semantic_valid is False
    assert expected in result.semantic_failures


@pytest.mark.parametrize(
    ("relative", "field", "value", "expected"),
    [
        ("qualification/approval.json", "expires_at", "2026-01-01T00:00:00Z", "not currently effective"),
        ("qualification/approval.json", "approved_at", "2026-04-01T00:00:00Z", "predates the completed qualification run"),
        ("qualification/approval.json", "decision", "rejected", "did not approve"),
        ("qualification/approval.json", "independent", False, "incomplete, conflicted"),
        ("qualification/approval.json", "conflicts_resolved", False, "incomplete, conflicted"),
        ("qualification/approval.json", "revoked_at", "2026-06-01T00:00:00Z", "has been revoked"),
        ("reviewers/judge-reviewer.json", "decision", "not-qualified", "did not qualify"),
        ("reviewers/judge-reviewer.json", "assessor_independent", False, "did not qualify"),
        ("reviewers/judge-reviewer.json", "conflicts_resolved", False, "did not qualify"),
        ("reviewers/judge-reviewer.json", "revoked_at", "2026-06-01T00:00:00Z", "has been revoked"),
    ],
)
def test_approval_and_reviewer_mutations_fail_closed(
    tmp_path: Path,
    relative: str,
    field: str,
    value: object,
    expected: str,
) -> None:
    package, now, base_verifier = build_synthetic_qualification_package(tmp_path)
    path = package / relative
    record = _strict_json_loads(path.read_bytes())
    assert isinstance(record, dict)
    record[field] = value
    atomic_json(path, record)
    _reindex_package(package)
    result = reconstruct_judge_qualification(package, now=now, base_behavior_verifier=base_verifier)
    assert result.integrity_valid is True
    assert result.approval_valid is False
    assert expected in "\n".join(result.approval_failures)


@pytest.mark.parametrize(
    ("reference_name", "expected"),
    [
        ("approver_qualification_evidence", "approver_qualification_evidence does not bind"),
        ("subject", "subject does not bind"),
    ],
)
def test_approval_references_are_hash_bound(tmp_path: Path, reference_name: str, expected: str) -> None:
    package, now, base_verifier = build_synthetic_qualification_package(tmp_path)
    approval_path = package / "qualification/approval.json"
    approval = _strict_json_loads(approval_path.read_bytes())
    assert isinstance(approval, dict)
    reference = approval.get(reference_name)
    assert isinstance(reference, dict)
    reference["sha256"] = "0" * 64
    atomic_json(approval_path, approval)
    _reindex_package(package)
    result = reconstruct_judge_qualification(package, now=now, base_behavior_verifier=base_verifier)
    assert result.integrity_valid is True
    assert result.approval_valid is False
    assert expected in "\n".join(result.approval_failures)


def test_missing_approver_evidence_and_changed_blueprint_fail_closed(tmp_path: Path) -> None:
    package, now, base_verifier = build_synthetic_qualification_package(tmp_path / "missing")
    (package / "reviewers/judge-reviewer.json").unlink()
    write_bundle(package)
    missing = reconstruct_judge_qualification(package, now=now, base_behavior_verifier=base_verifier)
    assert missing.integrity_valid is False

    package, now, base_verifier = build_synthetic_qualification_package(tmp_path / "blueprint")
    blueprint = package / "source-suite/evidence/qualification-blueprint.toml"
    blueprint.write_bytes(blueprint.read_bytes() + b"\n# coordinated digest mutation\n")
    _reindex_package(package)
    changed = reconstruct_judge_qualification(package, now=now, base_behavior_verifier=base_verifier)
    assert changed.valid is False
    assert "qualification blueprint" in "\n".join(changed.failures)


def test_unknown_field_and_duplicate_json_key_are_rejected(tmp_path: Path) -> None:
    package, now, base_verifier = build_synthetic_qualification_package(tmp_path)
    manifest_path = package / "qualification_evidence.json"
    manifest = _strict_json_loads(manifest_path.read_bytes())
    assert isinstance(manifest, dict)
    manifest["unexpected"] = True
    atomic_json(manifest_path, manifest)
    write_bundle(package)
    result = reconstruct_judge_qualification(package, now=now, base_behavior_verifier=base_verifier)
    assert result.integrity_valid is False
    assert "unknown fields" in "\n".join(result.integrity_failures)

    package, now, base_verifier = build_synthetic_qualification_package(tmp_path / "duplicate")
    manifest_path = package / "qualification_evidence.json"
    raw = manifest_path.read_text(encoding="utf-8")
    manifest_path.write_text(raw.replace('{\n  "artifact_type"', '{\n  "package_version": "1.0.0",\n  "artifact_type"', 1), encoding="utf-8")
    write_bundle(package)
    duplicate = reconstruct_judge_qualification(package, now=now, base_behavior_verifier=base_verifier)
    assert duplicate.integrity_valid is False
    assert "duplicate JSON key" in "\n".join(duplicate.integrity_failures)


def test_artifact_metadata_and_semantic_digest_multiplicity_are_reconstructed(tmp_path: Path) -> None:
    package, now, base_verifier = build_synthetic_qualification_package(tmp_path / "metadata")
    manifest_path = package / "qualification_evidence.json"
    manifest = _strict_json_loads(manifest_path.read_bytes())
    assert isinstance(manifest, dict) and isinstance(manifest.get("artifacts"), list)
    report = next(item for item in manifest["artifacts"] if item["artifact_type"] == "qualification-report")
    report["media_type"] = "text/plain"
    atomic_json(manifest_path, manifest)
    write_bundle(package)
    result = reconstruct_judge_qualification(package, now=now, base_behavior_verifier=base_verifier)
    assert result.integrity_valid is False
    assert "artifact metadata differs from canonical byte reconstruction" in "\n".join(result.integrity_failures)

    package, now, base_verifier = build_synthetic_qualification_package(tmp_path / "digest")
    source = package / "corpus/source-run-manifest.json"
    duplicate = package / "corpus/source-run-manifest-copy.json"
    duplicate.write_bytes(source.read_bytes())
    manifest_path = package / "qualification_evidence.json"
    manifest = _strict_json_loads(manifest_path.read_bytes())
    assert isinstance(manifest, dict) and isinstance(manifest.get("artifacts"), list)
    manifest["artifacts"].append(
        {
            "artifact_id": "artifact-duplicate-source-run",
            "relative_path": "corpus/source-run-manifest-copy.json",
            "sha256": sha256_file(duplicate),
            "artifact_type": "corpus-source-run-manifest",
            "media_type": "application/json",
            "schema_version": "1.0.0",
        }
    )
    atomic_json(manifest_path, manifest)
    write_bundle(package)
    result = reconstruct_judge_qualification(package, now=now, base_behavior_verifier=base_verifier)
    assert result.integrity_valid is False
    assert "artifact roles cannot be reconstructed" in "\n".join(result.integrity_failures)


def test_reviewer_support_cannot_be_an_external_url_only(tmp_path: Path) -> None:
    package, now, base_verifier = build_synthetic_qualification_package(tmp_path)
    support_path = package / "reviewers/judge-support.json"
    support = _strict_json_loads(support_path.read_bytes())
    assert isinstance(support, dict)
    support["content"] = "https://example.invalid/reviewer-cv"
    atomic_json(support_path, support)
    _reindex_package(package)

    result = reconstruct_judge_qualification(package, now=now, base_behavior_verifier=base_verifier)

    assert result.approval_valid is False
    assert "cannot consist only of an external URL" in "\n".join(result.approval_failures)


def test_reviewer_support_must_predate_qualification(tmp_path: Path) -> None:
    package, now, base_verifier = build_synthetic_qualification_package(tmp_path)
    support_path = package / "reviewers/judge-support.json"
    support = _strict_json_loads(support_path.read_bytes())
    assert isinstance(support, dict)
    support["issued_at"] = "2026-01-15T00:00:00Z"
    atomic_json(support_path, support)
    _reindex_package(package)

    result = reconstruct_judge_qualification(package, now=now, base_behavior_verifier=base_verifier)

    assert result.approval_valid is False
    assert "postdates the reviewer qualification" in "\n".join(result.approval_failures)


def test_synthetic_reviewer_support_is_limited_to_conformance_fixtures(tmp_path: Path) -> None:
    package, now, base_verifier = build_synthetic_qualification_package(tmp_path)
    suite_path = package / "source-suite/suite.toml"
    suite_path.write_text(
        suite_path.read_text(encoding="utf-8").replace(
            'assurance = "conformance-fixture"',
            'assurance = "candidate"',
        ),
        encoding="utf-8",
    )
    _reindex_package(package)

    result = reconstruct_judge_qualification(package, now=now, base_behavior_verifier=base_verifier)

    assert result.approval_valid is False
    assert "cannot use synthetic evidence outside a conformance fixture" in "\n".join(result.approval_failures)


def test_reviewer_support_schema_version_cannot_be_self_declared(tmp_path: Path) -> None:
    package, now, base_verifier = build_synthetic_qualification_package(tmp_path)
    reviewer_path = package / "reviewers/judge-reviewer.json"
    reviewer = _strict_json_loads(reviewer_path.read_bytes())
    assert isinstance(reviewer, dict) and isinstance(reviewer.get("supporting_evidence"), list)
    reference = reviewer["supporting_evidence"][0]
    assert isinstance(reference, dict)
    reference["schema_version"] = "999.0.0"
    atomic_json(reviewer_path, reviewer)
    approval_path = package / "qualification/approval.json"
    approval = _strict_json_loads(approval_path.read_bytes())
    assert isinstance(approval, dict) and isinstance(approval.get("approver_qualification_evidence"), dict)
    approval["approver_qualification_evidence"]["sha256"] = sha256_file(reviewer_path)
    atomic_json(approval_path, approval)
    _reindex_package(package)

    result = reconstruct_judge_qualification(package, now=now, base_behavior_verifier=base_verifier)

    assert result.valid is False
    assert "does not bind the exact package artifact" in "\n".join(result.approval_failures)


def test_stale_byte_flip_and_base_semantic_failure_are_rejected(tmp_path: Path) -> None:
    package, now, base_verifier = build_synthetic_qualification_package(tmp_path)
    rubric = package / "corpus/rubric.md"
    rubric.write_bytes(rubric.read_bytes() + b"tamper")
    stale = reconstruct_judge_qualification(package, now=now, base_behavior_verifier=base_verifier)
    assert stale.integrity_valid is False

    package, now, _ = build_synthetic_qualification_package(tmp_path / "base")
    failed = reconstruct_judge_qualification(
        package,
        now=now,
        base_behavior_verifier=lambda _run, _now: {"integrity_valid": True, "semantic_valid": False},
    )
    assert failed.integrity_valid is True
    assert failed.semantic_valid is False
    assert "base behavior semantic verification" in "\n".join(failed.semantic_failures)


def test_every_declared_qualification_artifact_is_byte_bound(tmp_path: Path) -> None:
    package, now, base_verifier = build_synthetic_qualification_package(tmp_path)
    manifest = _strict_json_loads((package / "qualification_evidence.json").read_bytes())
    assert isinstance(manifest, dict) and isinstance(manifest.get("artifacts"), list)
    for artifact in manifest["artifacts"]:
        assert isinstance(artifact, dict) and isinstance(artifact.get("relative_path"), str)
        path = package / artifact["relative_path"]
        original = path.read_bytes()
        path.write_bytes(original[:-1] + bytes([original[-1] ^ 1]) if original else b"x")
        result = reconstruct_judge_qualification(package, now=now, base_behavior_verifier=base_verifier)
        assert result.integrity_valid is False, artifact["relative_path"]
        path.write_bytes(original)


@pytest.mark.parametrize("mutation", ["absolute", "traversal", "duplicate", "case-collision"])
def test_qualification_manifest_rejects_unsafe_or_ambiguous_paths(tmp_path: Path, mutation: str) -> None:
    package, now, base_verifier = build_synthetic_qualification_package(tmp_path)
    manifest_path = package / "qualification_evidence.json"
    manifest = _strict_json_loads(manifest_path.read_bytes())
    assert isinstance(manifest, dict) and isinstance(manifest.get("artifacts"), list)
    artifacts = manifest["artifacts"]
    assert len(artifacts) >= 2 and all(isinstance(item, dict) for item in artifacts[:2])
    first = artifacts[0]
    second = artifacts[1]
    if mutation == "absolute":
        first["relative_path"] = "/absolute/outside"
    elif mutation == "traversal":
        first["relative_path"] = "../outside"
    elif mutation == "duplicate":
        second["relative_path"] = first["relative_path"]
    else:
        second["relative_path"] = str(first["relative_path"]).swapcase()
    atomic_json(manifest_path, manifest)
    write_bundle(package)

    result = reconstruct_judge_qualification(package, now=now, base_behavior_verifier=base_verifier)

    assert result.integrity_valid is False


def test_qualification_package_rejects_missing_and_extra_files(tmp_path: Path) -> None:
    package, now, base_verifier = build_synthetic_qualification_package(tmp_path / "missing")
    (package / "qualification/report.json").unlink()
    missing = reconstruct_judge_qualification(package, now=now, base_behavior_verifier=base_verifier)
    assert missing.integrity_valid is False

    package, now, base_verifier = build_synthetic_qualification_package(tmp_path / "extra")
    (package / "undeclared-extra.txt").write_text("not declared\n", encoding="utf-8")
    extra = reconstruct_judge_qualification(package, now=now, base_behavior_verifier=base_verifier)
    assert extra.integrity_valid is False


def test_package_rejects_unbundled_verification_control_file(tmp_path: Path) -> None:
    package, now, base_verifier = build_synthetic_qualification_package(tmp_path)
    atomic_json(package / "verification.json", {"valid": True})
    result = reconstruct_judge_qualification(package, now=now, base_behavior_verifier=base_verifier)
    assert result.integrity_valid is False
    assert "control file set is not closed" in "\n".join(result.integrity_failures)


def test_new_evidence_schemas_close_every_contract_object() -> None:
    root = Path(__file__).parents[1] / "schemas"
    names = (
        "judge-qualification-evidence-package-1.0.0.schema.json",
        "judge-approval-3.0.0.schema.json",
        "judge-qualification-blueprint-approval-2.0.0.schema.json",
        "reviewer-qualification-evidence-1.0.0.schema.json",
    )

    def objects(value: Any) -> list[dict[str, Any]]:
        found: list[dict[str, Any]] = []
        if isinstance(value, dict):
            declared = value.get("type")
            if declared == "object" or isinstance(declared, list) and "object" in declared:
                found.append(value)
            for child in value.values():
                found.extend(objects(child))
        elif isinstance(value, list):
            for child in value:
                found.extend(objects(child))
        return found

    for name in names:
        schema = json.loads((root / name).read_text(encoding="utf-8"))
        assert all(node.get("additionalProperties") is False for node in objects(schema)), name
