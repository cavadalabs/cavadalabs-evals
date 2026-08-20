from __future__ import annotations

import hashlib
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path

import pytest

from cavada_eval.artifacts import write_bundle
from cavada_eval.behavior_verify import _ledger_errors, _safe_path, suite_snapshot_files, verify_behavior_run
from cavada_eval.calibration import _qualification_structure_errors
from cavada_eval.demo import run_demo
from cavada_eval.metrics import deterministic_evaluation
from cavada_eval.protocol import ProtocolError, Suite, sha256_file
from cavada_eval.release import verified_public_release


def _bundle(root: Path, manifest: str | dict[str, object]) -> Path:
    root.mkdir()
    (root / "manifest.json").write_text(manifest if isinstance(manifest, str) else json.dumps(manifest), encoding="utf-8")
    write_bundle(root)
    return root


def test_incomplete_candidate_is_not_mistaken_for_semantically_valid_evidence(tmp_path: Path) -> None:
    run = _bundle(tmp_path / "run", {"run_id": "candidate", "official": False, "official_requested": False})
    candidate = verify_behavior_run(run)
    assert candidate["integrity_valid"] is True
    assert candidate["semantic_valid"] is False
    assert candidate["valid"] is False
    assert candidate["semantic"]["required"] is True
    assert candidate["verification_result_version"] == "2.0.0"
    assert candidate["artifact_type"] == "behavior-run"
    assert candidate["rankable"] is False

    manifest = json.loads((run / "manifest.json").read_text(encoding="utf-8"))
    manifest["assurance"] = "official"
    (run / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    write_bundle(run)
    claimed = verify_behavior_run(run)
    assert claimed["semantic_valid"] is False
    assert claimed["valid"] is False

    manifest.pop("assurance")
    manifest.update({"official": True, "official_requested": True, "status": "passed"})
    (run / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    write_bundle(run)
    escalated = verify_behavior_run(run, now=datetime(2026, 8, 5, tzinfo=timezone.utc))
    assert escalated["integrity_valid"] is True
    assert escalated["semantic_valid"] is False
    assert escalated["valid"] is False

    with pytest.raises(ProtocolError) as caught:
        verified_public_release(run, tmp_path / "missing-engagement.json", tmp_path / "missing-approval.json")
    assert all(failure in str(caught.value) for failure in verify_behavior_run(run)["failures"])


def test_candidate_semantics_reject_tampering_after_checksums_are_regenerated(tmp_path: Path) -> None:
    run = Path(run_demo(Path.cwd(), artifact_root=tmp_path)["run"])
    verified = verify_behavior_run(run)
    assert verified["integrity_valid"] is True
    assert verified["semantic_valid"] is True
    assert verified["assurance_valid"] is True
    assert verified["valid"] is True
    assert verified["assurance_level"] == "candidate"
    assert verified["claim_scope"] == []
    assert verified["rankable"] is False

    metrics = json.loads((run / "metrics.json").read_text(encoding="utf-8"))
    metrics["pass"] = 0
    (run / "metrics.json").write_text(json.dumps(metrics, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    manifest = json.loads((run / "manifest.json").read_text(encoding="utf-8"))
    manifest["metrics"] = metrics
    manifest["artifacts"]["metrics.json"] = sha256_file(run / "metrics.json")
    (run / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    write_bundle(run)

    tampered = verify_behavior_run(run)
    assert tampered["integrity_valid"] is True
    assert tampered["semantic_valid"] is False
    assert tampered["valid"] is False
    assert "metrics pass does not reconcile" in "\n".join(tampered["semantic_failures"])


def test_candidate_semantics_reject_unknown_ledger_fields_with_fresh_checksums(tmp_path: Path) -> None:
    run = Path(run_demo(Path.cwd(), artifact_root=tmp_path)["run"])
    request_path = run / "requests.jsonl"
    requests = [json.loads(line) for line in request_path.read_text(encoding="utf-8").splitlines()]
    requests[0]["untrusted_extension"] = True
    request_path.write_text("".join(json.dumps(row) + "\n" for row in requests), encoding="utf-8")
    manifest = json.loads((run / "manifest.json").read_text(encoding="utf-8"))
    manifest["artifacts"]["requests.jsonl"] = sha256_file(request_path)
    (run / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    write_bundle(run)

    tampered = verify_behavior_run(run)
    assert tampered["integrity_valid"] is True
    assert tampered["semantic_valid"] is False
    assert tampered["valid"] is False
    assert "requests.jsonl[0] has unknown fields" in "\n".join(tampered["semantic_failures"])


def test_recorded_target_response_is_bound_to_its_source_bytes(tmp_path: Path) -> None:
    run = Path(run_demo(Path.cwd(), artifact_root=tmp_path)["run"])
    responses_path = run / "raw_responses.jsonl"
    responses = [json.loads(line) for line in responses_path.read_text(encoding="utf-8").splitlines()]
    responses[0]["response"]["forged_not_in_recorded_source"] = True
    responses_path.write_text("".join(json.dumps(response) + "\n" for response in responses), encoding="utf-8")
    manifest = json.loads((run / "manifest.json").read_text(encoding="utf-8"))
    manifest["artifacts"]["raw_responses.jsonl"] = sha256_file(responses_path)
    (run / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    write_bundle(run)

    tampered = verify_behavior_run(run)

    assert tampered["integrity_valid"] is True and tampered["semantic_valid"] is False
    assert "recorded target response differs from its hash-pinned source" in "\n".join(tampered["semantic_failures"])


def test_candidate_bundle_rejects_extra_artifacts_even_when_reindexed(tmp_path: Path) -> None:
    run = Path(run_demo(Path.cwd(), artifact_root=tmp_path)["run"])
    extra = run / "unexpected-extra.bin"
    extra.write_bytes(b"not part of the behavior artifact contract")
    write_bundle(run)

    undeclared = verify_behavior_run(run)
    assert undeclared["integrity_valid"] is True and undeclared["semantic_valid"] is False
    assert "closed file set differs" in "\n".join(undeclared["semantic_failures"])

    manifest = json.loads((run / "manifest.json").read_text(encoding="utf-8"))
    manifest["artifacts"][extra.name] = sha256_file(extra)
    (run / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    write_bundle(run)

    reindexed = verify_behavior_run(run)
    assert reindexed["integrity_valid"] is True and reindexed["semantic_valid"] is False
    assert "declares unsupported artifacts" in "\n".join(reindexed["semantic_failures"])

    extra.unlink()
    manifest["artifacts"].pop(extra.name)
    official_only = run / "engagement_evidence/evil"
    official_only.parent.mkdir()
    official_only.write_bytes(b"candidate cannot smuggle official assurance evidence")
    manifest["artifacts"][official_only.relative_to(run).as_posix()] = sha256_file(official_only)
    (run / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    write_bundle(run)

    prefixed = verify_behavior_run(run)
    assert prefixed["integrity_valid"] is True and prefixed["semantic_valid"] is False
    assert "declares unsupported artifacts" in "\n".join(prefixed["semantic_failures"])

    official_only.unlink()
    official_only.parent.rmdir()
    manifest["artifacts"].pop("engagement_evidence/evil")
    manifest["artifact_security"]["encryption_state"] = "attested"
    (run / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    write_bundle(run)

    overclaim = verify_behavior_run(run)
    assert overclaim["integrity_valid"] is True and overclaim["semantic_valid"] is False
    assert "artifact security states do not reconstruct" in "\n".join(overclaim["semantic_failures"])

    manifest["artifact_security"].update(
        storage_attestation={
            "attestation_id": "",
            "approver": "",
            "encryption_at_rest": True,
            "immutability": True,
            "access_policy_reference": "",
            "audit_log_reference": "",
            "retention_policy_reference": "",
            "backup_restore_reference": "",
            "effective_at": manifest["started_at"],
            "expires_at": "2099-01-01T00:00:00Z",
        },
        encryption_state="attested",
        immutability_state="attested",
    )
    (run / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    write_bundle(run)
    empty_storage = verify_behavior_run(run)
    assert "storage attestation fields are incomplete" in "\n".join(empty_storage["semantic_failures"])

    manifest["artifact_security"].update(
        storage_attestation=None,
        encryption_state="not-attested",
        immutability_state="not-attested",
    )
    manifest["target"]["endpoint"] = "https://forged-target.invalid"
    manifest["judge"]["endpoint"] = "https://forged-judge.invalid"
    (run / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    write_bundle(run)

    endpoints = verify_behavior_run(run)
    assert endpoints["integrity_valid"] is True and endpoints["semantic_valid"] is False
    endpoint_failures = "\n".join(endpoints["semantic_failures"])
    assert "target request endpoint differs from the manifest" in endpoint_failures
    assert "judge request endpoint differs from the manifest" in endpoint_failures

    requests_path = run / "requests.jsonl"
    requests = [json.loads(line) for line in requests_path.read_text(encoding="utf-8").splitlines()]
    for request in requests:
        request["endpoint"] = manifest["target"]["endpoint"] if request["kind"] == "target" else manifest["judge"]["endpoint"]
    requests_path.write_text("".join(json.dumps(request) + "\n" for request in requests), encoding="utf-8")
    manifest["artifacts"]["requests.jsonl"] = sha256_file(requests_path)
    manifest["external_authorization"] = {
        "authorization_id": "wrong-destination",
        "approver": "independent-reviewer",
        "purpose": "candidate test",
        "destinations": [{"host": "other.invalid", "region": "test", "purpose": "candidate test"}],
        "effective_at": manifest["started_at"],
        "expires_at": "2099-01-01T00:00:00Z",
    }
    manifest["external_judge_authorized"] = True
    (run / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    write_bundle(run)

    wrong_authorization = verify_behavior_run(run)
    assert wrong_authorization["integrity_valid"] is True and wrong_authorization["semantic_valid"] is False
    authorization_failures = "\n".join(wrong_authorization["semantic_failures"])
    assert "external authorization omits hosts" in authorization_failures
    assert "external_judge_authorized does not reconstruct" in authorization_failures


def test_behavior_verifier_checks_hmac_when_the_internal_key_is_available(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CAVADA_EVAL_SIGNING_KEY", "synthetic-test-only-signing-key")
    run = Path(run_demo(Path.cwd(), artifact_root=tmp_path)["run"])
    signature_path = run / "signature.json"
    signature = json.loads(signature_path.read_text(encoding="utf-8"))
    signature["signature"] = "0" * 64
    signature_path.write_text(json.dumps(signature, sort_keys=True) + "\n", encoding="utf-8")

    invalid = verify_behavior_run(run)
    assert invalid["integrity_valid"] is False
    assert invalid["valid"] is False
    assert "invalid bundle signature" in "\n".join(invalid["integrity_failures"])

    monkeypatch.delenv("CAVADA_EVAL_SIGNING_KEY")
    unverified = verify_behavior_run(run)
    assert unverified["integrity_valid"] is True
    assert unverified["signature"] == "unverified"


def test_candidate_semantics_reject_nested_types_reports_versions_and_protocol_with_fresh_checksums(
    tmp_path: Path,
) -> None:
    baseline_root = tmp_path / "baseline"
    baseline_root.mkdir()
    baseline = Path(run_demo(Path.cwd(), artifact_root=baseline_root)["run"])

    def clone(name: str) -> Path:
        destination = tmp_path / name
        shutil.copytree(baseline, destination)
        (destination / "verification.json").unlink()
        return destination

    def finish(run: Path, *artifacts: str) -> dict[str, object]:
        manifest = json.loads((run / "manifest.json").read_text(encoding="utf-8"))
        for artifact in artifacts:
            manifest["artifacts"][artifact] = sha256_file(run / artifact)
        if "protocol_snapshot.md" in artifacts:
            manifest["protocol_sha256"] = sha256_file(run / "protocol_snapshot.md")
        (run / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        write_bundle(run)
        return verify_behavior_run(run)

    transport_run = clone("transport-type")
    responses_path = transport_run / "raw_responses.jsonl"
    responses = [json.loads(line) for line in responses_path.read_text(encoding="utf-8").splitlines()]
    responses[0]["transport"]["request_bytes"] = "not-an-integer"
    responses_path.write_text("".join(json.dumps(row) + "\n" for row in responses), encoding="utf-8")
    transport = finish(transport_run, "raw_responses.jsonl")
    assert transport["integrity_valid"] is True and transport["semantic_valid"] is False
    assert "request_bytes must be a non-negative integer" in "\n".join(transport["semantic_failures"])

    result_run = clone("result-type")
    results_path = result_run / "case_results.jsonl"
    results = [json.loads(line) for line in results_path.read_text(encoding="utf-8").splitlines()]
    results[0]["reason"] = 12345
    results[0]["duration_ms"] = "bad"
    results_path.write_text("".join(json.dumps(row) + "\n" for row in results), encoding="utf-8")
    result = finish(result_run, "case_results.jsonl")
    assert result["integrity_valid"] is True and result["semantic_valid"] is False
    assert "reason must be a non-empty string" in "\n".join(result["semantic_failures"])
    assert "duration_ms must be a finite non-negative number" in "\n".join(result["semantic_failures"])

    report_run = clone("derived-report")
    (report_run / "summary.json").write_text('{"tampered":true}\n', encoding="utf-8")
    report = finish(report_run, "summary.json")
    assert report["integrity_valid"] is True and report["semantic_valid"] is False
    assert "derived report does not reconstruct from behavior evidence: summary.json" in "\n".join(
        report["semantic_failures"]
    )

    derived_mutations = {
        "dataset_card.md": ("tampered card\n", "dataset card does not reconstruct"),
        "scenario_results.jsonl": ('{"case_id":"forged"}\n', "scenario results exist without reconstructible"),
        "adjudication_queue.jsonl": (
            json.dumps(results[1]) + "\n",
            "adjudication queue does not reconcile",
        ),
        "asset_inventory.json": ('[{"tampered":true}]\n', "asset inventory does not reconstruct"),
    }
    for artifact, (content, expected_failure) in derived_mutations.items():
        derived_run = clone(f"derived-{artifact.replace('.', '-')}")
        (derived_run / artifact).write_text(content, encoding="utf-8")
        derived = finish(derived_run, artifact)
        assert derived["integrity_valid"] is True and derived["semantic_valid"] is False
        assert expected_failure in "\n".join(derived["semantic_failures"])

    wire_run = clone("missing-wire")
    judgments_path = wire_run / "judgments.jsonl"
    judgments = [json.loads(line) for line in judgments_path.read_text(encoding="utf-8").splitlines()]
    for field in ("wire_body_base64", "wire_body_sha256", "wire_body_bytes", "wire_body_truncated"):
        judgments[0].pop(field)
    judgments_path.write_text("".join(json.dumps(row) + "\n" for row in judgments), encoding="utf-8")
    wire = finish(wire_run, "judgments.jsonl")
    assert wire["integrity_valid"] is True and wire["semantic_valid"] is False
    assert "successful judge response lacks complete wire bytes" in "\n".join(wire["semantic_failures"])

    version_run = clone("manifest-version")
    version_manifest = json.loads((version_run / "manifest.json").read_text(encoding="utf-8"))
    version_manifest.update(
        {
            "protocol_version": "999.999.999",
            "report_version": "999.999.999",
            "adapter_contract_version": "999.999.999",
            "run_id": 123,
            "reproduction_command": [],
        }
    )
    (version_run / "manifest.json").write_text(
        json.dumps(version_manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    write_bundle(version_run)
    version = verify_behavior_run(version_run)
    assert version["integrity_valid"] is True and version["semantic_valid"] is False
    version_failures = "\n".join(version["semantic_failures"])
    assert "protocol_version must be" in version_failures
    assert "run_id must be a non-empty string" in version_failures

    for field in ("official", "finished_at", "abort_reason", "protocol_sha256", "metrics", "artifacts"):
        missing_run = clone(f"missing-{field}")
        missing_manifest = json.loads((missing_run / "manifest.json").read_text(encoding="utf-8"))
        missing_manifest.pop(field)
        (missing_run / "manifest.json").write_text(
            json.dumps(missing_manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        write_bundle(missing_run)
        missing = verify_behavior_run(missing_run)
        assert missing["integrity_valid"] is True and missing["semantic_valid"] is False
        assert field in "\n".join(missing["semantic_failures"])

    protocol_run = clone("protocol-snapshot")
    (protocol_run / "protocol_snapshot.md").write_text("tampered protocol\n", encoding="utf-8")
    protocol = finish(protocol_run, "protocol_snapshot.md")
    assert protocol["integrity_valid"] is True and protocol["semantic_valid"] is False
    assert "protocol snapshot differs from the canonical protocol asset" in "\n".join(protocol["semantic_failures"])


@pytest.mark.parametrize(
    "manifest, expected",
    [
        ('{"official_requested":false,"official_requested":true}', "duplicate JSON key"),
        ('{"official_requested":false,"score":NaN}', "non-finite JSON number"),
        ('{"official_requested":false,"score":Infinity}', "non-finite JSON number"),
        ('{"official_requested":false,"score":1e999}', "non-finite JSON number"),
    ],
)
def test_manifest_rejects_duplicate_keys_and_non_finite_numbers(tmp_path: Path, manifest: str, expected: str) -> None:
    result = verify_behavior_run(_bundle(tmp_path / "run", manifest))
    assert result["valid"] is False
    assert expected in "\n".join(result["failures"])


def test_safe_path_rejects_symlink_ancestor(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (tmp_path / "linked").symlink_to(outside, target_is_directory=True)
    with pytest.raises(ProtocolError, match="path is unsafe"):
        _safe_path(tmp_path, "linked/evidence.json", "evidence")


def test_qualification_v2_requires_nested_schema_fields() -> None:
    errors = _qualification_structure_errors(
        {
            "bundle_verification": {"valid": True},
            "judge_configuration": {},
            "judges": {"primary": {"passed": True}},
        }
    )
    assert "judge qualification.bundle_verification is missing fields" in "\n".join(errors)
    assert "judge qualification.judges.primary is missing fields" in "\n".join(errors)


def test_multi_judge_reconciliation_keys_include_judge_id(tmp_path: Path) -> None:
    case = {
        "id": "one",
        "input": "Question",
        "category": "quality",
        "risk_domain": "quality",
        "severity": "low",
        "expected_behavior": "answer",
        "expected_behavior_reason": "Answer the question.",
        "expected_contains": ["Answer"],
    }
    suite = Suite(tmp_path, {"target": {"kind": "json"}}, (case,), "rubric", tmp_path / "dataset.jsonl", tmp_path / "rubric.md")
    raw = {"answer": "Answer", "model": "target-real", "usage": {"prompt_tokens": 2, "completion_tokens": 2}}
    deterministic = deterministic_evaluation(case, "Answer", target_raw=raw, retrieved_ids=[], tool_calls=[])
    base = {"case_id": "one", "repetition": 1}
    target_transport = {"request_id": "target-1", "total_ms": 4.0, "headers_ms": 1.0, "response_bytes": 10}
    requests = [{**base, "kind": "target", "request_id": "target-1"}]
    requests.extend(
        {
            **base,
            "kind": "judge",
            "judge_id": judge_id,
            "judge_repetition": index,
            "model_repetition": 1,
            "request_id": f"judge-{judge_id}",
            "requested_model": f"{judge_id}-request",
            "judge_revision": f"{judge_id}-revision",
        }
        for index, judge_id in enumerate(("left", "right"), 1)
    )
    judgment = {"verdict": "pass", "score": 5, "reason": "ok", "criteria": {}}
    judge_content = json.dumps(judgment)
    judgments = [
        {
            **base,
            "judge_id": judge_id,
            "judge_repetition": index,
            "model_repetition": 1,
            "requested_model": f"{judge_id}-request",
            "judge_revision": f"{judge_id}-revision",
            "reported_model": f"{judge_id}-real",
            "judgment": judgment,
            "raw": {"model": f"{judge_id}-real", "choices": [{"message": {"content": judge_content}}]},
            "raw_content": judge_content,
            "transport": {"request_id": f"judge-{judge_id}"},
        }
        for index, judge_id in enumerate(("left", "right"), 1)
    ]
    rows = {
        "requests.jsonl": requests,
        "raw_responses.jsonl": [{**base, "reported_model": "target-real", "response": raw, "transport": target_transport}],
        "judgments.jsonl": judgments,
        "case_results.jsonl": [
            {
                **base,
                "status": "pass",
                "reason": "judge unanimous",
                "score": 5.0,
                "judge_agreement": 1.0,
                "deterministic": deterministic,
                "target_latency_ms": 4.0,
                "target_headers_ms": 1.0,
                "target_response_bytes": 10,
                "input_tokens": 2,
                "output_tokens": 2,
                "output_tokens_per_second": 500.0,
            }
        ],
    }
    for name, values in rows.items():
        (tmp_path / name).write_text("".join(json.dumps(value) + "\n" for value in values), encoding="utf-8")
    manifest = {
        "parameters": {"repetitions": 1, "judge_repetitions": 1},
        "target": {"expected_reported_model": "target-real"},
        "judge": {
            "consensus": "unanimous",
            "models": [
                {"id": "left", "model": "left-request", "expected_model": "left-real", "revision": "left-revision"},
                {"id": "right", "model": "right-request", "expected_model": "right-real", "revision": "right-revision"},
            ],
        },
    }
    baseline = _ledger_errors(suite, manifest, tmp_path)
    assert "judge request and output ledgers do not exactly reconcile" not in baseline
    assert not any("judge projection differs" in failure or "judge identity mismatch" in failure for failure in baseline)
    assert not any("case result performance projection differs" in failure for failure in baseline)

    judgments[0]["raw"]["model"] = "forged-model"
    (tmp_path / "judgments.jsonl").write_text("".join(json.dumps(value) + "\n" for value in judgments), encoding="utf-8")
    assert any("judge identity mismatch" in failure for failure in _ledger_errors(suite, manifest, tmp_path))

    judgments[0]["raw"]["model"] = "left-real"
    judgments[0]["raw_content"] = "forged projection"
    (tmp_path / "judgments.jsonl").write_text("".join(json.dumps(value) + "\n" for value in judgments), encoding="utf-8")
    assert any("judge projection differs" in failure for failure in _ledger_errors(suite, manifest, tmp_path))

    judgments[0]["raw_content"] = judge_content
    rows["case_results.jsonl"][0]["target_latency_ms"] = 4000.0
    (tmp_path / "judgments.jsonl").write_text("".join(json.dumps(value) + "\n" for value in judgments), encoding="utf-8")
    (tmp_path / "case_results.jsonl").write_text(
        "".join(json.dumps(value) + "\n" for value in rows["case_results.jsonl"]), encoding="utf-8"
    )
    assert any("case result performance projection differs" in failure for failure in _ledger_errors(suite, manifest, tmp_path))


def test_suite_snapshot_closes_pilot_campaign_and_every_run_bundle(tmp_path: Path) -> None:
    run = tmp_path / "pilot" / "run-one"
    run.mkdir(parents=True)
    (run / "manifest.json").write_text('{"run_id":"pilot-one"}', encoding="utf-8")
    write_bundle(run)
    evidence = tmp_path / "pilot" / "evidence.json"
    evidence.write_text('{"status":"passed"}', encoding="utf-8")
    evidence_hash = hashlib.sha256(evidence.read_bytes()).hexdigest()
    campaign = {
        "campaign_version": "1.0.0",
        "judge_qualification": {"path": evidence.name, "sha256": evidence_hash},
        "judge_independent_approval": {"path": evidence.name, "sha256": evidence_hash},
        "transcript_review": {"path": evidence.name, "sha256": evidence_hash},
        "runs": [{"role": "target", "family_alias": "family-a", "path": run.name}],
    }
    campaign_path = tmp_path / "pilot" / "campaign.json"
    campaign_path.write_text(json.dumps(campaign), encoding="utf-8")
    campaign_hash = hashlib.sha256(campaign_path.read_bytes()).hexdigest()
    report = {"pilot_campaign": "pilot/campaign.json", "pilot_campaign_sha256": campaign_hash}
    report_path = tmp_path / "calibration.json"
    report_path.write_text(json.dumps(report), encoding="utf-8")
    report_hash = hashlib.sha256(report_path.read_bytes()).hexdigest()
    dataset = tmp_path / "dataset.jsonl"
    rubric = tmp_path / "rubric.md"
    dataset.write_text("", encoding="utf-8")
    rubric.write_text("rubric", encoding="utf-8")
    suite = Suite(
        tmp_path,
        {"calibration": {"evidence": report_path.name, "evidence_sha256": report_hash}},
        (),
        "rubric",
        dataset,
        rubric,
    )
    snapshots = suite_snapshot_files(suite)
    assert {
        "calibration.json",
        "pilot/campaign.json",
        "pilot/evidence.json",
        "pilot/run-one/manifest.json",
        "pilot/run-one/bundle.json",
        "pilot/run-one/checksums.txt",
    } <= set(snapshots)
