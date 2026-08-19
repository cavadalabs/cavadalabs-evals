from __future__ import annotations

import argparse
import json
import re
import tomllib
from collections import Counter
from pathlib import Path
from typing import Any

from cavada_eval.program import validate_judge_qualification_blueprint
from cavada_eval.protocol import ProtocolError, _read_jsonl, append_jsonl, atomic_json, atomic_text, load_suite, sha256_bytes, sha256_file

REQUIRED = {
    "item_id",
    "source_case_id",
    "input",
    "response",
    "mandatory_criteria",
    "expected_behavior",
    "gold_verdict",
    "gold_rationale",
    "module",
    "risk_domain",
    "severity",
    "language",
    "locale",
    "response_length",
    "response_style",
    "probe_type",
    "model_family_alias",
    "source_run_manifest_sha256",
    "gold_evidence_sha256",
    "review_method",
}
HASH = re.compile(r"^[a-f0-9]{64}$")


def _outside_repo(path: Path, repo: Path, label: str) -> Path:
    resolved = path.resolve()
    try:
        resolved.relative_to(repo.resolve())
    except ValueError:
        return resolved
    raise ProtocolError(f"restricted {label} must be outside the repository")


def _allocation(blueprint: dict[str, Any], dimension: str) -> dict[str, int]:
    rows = (blueprint.get("allocations") or {}).get(dimension)
    if not isinstance(rows, list):
        raise ProtocolError(f"qualification blueprint is missing allocation {dimension}")
    result: dict[str, int] = {}
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("id"), str) or not isinstance(row.get("target"), int):
            raise ProtocolError(f"qualification blueprint has invalid allocation {dimension}")
        result[str(row["id"])] = int(row["target"])
    return result


def _validate(items: tuple[dict[str, Any], ...], blueprint: dict[str, Any]) -> None:
    target = blueprint.get("target_unique_responses")
    if not isinstance(target, int) or len(items) != target:
        raise ProtocolError(f"calibration corpus requires exactly {target} unique responses; got {len(items)}")
    ids: set[str] = set()
    hashes = ("source_run_manifest_sha256", "gold_evidence_sha256")
    for index, item in enumerate(items, 1):
        missing = sorted(REQUIRED - set(item))
        if missing:
            raise ProtocolError(f"calibration item {index} missing fields: {missing}")
        item_id = item.get("item_id")
        if not isinstance(item_id, str) or not item_id or item_id in ids:
            raise ProtocolError(f"calibration item {index} has invalid or duplicate item_id")
        ids.add(item_id)
        if not isinstance(item.get("input"), str) or not item["input"].strip():
            raise ProtocolError(f"calibration item {item_id} requires text input")
        if not isinstance(item.get("response"), str) or not item["response"].strip():
            raise ProtocolError(f"calibration item {item_id} requires a recorded response")
        criteria = item.get("mandatory_criteria")
        if not isinstance(criteria, list) or not criteria or not all(isinstance(value, str) and value.strip() for value in criteria):
            raise ProtocolError(f"calibration item {item_id} requires mandatory criteria")
        if item.get("gold_verdict") not in {"pass", "fail"}:
            raise ProtocolError(f"calibration item {item_id} gold verdict must be pass or fail")
        if not isinstance(item.get("gold_rationale"), str) or not item["gold_rationale"].strip():
            raise ProtocolError(f"calibration item {item_id} requires a gold rationale")
        if not isinstance(item.get("review_method"), str) or not item["review_method"].strip():
            raise ProtocolError(f"calibration item {item_id} requires an independent review method")
        if any(not isinstance(item.get(field), str) or not HASH.fullmatch(str(item[field])) for field in hashes):
            raise ProtocolError(f"calibration item {item_id} requires valid evidence hashes")

    dimensions = ("language", "severity", "response_length", "response_style", "probe_type")
    for dimension in dimensions:
        actual = Counter(str(item.get(dimension)) for item in items)
        expected = _allocation(blueprint, dimension)
        if dict(actual) != expected:
            raise ProtocolError(f"calibration {dimension} allocation mismatch: expected {expected}, got {dict(actual)}")

    modules = blueprint.get("modules")
    if not isinstance(modules, list):
        raise ProtocolError("qualification blueprint requires modules")
    expected_modules = {str(row["id"]): row for row in modules if isinstance(row, dict) and isinstance(row.get("id"), str)}
    actual_modules = Counter(str(item.get("module")) for item in items)
    if actual_modules != Counter({module: int(row["target"]) for module, row in expected_modules.items()}):
        raise ProtocolError("calibration module allocation mismatch")
    for module, row in expected_modules.items():
        selected = [item for item in items if item["module"] == module]
        verdicts = Counter(str(item["gold_verdict"]) for item in selected)
        expected = {"pass": int(row["pass_target"]), "fail": int(row["fail_target"])}
        if dict(verdicts) != expected:
            raise ProtocolError(f"calibration module {module} verdict allocation mismatch")
    aliases = {str(item.get("model_family_alias")) for item in items}
    minimum_families = int(blueprint.get("minimum_model_families", 0))
    if "" in aliases or len(aliases) < minimum_families:
        raise ProtocolError(f"calibration corpus requires at least {minimum_families} non-empty model-family aliases")


def assemble(
    source_suite_path: Path,
    items_path: Path,
    blueprint_path: Path,
    output: Path,
    *,
    corpus_version: str,
    frozen_at: str,
) -> dict[str, Any]:
    repo = Path(__file__).resolve().parents[1]
    items_path = _outside_repo(items_path, repo, "calibration input")
    output = _outside_repo(output, repo, "calibration output")
    if output.exists():
        raise ProtocolError(f"calibration output already exists: {output}")
    if not re.fullmatch(r"\d+\.\d+\.\d+", corpus_version):
        raise ProtocolError("corpus version must be semantic x.y.z")
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:Z|[+-]\d{2}:\d{2})", frozen_at):
        raise ProtocolError("frozen-at must be an ISO-8601 timestamp with timezone")
    source_suite = load_suite(source_suite_path)
    if blueprint_path.is_symlink() or not blueprint_path.is_file():
        raise ProtocolError("qualification blueprint must be a regular file")
    try:
        blueprint_raw = blueprint_path.read_bytes()
        blueprint = tomllib.loads(blueprint_raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ProtocolError(f"cannot load qualification blueprint: {exc}") from exc
    blueprint_errors = validate_judge_qualification_blueprint(blueprint_path, source_suite, raw=blueprint_raw)
    if blueprint_errors:
        raise ProtocolError("invalid qualification blueprint:\n" + "\n".join(blueprint_errors))
    blueprint_sha = sha256_bytes(blueprint_raw)
    judge = source_suite.config.get("judge")
    if (
        not isinstance(judge, dict)
        or judge.get("qualification_blueprint_sha256") != blueprint_sha
    ):
        raise ProtocolError("qualification blueprint does not match the source suite pin")
    items = _read_jsonl(items_path)
    _validate(items, blueprint)

    output.mkdir(parents=True)
    dataset_path = output / "dataset.jsonl"
    responses_path = output / "recorded-responses.jsonl"
    atomic_text(dataset_path, "")
    atomic_text(responses_path, "")
    for item in items:
        source = {
            "origin": "restricted human-gold judge calibration corpus",
            "source_case_id": item["source_case_id"],
            "source_run_manifest_sha256": item["source_run_manifest_sha256"],
            "gold_evidence_sha256": item["gold_evidence_sha256"],
            "model_family_alias": item["model_family_alias"],
        }
        case = {
            "id": item["item_id"],
            "input": item["input"],
            "category": item["module"],
            "module": item["module"],
            "risk_domain": item["risk_domain"],
            "severity": item["severity"],
            "language": item["language"],
            "locale": item["locale"],
            "split": "calibration",
            "tags": ["judge-calibration", str(item["probe_type"])],
            "expected_behavior": item["expected_behavior"],
            "expected_behavior_reason": item["gold_rationale"],
            "mandatory_criteria": item["mandatory_criteria"],
            "judge_gold_verdict": item["gold_verdict"],
            "response_length": item["response_length"],
            "response_style": item["response_style"],
            "probe_type": item["probe_type"],
            "model_family_alias": item["model_family_alias"],
            "source": source,
            "review": {"status": "approved", "method": item["review_method"]},
        }
        append_jsonl(dataset_path, case)
        append_jsonl(
            responses_path,
            {"case_id": item["item_id"], "response": {"answer": item["response"], "model": "recorded-human-gold"}},
        )
    atomic_text(output / "rubric.md", source_suite.rubric)
    dataset_sha = sha256_file(dataset_path)
    responses_sha = sha256_file(responses_path)
    rubric_sha = sha256_file(output / "rubric.md")
    quote = json.dumps
    gates_toml = "\n".join(
        f'''[[gates]]
category = {quote(gate["category"])}
metric = {quote(gate.get("metric", "pass_rate_ci.lower"))}
min = {quote(gate["min"])}
'''
        for gate in source_suite.config.get("gates", [])
    )
    suite_toml = f'''protocol_version = "1.0.0"
name = "cavada-core-judge-qualification-v1"
version = {quote(corpus_version)}
status = "candidate"
description = "Restricted human-gold qualification corpus for a fixed judge configuration."
profile = "text-generation"
dataset = "dataset.jsonl"
rubric = "rubric.md"
data_classification = "restricted"
dataset_sha256 = {quote(dataset_sha)}
rubric_sha256 = {quote(rubric_sha)}
temperature = 0
max_tokens = 1024

{gates_toml}
[judge]
qualification_blueprint = "qualification-blueprint.toml"
qualification_blueprint_sha256 = {quote(blueprint_sha)}

[governance]
owner = "CavadaLabs evaluation maintainers"
purpose = "Qualify one exact judge identity and configuration"
intended_use = "Restricted judge qualification under the named blueprint"
prohibited_use = "Target-model ranking, public data release, legal compliance, or universal judge claims"
license = "Restricted corpus; rights evidence is linked per item"
origin = "Independently reviewed recorded responses assembled at {frozen_at}"
created_at = {quote(frozen_at[:10])}
retention = "Restricted retention policy applies"
personal_data = "Must be declared and approved in the external corpus evidence"
legal_basis_reference = "See restricted corpus evidence"
rotation_due = "2027-02-05"
contamination_status = "Recorded responses are isolated from the judge until execution"
canary_strategy = "Not applicable to judge response qualification"
known_leaks = "The qualification corpus must remain restricted"
representativeness = "Blueprint-balanced judge qualification responses only"
transfer_restrictions = "Do not send outside authorized judge destinations"
near_duplicate_threshold = 0.99
semantic_duplicate_threshold = 1.0
minimum_category_cases = 1
maximum_category_share = 1.0

[target]
kind = "recorded"
responses = "recorded-responses.jsonl"
responses_sha256 = {quote(responses_sha)}
response_field = "answer"
reported_model_field = "model"

[statistics]
confidence = 0.95
bootstrap_samples = 10000
seed = 20260805
'''
    atomic_text(output / "suite.toml", suite_toml)
    atomic_text(output / "qualification-blueprint.toml", blueprint_raw.decode("utf-8"))
    manifest = {
        "corpus_version": corpus_version,
        "frozen_at": frozen_at,
        "blueprint_version": blueprint.get("version"),
        "blueprint_sha256": blueprint_sha,
        "source_suite": f"{source_suite.name}@{source_suite.version}",
        "source_dataset_sha256": sha256_file(source_suite.dataset_path),
        "source_rubric_sha256": sha256_file(source_suite.rubric_path),
        "items_source_sha256": sha256_file(items_path),
        "dataset_sha256": dataset_sha,
        "recorded_responses_sha256": responses_sha,
        "rubric_sha256": rubric_sha,
        "items": len(items),
        "model_family_aliases": sorted({str(item["model_family_alias"]) for item in items}),
        "gold_evidence_sha256": sorted({str(item["gold_evidence_sha256"]) for item in items}),
        "identity_blinded_to_judge": True,
        "independent_gold_required": True,
    }
    atomic_json(output / "corpus_manifest.json", manifest)
    load_suite(output)
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("source_suite", type=Path)
    parser.add_argument("items", type=Path)
    parser.add_argument("blueprint", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--corpus-version", required=True)
    parser.add_argument("--frozen-at", required=True)
    args = parser.parse_args()
    print(
        json.dumps(
            assemble(
                args.source_suite,
                args.items,
                args.blueprint,
                args.output,
                corpus_version=args.corpus_version,
                frozen_at=args.frozen_at,
            ),
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
