from __future__ import annotations

import argparse
import json
import re
import unicodedata
from collections import Counter
from pathlib import Path
from typing import Any

from cavada_eval.protocol import (
    ProtocolError,
    Suite,
    _read_jsonl,
    content_text,
    load_suite,
    semantic_duplicate_candidates,
    sha256_file,
    validate_suite,
)

EVALUATOR_LANGUAGE = re.compile(
    r"\b(?:benchmark|evaluator|grader|grading|rubric|judge model|model evaluation|"
    r"evaluation (?:suite|benchmark|of (?:this|the) response)|valutatore|correttore|rubrica|"
    r"giudice automatico|valutazione (?:del modello|del benchmark|della risposta))\b",
    re.IGNORECASE,
)
GRADER_INFLUENCE = re.compile(
    r"\b(?:mark|label|rate|classify) (?:this |the )?(?:answer|response) (?:as )?(?:pass|correct)|"
    r"\b(?:assegna|classifica|valuta) (?:questa |la )?(?:risposta) (?:come )?(?:corretta|superata)",
    re.IGNORECASE,
)
DETERMINISTIC_FIELDS = {
    "expected_output",
    "expected_number",
    "expected_json_value",
    "required_terms",
    "forbidden_terms",
    "expected_regex",
    "expected_retrieval_ids",
    "expected_tool_calls",
}


def normalized(value: Any) -> str:
    return " ".join(re.findall(r"\w+", unicodedata.normalize("NFKC", str(value)).casefold()))


def quality_report(suite_path: Path, *, dataset: Path | None = None, suite_version: str | None = None) -> dict[str, Any]:
    suite = load_suite(suite_path)
    if dataset is not None:
        dataset_path = (suite.root / dataset).resolve() if not dataset.is_absolute() else dataset.resolve()
        try:
            relative = dataset_path.relative_to(suite.root)
        except ValueError as exc:
            raise ProtocolError("historical dataset must remain inside the suite") from exc
        if not dataset_path.is_file() or not suite_version:
            raise ProtocolError("historical dataset and suite version must both be valid")
        config = {**suite.config, "dataset": str(relative), "version": suite_version}
        suite = Suite(suite.root, config, _read_jsonl(dataset_path), suite.rubric, dataset_path, suite.rubric_path)
        errors = validate_suite(suite)
        if errors:
            raise ProtocolError("\n".join(errors))
    cases: list[dict[str, Any]] = []
    errors: list[str] = []
    review_flags = 0
    for case in suite.cases:
        case_id = str(case["id"])
        prompt = content_text(case.get("input"))
        criteria = case.get("mandatory_criteria")
        criteria_present = isinstance(criteria, list) and bool(criteria) and all(
            isinstance(item, str) and item.strip() for item in criteria
        )
        messages = case.get("messages")
        conversation_consistent = not messages or (
            isinstance(messages, list)
            and isinstance(messages[-1], dict)
            and messages[-1].get("role") == "user"
            and content_text(messages[-1].get("content")) == prompt
        )
        evaluator_language = bool(EVALUATOR_LANGUAGE.search(prompt))
        grader_influence = bool(GRADER_INFLUENCE.search(prompt))
        criteria_exposed = bool(criteria_present) and any(normalized(item) in normalized(prompt) for item in criteria)
        references = sorted(field for field in DETERMINISTIC_FIELDS if field in case)
        reference_exposed = False
        expected = case.get("expected_output")
        if isinstance(expected, str) and normalized(expected):
            reference_exposed = normalized(expected) in normalized(prompt)
        unintended_shortcut = reference_exposed and case.get("category") == "factuality"
        evidence = "deterministic-reference" if references else "behavioral-criteria"
        checks = {
            "nonempty_input": bool(prompt.strip()),
            "mandatory_criteria_present": criteria_present,
            "answerability_evidence": bool(references or criteria_present),
            "conversation_last_turn_matches_input": conversation_consistent,
            "no_evaluator_language": not evaluator_language,
            "no_grader_influence_request": not grader_influence,
            "criteria_not_verbatim_in_target_input": not criteria_exposed,
            "no_unintended_reference_shortcut": not unintended_shortcut,
        }
        failed = sorted(name for name, passed in checks.items() if not passed)
        errors.extend(f"{case_id}: {name}" for name in failed)
        flags = ["expected-reference-visible"] if reference_exposed else []
        review_flags += len(flags)
        cases.append(
            {
                "case_id": case_id,
                "module": case["category"],
                "language": case["language"],
                "split": case["split"],
                "solvability_evidence": evidence,
                "deterministic_reference_fields": references,
                "checks": checks,
                "review_flags": flags,
                "review_flag_disposition": (
                    "unresolved factuality shortcut"
                    if unintended_shortcut
                    else "intentional exact-output or transformation task"
                    if flags
                    else "none"
                ),
                "development_disposition": "author-reviewed; independent review required",
            }
        )
    duplicates = semantic_duplicate_candidates(suite)
    if duplicates:
        errors.append(f"token-containment duplicate candidates: {len(duplicates)}")
    neighbor_gaps: list[str] = []
    if tuple(int(part) for part in suite.version.split(".")) >= (0, 6, 0):
        groups: dict[str, list[dict[str, Any]]] = {}
        for case in suite.cases:
            groups.setdefault(str(case.get("scenario_group_id", "")), []).append(case)
        for case in suite.cases:
            if case["expected_behavior"] != "refuse":
                continue
            peers = groups.get(str(case.get("scenario_group_id", "")), [])
            if not any(peer.get("pair_role") == "benign" and peer.get("neighbor_of") == case["id"] for peer in peers):
                neighbor_gaps.append(str(case["id"]))
        errors.extend(f"{case_id}: missing benign refusal neighbor" for case_id in neighbor_gaps)
    summary = {
        "cases": len(cases),
        "automated_errors": len(errors),
        "manual_review_flags": review_flags,
        "token_containment_candidates": len(duplicates),
        "status": "pass-development-qa" if not errors else "fail-development-qa",
    }
    scenario_roles = Counter(str(case.get("scenario_role")) for case in suite.cases if case.get("scenario_role") is not None)
    if scenario_roles:
        summary["independent_scenarios"] = scenario_roles.get("primary", 0)
        summary["scenario_variants"] = scenario_roles.get("variant", 0)
        summary["scenario_groups"] = len({str(case.get("scenario_group_id")) for case in suite.cases})
    if tuple(int(part) for part in suite.version.split(".")) >= (0, 6, 0):
        summary["refusal_neighbor_gaps"] = len(neighbor_gaps)
    return {
        "report_version": "1.0.0",
        "suite": suite.name,
        "suite_version": suite.version,
        "dataset_sha256": sha256_file(suite.dataset_path),
        "review_scope": ["solvability", "scenario-independence", "leakage", "shortcuts", "grader-gaming", "evaluation-awareness"],
        "review_method": "deterministic per-case checks plus Codex-assisted author review of generated template families",
        "independence": "not-independent",
        "approval_effect": "development QA only; does not approve cases or satisfy independent review gates",
        "summary": summary,
        "errors": errors,
        "known_limits": [
            "Target-visible exact references can be intentional task content and require construct review.",
            "Lexical checks do not establish semantic uniqueness, absence of contamination, or deployment representativeness.",
            "The author review is not independent human, native-language, statistical, security, or legal approval.",
        ],
        "cases": cases,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("suite", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--dataset", type=Path)
    parser.add_argument("--suite-version")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if (args.dataset is None) != (args.suite_version is None):
        parser.error("--dataset and --suite-version must be used together")
    rendered = json.dumps(
        quality_report(args.suite, dataset=args.dataset, suite_version=args.suite_version),
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
    ) + "\n"
    if args.check:
        return 0 if args.output.is_file() and args.output.read_text(encoding="utf-8") == rendered else 1
    if args.output.exists():
        raise SystemExit(f"refusing to overwrite {args.output}")
    args.output.write_text(rendered, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
