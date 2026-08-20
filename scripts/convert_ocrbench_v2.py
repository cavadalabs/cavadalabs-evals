#!/usr/bin/env python3
"""Convert official OCRBench v2 scored JSON to the external-import contract."""

from __future__ import annotations

import argparse
import json
import math
import re
from pathlib import Path
from typing import Any

UPSTREAM_COMMIT = "cbf4b64d2981dc5f9009df4bb7f5581f84381ad4"
SHA256 = re.compile(r"^[a-f0-9]{64}$")
TASKS = {
    "text recognition en",
    "fine-grained text recognition en",
    "full-page OCR en",
    "text grounding en",
    "VQA with position en",
    "text spotting en",
    "key information extraction en",
    "key information mapping en",
    "document parsing en",
    "chart parsing en",
    "table parsing en",
    "formula recognition en",
    "math QA en",
    "text counting en",
    "document classification en",
    "cognition VQA en",
    "diagram QA en",
    "reasoning VQA en",
    "science QA en",
    "APP agent en",
    "ASCII art classification en",
    "full-page OCR cn",
    "key information extraction cn",
    "handwritten answer extraction cn",
    "document parsing cn",
    "table parsing cn",
    "formula recognition cn",
    "cognition VQA cn",
    "reasoning VQA cn",
    "text translation cn",
}


def convert(source: Path, dataset_sha256: str, evaluator_sha256: str, invocation: str) -> dict[str, Any]:
    if not SHA256.fullmatch(dataset_sha256) or not SHA256.fullmatch(evaluator_sha256):
        raise ValueError("dataset and evaluator hashes must be lowercase SHA-256")
    if not invocation.strip():
        raise ValueError("the exact upstream invocation is required")
    try:
        items = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("input must be valid OCRBench v2 JSON") from exc
    if not isinstance(items, list) or not items:
        raise ValueError("input must be a non-empty JSON array")

    results: list[dict[str, Any]] = []
    case_ids: set[str] = set()
    for index, item in enumerate(items):
        if not isinstance(item, dict):
            raise ValueError(f"item {index} must be an object")
        raw_case_id = item.get("id")
        case_id = str(raw_case_id).strip() if isinstance(raw_case_id, (str, int)) and not isinstance(raw_case_id, bool) else ""
        task = item.get("type")
        score = item.get("score")
        if not case_id or case_id in case_ids:
            raise ValueError(f"item {index} has a missing or duplicate id")
        if task not in TASKS:
            raise ValueError(f"item {index} has an unsupported task type")
        if isinstance(score, bool) or not isinstance(score, (int, float)) or not math.isfinite(score) or not 0 <= score <= 1:
            raise ValueError(f"item {index} has a score outside [0, 1]")
        ignored = item.get("ignore")
        if ignored not in (None, "True"):
            raise ValueError(f"item {index} has an unsupported ignore marker")
        case_ids.add(case_id)
        results.append(
            {
                "case_id": case_id,
                "status": "skipped" if ignored == "True" else "scored",
                "score": float(score),
                "category": task,
                "language": "en" if task.endswith(" en") else "zh-CN" if task.endswith(" cn") else "und",
                "source_dataset": item["dataset_name"] if isinstance(item.get("dataset_name"), str) and item["dataset_name"].strip() else "unknown",
            }
        )

    return {
        "adapter_version": "1.0.0",
        "source": {
            "name": "OCRBench v2",
            "version": "2",
            "commit": UPSTREAM_COMMIT,
            "license": "upstream code: MIT; dataset: research-only/non-commercial",
            "dataset_sha256": dataset_sha256,
            "evaluator_sha256": evaluator_sha256,
            "invocation": invocation,
        },
        "suite": {
            "name": "ocrbench-v2-external",
            "modality": "image-to-text",
            "data_redistributed": False,
            "score_scale": [0, 1],
            "claim": "upstream evidence only; not CavadaLabs official certification",
        },
        "results": results,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="JSON produced by the pinned OCRBench v2 evaluator")
    parser.add_argument("output", type=Path, help="new external-import JSON path")
    parser.add_argument("--dataset-sha256", required=True)
    parser.add_argument("--evaluator-sha256", required=True)
    parser.add_argument("--invocation", required=True, help="exact command used for upstream evaluation")
    args = parser.parse_args()
    try:
        contract = convert(args.input, args.dataset_sha256, args.evaluator_sha256, args.invocation)
        with args.output.open("x", encoding="utf-8") as handle:
            json.dump(contract, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
    except (OSError, ValueError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()
