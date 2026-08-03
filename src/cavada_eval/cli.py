from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .protocol import ProtocolError, audit_suite, load_suite
from .runner import run


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="cavada-eval")
    commands = root.add_subparsers(dest="command", required=True)

    validate = commands.add_parser("validate", help="Validate suite schema and integrity")
    validate.add_argument("suite")
    validate.add_argument("--official", action="store_true")

    audit = commands.add_parser("audit", help="Print suite composition and hashes")
    audit.add_argument("suite")

    execute = commands.add_parser("run", help="Run an immutable benchmark")
    execute.add_argument("suite")
    execute.add_argument("--endpoint", required=True)
    execute.add_argument("--model-label", required=True)
    execute.add_argument("--expected-model", required=True)
    execute.add_argument("--model-revision", default="")
    execute.add_argument("--request-model")
    execute.add_argument("--judge-endpoint", required=True)
    execute.add_argument("--judge-model", required=True)
    execute.add_argument("--expected-judge-model")
    execute.add_argument("--judge-revision", default="")
    execute.add_argument("--target-key-env", default="TARGET_API_KEY")
    execute.add_argument("--judge-key-env", default="JUDGE_API_KEY")
    execute.add_argument("--repetitions", type=int, default=1)
    execute.add_argument("--judge-repetitions", type=int, default=1)
    execute.add_argument("--max-cases", type=int, default=0)
    execute.add_argument("--timeout", type=float, default=90)
    execute.add_argument("--official", action="store_true")
    execute.add_argument("--allow-external-judge", action="store_true")
    return root


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "validate":
            suite = load_suite(args.suite, official=args.official)
            print(json.dumps(audit_suite(suite), ensure_ascii=False, indent=2))
            return 0
        if args.command == "audit":
            print(json.dumps(audit_suite(load_suite(args.suite)), ensure_ascii=False, indent=2))
            return 0
        suite = load_suite(args.suite, official=args.official)
        repo_root = Path(__file__).resolve().parents[2]
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
            repetitions=args.repetitions,
            judge_repetitions=args.judge_repetitions,
            max_cases=args.max_cases,
            timeout=args.timeout,
            official=args.official,
            allow_external_judge=args.allow_external_judge,
        )
        manifest = json.loads((run_dir / "manifest.json").read_text())
        print(run_dir)
        return 0 if manifest["status"] == "passed" else 1
    except ProtocolError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
