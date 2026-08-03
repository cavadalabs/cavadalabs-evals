#!/usr/bin/env python3
"""Generate local build provenance; release signing remains external."""

from __future__ import annotations

import argparse
import json
import platform
import shutil
import subprocess
import tomllib
from datetime import datetime, timezone
from pathlib import Path

from cavada_eval.protocol import sha256_file


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dist", type=Path, default=Path("dist"))
    parser.add_argument("--output", type=Path, default=Path("dist/build-provenance.json"))
    args = parser.parse_args()
    git = shutil.which("git")
    commit = ""
    if git:
        result = subprocess.run(  # noqa: S603 -- fixed arguments and resolved executable.
            [git, "rev-parse", "HEAD"], check=False, capture_output=True, text=True, timeout=10
        )
        commit = result.stdout.strip() if result.returncode == 0 else ""
    output = args.output.resolve()
    with Path("pyproject.toml").open("rb") as handle:
        project = tomllib.load(handle)["project"]
    version = str(project["version"])
    subjects = [
        {"name": path.name, "digest": {"sha256": sha256_file(path)}}
        for path in sorted(args.dist.resolve().glob("*"))
        if path.is_file() and path.resolve() != output and (version in path.name or path.name.startswith("sbom."))
    ]
    if not subjects:
        raise SystemExit("No current-version build artifacts found")
    provenance = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": subjects,
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "buildType": "https://cavadalabs.com/evals/uv-build/v1",
                "externalParameters": {"command": "uv build"},
                "resolvedDependencies": [{"uri": "uv.lock", "digest": {"sha256": sha256_file(Path("uv.lock"))}}],
            },
            "runDetails": {
                "builder": {"id": "local-or-ci-unsigned"},
                "metadata": {"invocationId": commit, "startedOn": datetime.now(timezone.utc).isoformat()},
                "environment": {"python": platform.python_version(), "platform": platform.platform()},
            },
        },
        "warning": "Unsigned local provenance. Release identity and trusted timestamp require external signing infrastructure.",
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(provenance, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
