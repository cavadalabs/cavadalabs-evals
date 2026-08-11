#!/usr/bin/env python3
"""Verify that built archives are runnable and contain no private artifacts."""

from __future__ import annotations

import tarfile
import zipfile
from pathlib import Path, PurePosixPath

REQUIRED_WHEEL = {
    "cavada_eval/py.typed",
    "cavada_eval/_resources/PROTOCOL.md",
    "cavada_eval/_resources/PERFORMANCE_PROTOCOL.md",
    "cavada_eval/_resources/PERFORMANCE_PROTOCOL_V1_0.md",
    "cavada_eval/_resources/PERFORMANCE_PROTOCOL_V2.md",
    "cavada_eval/_resources/IMPLEMENTATION_CHECKLIST.md",
    "cavada_eval/_resources/OFFICIAL_EVALUATION_PROGRAM.md",
    "cavada_eval/_resources/SECURITY.md",
    "cavada_eval/_resources/docs/COMPLIANCE.md",
    "cavada_eval/_resources/docs/THREAT_MODEL.md",
    "cavada_eval/_resources/.github/workflows/ci.yml",
    "cavada_eval/_resources/program/registry.toml",
    "cavada_eval/_resources/schemas/manifest.schema.json",
    "cavada_eval/_resources/schemas/performance-plan-2.0.0.schema.json",
    "cavada_eval/_resources/schemas/performance-manifest-2.0.0.schema.json",
    "cavada_eval/_resources/schemas/performance-publication-2.0.0.schema.json",
    "cavada_eval/_resources/schemas/results-registry-2.0.0.schema.json",
    "cavada_eval/_resources/suites/cavada-core-assistant-text-v1/suite.toml",
    "cavada_eval/_resources/suites/security-privacy-smoke-v1/suite.toml",
    "cavada_eval/_resources/suites/template/suite.toml",
    "cavada_eval/_resources/performance/plans/llm-serving-quick-v1.toml",
    "cavada_eval/_resources/performance/plans/llm-serving-v2.toml",
    "cavada_eval/_resources/performance/VERSION_PROVENANCE.md",
    "cavada_eval/_resources/performance/workloads/llm-serving-synthetic-v2.jsonl",
}
REQUIRED_SDIST_SUFFIXES = {
    "/PROTOCOL.md",
    "/PERFORMANCE_PROTOCOL.md",
    "/PERFORMANCE_PROTOCOL_V1_0.md",
    "/PERFORMANCE_PROTOCOL_V2.md",
    "/IMPLEMENTATION_CHECKLIST.md",
    "/OFFICIAL_EVALUATION_PROGRAM.md",
    "/SECURITY.md",
    "/docs/COMPLIANCE.md",
    "/docs/THREAT_MODEL.md",
    "/.github/workflows/ci.yml",
    "/uv.lock",
    "/program/registry.toml",
    "/schemas/manifest.schema.json",
    "/schemas/performance-plan-2.0.0.schema.json",
    "/schemas/performance-manifest-2.0.0.schema.json",
    "/schemas/performance-publication-2.0.0.schema.json",
    "/schemas/results-registry-2.0.0.schema.json",
    "/suites/cavada-core-assistant-text-v1/suite.toml",
    "/suites/security-privacy-smoke-v1/suite.toml",
    "/suites/template/suite.toml",
    "/performance/plans/llm-serving-quick-v1.toml",
    "/performance/plans/llm-serving-v2.toml",
    "/performance/VERSION_PROVENANCE.md",
    "/performance/workloads/llm-serving-synthetic-v2.jsonl",
    "/src/cavada_eval/py.typed",
}
FORBIDDEN_PARTS = {".codex-internal", ".git", "runs", "tmp"}


def _check(names: set[str], required: set[str], *, exact: bool) -> None:
    private = sorted(name for name in names if FORBIDDEN_PARTS.intersection(PurePosixPath(name).parts))
    missing = sorted(item for item in required if item not in names) if exact else sorted(item for item in required if not any(name.endswith(item) for name in names))
    if private or missing:
        raise SystemExit(f"distribution check failed: private={private}, missing={missing}")


def main() -> int:
    dist = Path("dist")
    wheels = sorted(dist.glob("*.whl"))
    sdists = sorted(dist.glob("*.tar.gz"))
    if len(wheels) != 1 or len(sdists) != 1:
        raise SystemExit("distribution check requires exactly one wheel and one source archive")
    with zipfile.ZipFile(wheels[0]) as archive:
        names = set(archive.namelist())
        _check(names, REQUIRED_WHEEL, exact=True)
        unexpected = sorted(
            name
            for name in names
            if name == "cavada_eval/_resources/uv.lock"
            or (
                name.startswith("cavada_eval/_resources/suites/")
                and not any(
                    name.startswith(f"cavada_eval/_resources/suites/{suite}/")
                    for suite in ("cavada-core-assistant-text-v1", "security-privacy-smoke-v1", "template")
                )
            )
        )
        if unexpected:
            raise SystemExit(f"distribution check failed: unexpected wheel resources={unexpected}")
    with tarfile.open(sdists[0]) as archive:
        _check(set(archive.getnames()), REQUIRED_SDIST_SUFFIXES, exact=False)
    print("Distribution contents passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
