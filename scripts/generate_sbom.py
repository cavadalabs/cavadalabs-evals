#!/usr/bin/env python3
"""Generate an SBOM from the distribution that will actually be published."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import zipfile
from email import policy
from email.parser import BytesParser
from pathlib import Path
from typing import Any

NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")
EXTRA = re.compile(r"\bextra\s*==\s*['\"]([^'\"]+)['\"]")


def generate(wheel: Path, lock: Path = Path("uv.lock")) -> dict[str, Any]:
    if not wheel.is_file() or wheel.suffix != ".whl":
        raise ValueError(f"wheel does not exist: {wheel}")
    with zipfile.ZipFile(wheel) as archive:
        names = [name for name in archive.namelist() if name.endswith(".dist-info/METADATA")]
        if len(names) != 1:
            raise ValueError("wheel must contain exactly one dist-info/METADATA file")
        metadata = BytesParser(policy=policy.default).parsebytes(archive.read(names[0]))
    project = metadata.get("Name")
    version = metadata.get("Version")
    if not project or not version:
        raise ValueError("wheel METADATA requires Name and Version")

    requirements = sorted(metadata.get_all("Requires-Dist", []), key=str.casefold)
    components = []
    dependency_refs = []
    for requirement in requirements:
        match = NAME.match(requirement)
        if match is None:
            raise ValueError(f"invalid Requires-Dist value: {requirement}")
        extra = EXTRA.search(requirement)
        reference = "urn:cavadalabs:requires-dist:" + hashlib.sha256(requirement.encode()).hexdigest()
        dependency_refs.append(reference)
        component: dict[str, Any] = {
            "type": "library",
            "bom-ref": reference,
            "name": match.group(1),
            "scope": "optional" if extra else "required",
            "properties": [{"name": "cavadalabs:requires-dist", "value": requirement}],
        }
        if extra:
            component["properties"].append({"name": "cavadalabs:extra", "value": extra.group(1)})
        components.append(component)

    normalized = project.casefold().replace("_", "-")
    project_ref = f"pkg:pypi/{normalized}@{version}"
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "component": {"type": "application", "bom-ref": project_ref, "name": project, "version": version, "purl": project_ref},
            "properties": [
                {"name": "cavadalabs:wheel", "value": wheel.name},
                {"name": "cavadalabs:wheel-sha256", "value": hashlib.sha256(wheel.read_bytes()).hexdigest()},
                {"name": "cavadalabs:uv-lock-sha256", "value": hashlib.sha256(lock.read_bytes()).hexdigest()},
            ],
        },
        "components": components,
        "dependencies": [{"ref": project_ref, "dependsOn": dependency_refs}],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate a deterministic CycloneDX SBOM from wheel METADATA.")
    parser.add_argument("--wheel", type=Path, required=True)
    parser.add_argument("--lock", type=Path, default=Path("uv.lock"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        document = generate(args.wheel, args.lock)
    except (OSError, ValueError, zipfile.BadZipFile) as exc:
        parser.error(str(exc))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
