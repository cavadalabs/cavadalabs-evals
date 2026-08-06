from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate a deterministic CycloneDX-compatible component inventory.")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    components = [
        {
            "type": "library",
            "name": distribution.metadata["Name"],
            "version": distribution.version,
            "purl": f"pkg:pypi/{distribution.metadata['Name']}@{distribution.version}",
        }
        for distribution in importlib.metadata.distributions()
        if distribution.metadata.get("Name")
    ]
    components.sort(key=lambda item: (item["name"].casefold(), item["version"]))
    lock = Path("uv.lock")
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "component": {"type": "application", "name": "cavadalabs-evals"},
            "properties": [{"name": "cavadalabs:uv-lock-sha256", "value": hashlib.sha256(lock.read_bytes()).hexdigest() if lock.is_file() else "missing"}],
        },
        "components": components,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
