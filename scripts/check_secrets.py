#!/usr/bin/env python3
"""Fail when tracked source contains a credential-shaped value."""

from __future__ import annotations

import argparse
import shutil
import subprocess
from pathlib import Path

from cavada_eval.protocol import SECRET_PATTERNS

MAX_FILE_BYTES = 5 * 1024 * 1024


def tracked_files(root: Path) -> list[Path]:
    git = shutil.which("git")
    if not git:
        raise RuntimeError("git is required")
    result = subprocess.run(  # noqa: S603 -- fixed arguments and a resolved local executable.
        [git, "ls-files", "-co", "--exclude-standard", "-z"],
        cwd=root,
        check=True,
        capture_output=True,
    )
    return [root / item.decode() for item in result.stdout.split(b"\0") if item]


def scan(root: Path) -> list[str]:
    failures: list[str] = []
    for path in tracked_files(root):
        if not path.is_file() or path.stat().st_size > MAX_FILE_BYTES or any(part in {".git", ".venv", "runs", "dist"} for part in path.parts):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for number, line in enumerate(text.splitlines(), 1):
            if "secret-scan: allow" in line:
                continue
            if any(pattern.search(line) for pattern in SECRET_PATTERNS):
                failures.append(f"{path.relative_to(root)}:{number}")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path.cwd())
    args = parser.parse_args()
    failures = scan(args.root.resolve())
    if failures:
        print("Credential-shaped values found:\n" + "\n".join(failures))
        return 1
    print("Secret scan passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
