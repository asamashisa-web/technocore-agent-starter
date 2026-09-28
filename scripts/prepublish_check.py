#!/usr/bin/env python3
"""Run local checks that must pass before this repository is made public."""

from __future__ import annotations

import compileall
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
PRIVATE_DIRECTORIES = {".git", ".secrets", ".state", "__pycache__"}
PRIVATE_KEY_HEADERS = tuple(
    "-----BEGIN " + label + "-----"
    for label in ("PRIVATE KEY", "ENCRYPTED PRIVATE KEY", "OPENSSH PRIVATE KEY")
)


def fail(message: str) -> None:
    print(f"FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def public_files() -> list[Path]:
    result: list[Path] = []
    for path in ROOT.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(ROOT)
        if any(part in PRIVATE_DIRECTORIES for part in relative.parts):
            continue
        result.append(path)
    return result


def check_git_exclusions() -> None:
    required = (".secrets/", ".state/")
    gitignore = (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
    for entry in required:
        if entry not in gitignore:
            fail(f"{entry} is missing from .gitignore")

    completed = subprocess.run(
        ["git", "ls-files", "--", ".secrets", ".state"],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode != 0:
        fail(f"git ls-files failed: {completed.stderr.strip()}")
    if completed.stdout.strip():
        fail("A private .secrets or .state file is tracked by Git")


def check_no_private_key_material() -> None:
    for path in public_files():
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for header in PRIVATE_KEY_HEADERS:
            if header in text:
                fail(f"Private-key material found in {path.relative_to(ROOT)}")


def main() -> None:
    if not compileall.compile_dir(ROOT, quiet=1):
        fail("Python compilation failed")
    tests = subprocess.run(
        [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"],
        cwd=ROOT,
        check=False,
    )
    if tests.returncode != 0:
        fail("Unit tests failed")
    check_git_exclusions()
    check_no_private_key_material()
    print("PASS: repository is ready for public review")


if __name__ == "__main__":
    main()
