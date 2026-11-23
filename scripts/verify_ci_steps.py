"""Verification helper: replay the CI steps locally against the fixtures.

Not collected by pytest (it lives outside ``tests/``); run it by hand:

    python scripts/verify_ci_steps.py

It runs the same commands as ``.github/workflows/ci.yml`` and then calls the same
assertions from ``scripts/ci_assert.py``, so a workflow edit that would break CI
fails here first. The compile step runs only when a compiler is discoverable, using
the same lookup the scanner uses.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from ci_assert import check_grading, check_html
from contractmap.sources.solc import find_solc

ROOT = Path(__file__).resolve().parents[1]
FOUNDRY = "tests/fixtures/foundry"
ARTIFACT = "tests/fixtures/foundry/out/Vault.sol/Vault.json"
PROJECT = "tests/fixtures/project"

failures: list[str] = []


def run(*args: str) -> int:
    print(f"$ contractmap {' '.join(args)}")
    completed = subprocess.run(
        [sys.executable, "-m", "contractmap", *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
        # The CLI switches its own streams to UTF-8 so its box-drawing tables render;
        # decode the same way, or Windows tries cp1252 and mangles the output.
        encoding="utf-8",
        errors="replace",
    )
    if completed.returncode != 0:
        print(completed.stdout[-2000:])
        print(completed.stderr[-2000:])
    return completed.returncode


def expect(label: str, args: list[str], want: int = 0) -> None:
    code = run(*args)
    status = "ok" if code == want else "FAIL"
    print(f"  {label}: exit {code} (expected {want}) -> {status}")
    if code != want:
        failures.append(f"{label}: exit {code}, expected {want}")


def check(label: str, problems: list[str]) -> None:
    print(f"  {label}: {'ok' if not problems else 'FAIL'}")
    for problem in problems:
        print(f"    {problem}")
    failures.extend(f"{label}: {problem}" for problem in problems)


def main() -> int:
    out = Path(tempfile.mkdtemp(prefix="contractmap-ci-"))
    foundry_json = out / "foundry.json"
    map_html = out / "map.html"
    try:
        expect(
            "scan artifacts",
            ["scan", FOUNDRY, "--format", "json", "--output", str(foundry_json)],
        )
        expect(
            "scan one artifact",
            ["scan", ARTIFACT, "--format", "json", "--output", str(out / "vault.json")],
        )
        expect("diff identical", ["diff", str(foundry_json), str(foundry_json)])
        expect("schema", ["schema", "--output", str(out / "schema.json")])
        expect("diff schema", ["schema", "--diff", "--output", str(out / "schema.diff.json")])
        expect("html", ["scan", FOUNDRY, "--format", "html", "--output", str(map_html)])
        check("offline viewer", check_html(map_html))

        # Use the same discovery the scanner uses, so this agrees with a real run:
        # solc may live in Foundry's svm store rather than on PATH.
        if find_solc() is None:
            print("  compile: skipped (no solc found)")
        else:
            source_json = out / "source.json"
            expect(
                "compile sources",
                [
                    "scan",
                    PROJECT,
                    "--allow-build",
                    "--format",
                    "json",
                    "--output",
                    str(source_json),
                ],
            )
            check("inherited guards", check_grading(source_json))
    finally:
        shutil.rmtree(out, ignore_errors=True)

    if failures:
        print("\nfailures:")
        for item in failures:
            print(f" - {item}")
        return 1
    print("\nall CI steps passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
