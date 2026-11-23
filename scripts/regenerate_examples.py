"""Regenerate the checked-in example outputs.

The examples are committed so readers can see the JSON shape without installing
anything. They must come from the current code, so this script rebuilds both and
then verifies the claims `examples/README.md` makes about the result.

    python scripts/regenerate_examples.py
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples"
TARGET = "tests/fixtures/foundry"


def run(args: list[str], *, capture: bool = False) -> str:
    completed = subprocess.run(
        [sys.executable, "-m", "contractmap", *args],
        cwd=ROOT,
        capture_output=capture,
        text=True,
        # The CLI reconfigures its streams to UTF-8 because the terminal tables use
        # box-drawing characters; decode the same way or Windows reads cp1252.
        encoding="utf-8",
        errors="replace",
    )
    if completed.returncode != 0:
        raise SystemExit(f"contractmap {args[0]} failed: {completed.stderr or completed.stdout}")
    return completed.stdout


def main() -> int:
    EXAMPLES.mkdir(exist_ok=True)
    terminal = run(["scan", TARGET], capture=True)
    (EXAMPLES / "foundry-terminal.txt").write_text(terminal, encoding="utf-8", newline="\n")
    print(f"wrote examples/foundry-terminal.txt ({len(terminal)} chars)")

    run(
        [
            "scan",
            TARGET,
            "--format",
            "json",
            "--output",
            str(EXAMPLES / "foundry-analysis.json"),
            "--quiet",
        ]
    )
    payload = json.loads((EXAMPLES / "foundry-analysis.json").read_text(encoding="utf-8"))
    print(f"wrote examples/foundry-analysis.json (digest {payload['metadata']['digest']})")

    # These are the assertions examples/README.md makes; fail loudly if the code
    # stops producing them, rather than shipping a stale claim.
    names = {contract["id"]: contract["name"] for contract in payload["contracts"]}
    graded = {
        (names.get(f["contract_id"], "?"), f["signature"]): f["access"]["restriction"]
        for f in payload["functions"]
    }
    expected = {
        ("Vault", "setFee(uint256)"): "confirmed",
        ("Vault", "pause()"): "confirmed",
        ("Roles", "pause()"): "inferred",
    }
    wrong = {key: graded.get(key) for key, want in expected.items() if graded.get(key) != want}
    if wrong:
        raise SystemExit(f"examples/README.md is now wrong: {wrong}")
    print("verified the access gradings quoted in examples/README.md")

    if payload["target"]["resolved_paths"]:
        raise SystemExit("artifact scans should not record resolved_paths")

    ids = [contract["id"] for contract in payload["contracts"]]
    if ids != sorted(set(ids)):
        raise SystemExit("contract ids are not unique and sorted")

    print("regenerated and verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
