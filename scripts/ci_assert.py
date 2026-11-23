"""Assertions CI runs against real CLI output.

Each check is a subcommand so the workflow can invoke it from bash or pwsh with
plain arguments — no heredocs, no shell quoting, identical code on every runner.

    python scripts/ci_assert.py html map.html
    python scripts/ci_assert.py grading source.json

Exits 0 when the assertion holds, 1 with a message when it does not.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

# The XML namespace is an identifier, not a fetch. Anything else is a network
# dependency, which would break the offline-viewer promise.
_ALLOWED_URLS = {"http://www.w3.org/2000/svg"}
_EXTERNAL_PATTERNS = (r'src="https?://', r'href="https?://', r"url\(https?://")

# Compiling is only useful if it changes a verdict. These entry points are guarded
# by `onlyOwner`, defined in a *base* contract, so they resolve to `confirmed` only
# when modifier facts are carried down the inheritance chain.
#
# Keyed by contract *and* signature: `pause()` exists on both `Roles` and `Vault`,
# and only `Vault`'s resolves, because `onlyRole` checks a mapping that cannot be
# read statically. Keying on the signature alone would silently pick one of them.
_EXPECTED_GRADING = {
    ("Vault", "setFee(uint256)"): "confirmed",
    ("Vault", "pause()"): "confirmed",
    ("Roles", "pause()"): "inferred",
}


def check_html(path: Path) -> list[str]:
    html = path.read_text(encoding="utf-8")
    urls = set(re.findall(r"https?://[^\"'\s>)]*", html)) - _ALLOWED_URLS
    problems = [f"references {url}" for url in sorted(urls)]
    problems += [
        f"has an external reference matching {pattern}"
        for pattern in _EXTERNAL_PATTERNS
        if re.search(pattern, html)
    ]
    if "<script" not in html:
        problems.append("has no inline script, so the viewer cannot work")
    return problems


def grading(payload: dict) -> dict[tuple[str, str], str]:
    names = {contract["id"]: contract["name"] for contract in payload["contracts"]}
    return {
        (names.get(function["contract_id"], "?"), function["signature"]): function["access"][
            "restriction"
        ]
        for function in payload["functions"]
    }


def check_grading(path: Path) -> list[str]:
    graded = grading(json.loads(path.read_text(encoding="utf-8")))
    for (contract, signature), restriction in sorted(graded.items()):
        print(f"{contract}.{signature}: {restriction}")

    problems: list[str] = []
    for (contract, signature), want in _EXPECTED_GRADING.items():
        got = graded.get((contract, signature))
        if got != want:
            problems.append(f"{contract}.{signature} resolved to {got!r}, expected {want!r}")
    return problems


CHECKS = {"html": check_html, "grading": check_grading}


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[0] not in CHECKS:
        print(f"usage: {Path(__file__).name} {{{'|'.join(CHECKS)}}} PATH", file=sys.stderr)
        return 2
    path = Path(argv[1])
    if not path.is_file():
        print(f"{path} does not exist", file=sys.stderr)
        return 1
    problems = CHECKS[argv[0]](path)
    if problems:
        for problem in problems:
            print(f"{path} {problem}", file=sys.stderr)
        return 1
    print(f"{argv[0]}: {path.name} is as expected")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
