"""The CI assertion helpers are part of the contract, so they get tests too.

These guard the claims the README and `examples/README.md` make: the viewer is
offline, and `onlyOwner` resolves down the inheritance chain. If the helper itself
regressed, CI would pass while the docs were wrong, so both directions are checked:
a good artifact passes, and a deliberately broken one fails.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[2]
EXAMPLES = ROOT / "examples"


def _load(name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def ci_assert() -> ModuleType:
    return _load("ci_assert")


def test_a_self_contained_viewer_passes(ci_assert: ModuleType, tmp_path: Path) -> None:
    page = tmp_path / "map.html"
    page.write_text(
        '<svg xmlns="http://www.w3.org/2000/svg"><script>render()</script></svg>',
        encoding="utf-8",
    )
    assert ci_assert.check_html(page) == []


@pytest.mark.parametrize(
    "snippet",
    [
        '<script src="https://cdn.example.com/d3.js"></script>',
        '<link rel="stylesheet" href="http://cdn.example.com/app.css">',
        "<style>body{background:url(https://example.com/x.png)}</style>",
    ],
)
def test_any_external_reference_is_rejected(
    ci_assert: ModuleType, tmp_path: Path, snippet: str
) -> None:
    page = tmp_path / "map.html"
    page.write_text(f"<html><script>x()</script>{snippet}</html>", encoding="utf-8")
    assert ci_assert.check_html(page) != []


def test_a_viewer_without_its_script_is_rejected(ci_assert: ModuleType, tmp_path: Path) -> None:
    page = tmp_path / "map.html"
    page.write_text("<html><body>static</body></html>", encoding="utf-8")
    assert any("inline script" in problem for problem in ci_assert.check_html(page))


def test_the_checked_in_example_satisfies_the_grading_claim(ci_assert: ModuleType) -> None:
    assert ci_assert.check_grading(EXAMPLES / "foundry-analysis.json") == []


def test_a_downgraded_guard_is_caught(ci_assert: ModuleType, tmp_path: Path) -> None:
    payload = json.loads((EXAMPLES / "foundry-analysis.json").read_text(encoding="utf-8"))
    names = {contract["id"]: contract["name"] for contract in payload["contracts"]}
    for function in payload["functions"]:
        if (names[function["contract_id"]], function["signature"]) == ("Vault", "pause()"):
            function["access"]["restriction"] = "unresolved"
    broken = tmp_path / "broken.json"
    broken.write_text(json.dumps(payload), encoding="utf-8")
    problems = ci_assert.check_grading(broken)
    assert problems and "Vault.pause()" in problems[0]


def test_grading_is_keyed_by_contract_and_signature(ci_assert: ModuleType) -> None:
    """`pause()` exists on Roles and Vault with different verdicts; the key must
    keep them apart or one silently overwrites the other."""

    payload = json.loads((EXAMPLES / "foundry-analysis.json").read_text(encoding="utf-8"))
    graded = ci_assert.grading(payload)
    assert graded[("Vault", "pause()")] == "confirmed"
    assert graded[("Roles", "pause()")] == "inferred"


def test_the_cli_entry_point_exits_two_without_arguments(ci_assert: ModuleType) -> None:
    assert ci_assert.main([]) == 2
