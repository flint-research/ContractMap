"""Diff semantics: stable identity, real change detection, metadata exclusion."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from contractmap.config import Settings
from contractmap.diff import ChangeKind, DiffCategory, compare
from contractmap.exporters.json_export import load_json, to_json
from contractmap.scanner.local import scan_local

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
FOUNDRY = FIXTURES / "foundry"


@pytest.fixture(scope="module")
def analysis():
    return scan_local(FOUNDRY, Settings())


def test_identical_analyses_are_empty(analysis) -> None:
    changes = compare(analysis, analysis)
    assert changes.changes == []


def test_run_metadata_does_not_create_changes(analysis, tmp_path: Path) -> None:
    """A re-scan has a new timestamp and duration; neither is an architectural change."""

    second = scan_local(FOUNDRY, Settings())
    assert second.metadata.generated_at is not None
    assert compare(analysis, second).changes == []


def test_a_removed_contract_is_reported(analysis) -> None:
    trimmed = analysis.model_copy(deep=True)
    victim = trimmed.contracts.pop()
    trimmed.functions = [f for f in trimmed.functions if f.contract_id != victim.id]

    changes = compare(analysis, trimmed)
    removals = [c for c in changes.changes if c.kind is ChangeKind.REMOVED]
    assert any(c.category is DiffCategory.CONTRACT and c.label == victim.name for c in removals)


def test_a_changed_access_grade_is_reported(analysis) -> None:
    weakened = analysis.model_copy(deep=True)
    target = next(f for f in weakened.functions if f.signature == "setFee(uint256)")
    original = target.access.restriction
    target.access.restriction = type(original).UNRESOLVED

    changes = compare(analysis, weakened)
    assert any(c.category is DiffCategory.ACCESS for c in changes.changes)


def test_a_removed_function_is_reported(analysis) -> None:
    trimmed = analysis.model_copy(deep=True)
    victim = next(f for f in trimmed.functions if f.signature == "withdraw(uint256)")
    trimmed.functions = [f for f in trimmed.functions if f.id != victim.id]

    changes = compare(analysis, trimmed)
    assert any(
        c.kind is ChangeKind.REMOVED and c.category is DiffCategory.FUNCTION
        for c in changes.changes
    )


def test_added_observation_is_reported(analysis) -> None:
    noisy = analysis.model_copy(deep=True)
    extra = analysis.observations[0].model_copy(deep=True)
    extra.id = extra.id + ":extra"
    noisy.observations = [*noisy.observations, extra]

    changes = compare(analysis, noisy)
    assert any(c.category is DiffCategory.OBSERVATION for c in changes.changes)


def test_round_trips_through_json(analysis, tmp_path: Path) -> None:
    """`diff` reads files, so comparison must survive serialisation."""

    path = tmp_path / "analysis.json"
    path.write_text(to_json(analysis), encoding="utf-8")
    restored = load_json(path)
    assert compare(analysis, restored).changes == []

    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["schema_version"]
