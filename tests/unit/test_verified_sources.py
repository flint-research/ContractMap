"""Verified-source lookup, parsing and the path from it to resolved access control.

The payloads here are trimmed copies of real Sourcify v2 responses, including the
dict-shaped ``sources`` field, so the parser is exercised against the shape the
service actually returns rather than one invented for the test.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from contractmap.config import Settings
from contractmap.models import AccessRestriction, SourceKind
from contractmap.scanner import remote
from contractmap.scanner.remote import Entity, ScanContext, _facts_for
from contractmap.sources.solc import find_solc
from contractmap.sources.verified import VerifiedSource, _parse_sourcify

SOURCIFY_SOURCE = """// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

abstract contract Base {
    address public owner;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function transferOwnership(address newOwner) external onlyOwner {
        owner = newOwner;
    }
}

contract Guarded is Base {
    function open() external payable {}

    function restricted() external onlyOwner {}
}
"""


def _payload(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "match": "exact_match",
        "chainId": "1",
        "address": "0x" + "ab" * 20,
        "abi": [
            {
                "type": "function",
                "name": "open",
                "inputs": [],
                "outputs": [],
                "stateMutability": "payable",
            },
        ],
        "compilation": {
            "language": "Solidity",
            "compiler": "solc",
            "compilerVersion": "0.8.24+commit.e11b9ed9",
            "name": "Guarded",
            "fullyQualifiedName": "Guarded.sol:Guarded",
        },
        "metadata": {"settings": {"compilationTarget": {"Guarded.sol": "Guarded"}}},
        "sources": {"Guarded.sol": {"content": SOURCIFY_SOURCE}},
    }
    payload.update(overrides)
    return payload


def test_parses_dict_shaped_sources() -> None:
    parsed = _parse_sourcify(_payload(), "0x" + "ab" * 20, 1)
    assert parsed is not None
    assert parsed.contract_name == "Guarded"
    assert parsed.compiler_version == "0.8.24+commit.e11b9ed9"
    assert list(parsed.source_files) == ["Guarded.sol"]
    assert parsed.primary_source == SOURCIFY_SOURCE


def test_contract_name_falls_back_to_metadata_target() -> None:
    parsed = _parse_sourcify(
        _payload(compilation={"compilerVersion": "0.8.24"}), "0x" + "ab" * 20, 1
    )
    assert parsed is not None
    assert parsed.contract_name == "Guarded"


def test_abi_string_and_plain_source_entries_are_accepted() -> None:
    payload = _payload(abi='[{"type": "function", "name": "open"}]')
    payload["sources"] = {"Guarded.sol": SOURCIFY_SOURCE}
    parsed = _parse_sourcify(payload, "0x" + "ab" * 20, 1)
    assert parsed is not None
    assert len(parsed.abi) == 1
    assert parsed.source_files["Guarded.sol"] == SOURCIFY_SOURCE


def test_non_object_payload_is_rejected() -> None:
    assert _parse_sourcify(["not", "an", "object"], "0x" + "ab" * 20, 1) is None


class FakeClient:
    """Only ``get_code`` is reachable from the facts path under test."""

    async def get_code(self, address: str, block: int | None = None) -> str:
        return "0x" + "60" * 40


def _context(*, allow_build: bool, solc: Path | None) -> ScanContext:
    return ScanContext(
        client=FakeClient(),  # type: ignore[arg-type]
        settings=Settings(allow_build=allow_build, solc_path=str(solc) if solc else None),
        builder=remote.GraphBuilder(),
        chain_id=1,
        block=100,
    )


@pytest.fixture
def verified_entity() -> Entity:
    address = "0x" + "ab" * 20
    return Entity(
        address=address,
        depth=0,
        code="0x" + "60" * 40,
        verified=VerifiedSource(
            provider="sourcify",
            address=address,
            abi=[{"type": "function", "name": "open", "inputs": [], "outputs": []}],
            source_files={"Guarded.sol": SOURCIFY_SOURCE},
            contract_name="Guarded",
            compiler_version="0.8.24",
        ),
    )


def test_source_scan_without_build_permission_degrades_to_abi(
    verified_entity: Entity,
) -> None:
    context = _context(allow_build=False, solc=None)
    facts = _facts_for(context, verified_entity)
    assert [fact.name for fact in facts] == ["open"]
    assert all(fact.access_kind == "unresolved" for fact in facts)
    assert any(item.code == "source_analysis_skipped" for item in context.builder.warnings)


def test_missing_compiler_is_a_warning_not_a_failure(
    verified_entity: Entity, tmp_path: Path
) -> None:
    missing = tmp_path / "definitely-not-solc"
    context = _context(allow_build=True, solc=missing)
    facts = _facts_for(context, verified_entity)
    assert [fact.name for fact in facts] == ["open"]
    assert any(item.code == "source_analysis_skipped" for item in context.builder.warnings)


@pytest.mark.skipif(find_solc() is None, reason="needs a solc binary to compile the source")
def test_compiling_verified_source_resolves_the_modifier_guard(
    verified_entity: Entity,
) -> None:
    context = _context(allow_build=True, solc=None)
    facts = _facts_for(context, verified_entity)
    by_name = {fact.name: fact for fact in facts}
    assert by_name["open"].access_kind == "none_identified"
    assert by_name["restricted"].access_kind == "confirmed"
    # Declared in the base, callable on the deployed contract, guarded by the base.
    inherited = by_name["transferOwnership"]
    assert (inherited.declared_in, inherited.access_kind, inherited.writes) == (
        "Base",
        "confirmed",
        ["owner"],
    )
    assert not [item for item in context.builder.warnings if item.code == "source_analysis_failed"]


class _Unit:
    def __init__(self, name: str) -> None:
        self.contract_name = name


def test_units_are_selected_by_verified_contract_name() -> None:
    verified = VerifiedSource(provider="sourcify", address="0x0", contract_name="Guarded")
    selected = remote._select_unit([_Unit("Other"), _Unit("Guarded")], verified)  # type: ignore[arg-type]
    assert selected is not None
    assert selected.contract_name == "Guarded"  # type: ignore[attr-defined]


def test_falls_back_to_first_unit_when_name_is_unavailable() -> None:
    verified = VerifiedSource(provider="sourcify", address="0x0")
    selected = remote._select_unit([_Unit("Only")], verified)  # type: ignore[arg-type]
    assert selected is not None
    assert selected.contract_name == "Only"  # type: ignore[attr-defined]


def test_unverified_contract_is_not_marked_as_verified_source() -> None:
    assert SourceKind.DEPLOYED_BYTECODE is not SourceKind.VERIFIED_SOURCE
    assert AccessRestriction.UNRESOLVED.value == "unresolved"
