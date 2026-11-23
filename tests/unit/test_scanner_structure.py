"""Structure the scanners must get right: inheritance, deduplication, single files.

These read the checked-in fixture projects, so they exercise the real artifact and
source paths rather than a hand-built model.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from contractmap.config import Settings
from contractmap.models import AccessRestriction, SourceKind
from contractmap.scanner.local import (
    declared_solc_version,
    discover_solidity,
    is_dependency,
    scan_local,
)
from contractmap.sources.solc import find_solc

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
FOUNDRY = FIXTURES / "foundry"
PROJECT = FIXTURES / "project"


@pytest.fixture(scope="module")
def artifact_result():
    return scan_local(FOUNDRY, Settings())


@pytest.fixture(scope="module")
def source_result():
    if find_solc() is None:
        pytest.skip("needs a solc binary to compile the source fixture")
    return scan_local(PROJECT, Settings(allow_build=True))


def test_base_contracts_come_from_the_ast(artifact_result) -> None:
    """solc reports inheritance through ``IdentifierPath.name``; reading only
    ``namePath`` silently produced zero inheritance edges."""
    bases = {contract.name: contract.base_contracts for contract in artifact_result.contracts}
    assert bases["Vault"] == ["Ownable"]
    assert bases["Upgradable"] == ["Ownable"]
    assert bases["Ownable"] == []


def test_inheritance_edges_exist(artifact_result) -> None:
    inherits = [edge for edge in artifact_result.edges if edge.kind.value == "inherits"]
    assert len(inherits) == 2


def test_a_source_scan_reports_each_contract_once(source_result) -> None:
    """Every contract in a file shares that file's AST, so analysing per compilation
    unit used to list each contract once per sibling."""
    names = [contract.name for contract in source_result.contracts]
    assert sorted(names) == sorted(set(names))
    assert sorted(names) == ["Fees", "IOracle", "Ownable", "Roles", "Upgradable", "Vault"]


def test_source_and_artifact_scans_agree_on_access(artifact_result, source_result) -> None:
    """The same contracts must grade identically whether they came from build output
    or were compiled from source. Divergence here means one path is guessing."""

    def grading(result) -> dict[tuple[str, str], AccessRestriction]:
        return {
            (contract.name, function.signature): function.access.restriction
            for contract in result.contracts
            for function in result.functions
            if function.contract_id == contract.id
        }

    assert grading(source_result) == grading(artifact_result)


def test_repeated_scans_agree_on_every_identifier() -> None:
    """`diff` is only useful if an unchanged target produces an unchanged document."""

    first = scan_local(FOUNDRY, Settings())
    second = scan_local(FOUNDRY, Settings())
    assert first.metadata.digest == second.metadata.digest
    assert [contract.id for contract in first.contracts] == [
        contract.id for contract in second.contracts
    ]
    assert [function.id for function in first.functions] == [
        function.id for function in second.functions
    ]


def test_observations_are_unique(source_result) -> None:
    ids = [item.id for item in source_result.observations]
    assert ids == sorted(set(ids))


def test_inherited_guard_resolves_to_confirmed(artifact_result) -> None:
    """``onlyOwner`` is defined in Ownable.sol, so a contract analyzed from its own
    compilation unit only resolves it if modifiers are carried down the chain."""
    by_signature = {item.signature: item for item in artifact_result.functions}
    set_fee = by_signature["setFee(uint256)"]
    assert set_fee.access.restriction is AccessRestriction.CONFIRMED

    pause = by_signature["pause()"]
    assert pause.access.restriction is AccessRestriction.CONFIRMED


def test_unguarded_function_stays_unrestricted(artifact_result) -> None:
    by_signature = {item.signature: item for item in artifact_result.functions}
    deposit = by_signature["deposit()"]
    assert deposit.access.restriction is AccessRestriction.NONE_IDENTIFIED


def test_single_file_scan_resolves_sibling_imports() -> None:
    if find_solc() is None:
        pytest.skip("needs a solc binary")
    result = scan_local(PROJECT / "src" / "Vault.sol", Settings(allow_build=True))
    names = {contract.name for contract in result.contracts}
    assert "Vault" in names
    assert "Ownable" in names


def test_single_artifact_file_scan() -> None:
    result = scan_local(FOUNDRY / "out" / "Vault.sol" / "Vault.json", Settings())
    assert [contract.name for contract in result.contracts] == ["Vault"]
    assert result.contracts[0].source_kind is SourceKind.COMPILED_SOURCE


def test_declared_version_prefers_foundry_config() -> None:
    config = (FOUNDRY / "foundry.toml").read_text(encoding="utf-8")
    assert "solc_version = '0.8.24'" in config
    assert declared_solc_version(FOUNDRY, {}) == "0.8.24"


def test_declared_version_ignores_ranges() -> None:
    sources = {"A.sol": "pragma solidity ^0.8.20;\ncontract A {}"}
    assert declared_solc_version(PROJECT / "src", sources) is None


def test_declared_version_reads_an_exact_pragma() -> None:
    sources = {"A.sol": "pragma solidity 0.8.19;\ncontract A {}"}
    assert declared_solc_version(PROJECT / "src", sources) == "0.8.19"


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("lib/forge-std/src/Test.sol", True),
        ("node_modules/@openzeppelin/contracts/access/Ownable.sol", True),
        ("@openzeppelin/contracts/access/Ownable.sol", True),
        ("test/Vault.t.sol", True),
        ("src/Deploy.s.sol", True),
        ("src/Vault.sol", False),
        ("contracts/lib/Math.sol", False),
    ],
)
def test_dependency_paths(source: str, expected: bool) -> None:
    assert is_dependency(source) is expected


def test_discovery_ignores_skip_names_above_the_root(tmp_path: Path) -> None:
    """A project living under a directory called `lib` or `out` must still be found."""

    root = tmp_path / "lib" / "project"
    (root / "src").mkdir(parents=True)
    (root / "src" / "A.sol").write_text("contract A {}", encoding="utf-8")
    (root / "lib" / "dep").mkdir(parents=True)
    (root / "lib" / "dep" / "B.sol").write_text("contract B {}", encoding="utf-8")
    assert [p.name for p in discover_solidity(root)] == ["A.sol"]


@pytest.mark.skipif(shutil.which("forge") is None, reason="needs forge")
def test_foundry_project_without_ast_is_rebuilt_with_forge(tmp_path: Path) -> None:
    """`forge build` leaves the AST out; --allow-build rebuilds into a temp directory."""

    shutil.copytree(PROJECT / "src", tmp_path / "src")
    (tmp_path / "foundry.toml").write_text(
        '[profile.default]\nsrc = "src"\nout = "out"\nlibs = []\n', encoding="utf-8"
    )
    result = scan_local(tmp_path, Settings(allow_build=True))
    vault = next(c for c in result.contracts if c.name == "Vault")
    guarded = [
        f
        for f in result.functions
        if f.contract_id == vault.id and f.access.restriction is AccessRestriction.CONFIRMED
    ]
    assert guarded
    assert not (tmp_path / "out").exists()


@pytest.mark.skipif(find_solc() is None, reason="needs a solc binary")
def test_common_guard_styles_are_recognised() -> None:
    """Each style below is a real caller check; reporting any as unguarded is wrong."""

    result = scan_local(FIXTURES / "guards", Settings(allow_build=True))
    grades = {f.name: f.access.restriction for f in result.functions if f.is_entry_point}
    for name in (
        "viaMsgSender",
        "viaOwnerCall",
        "viaMapping",
        "viaRevert",
        "viaAddressCast",
        "viaAuthModifier",
        "viaIfRevert",
        "viaAlias",
        "viaAuthCall",
    ):
        assert grades[name] is AccessRestriction.CONFIRMED, name
    # Writing to a caller-indexed mapping is bookkeeping, not a check.
    assert grades["registerOperator"] is AccessRestriction.NONE_IDENTIFIED
    assert grades["setFee"] is AccessRestriction.NONE_IDENTIFIED
    assert grades["grantIfMissing"] is AccessRestriction.NONE_IDENTIFIED


def test_unguarded_selfdestruct_is_reported(artifact_result) -> None:
    found = [
        o for o in artifact_result.observations if o.category == "unguarded_dangerous_operation"
    ]
    assert [e.detail for o in found for e in o.evidence] == ["destroy()"]


def test_library_calls_are_not_external_but_value_calls_are(artifact_result) -> None:
    """`amount.applyFee()` runs in place; `msg.sender.call{value: x}()` leaves the contract."""

    external = {f.name: f.calls_external for f in artifact_result.functions}
    assert external["feeOn"] is False
    assert external["withdraw"] is True


@pytest.fixture(scope="module")
def surface():
    if find_solc() is None:
        pytest.skip("needs a solc binary")
    result = scan_local(FIXTURES / "inheritance", Settings(allow_build=True))
    names = {c.id: c.name for c in result.contracts}
    return result, {(names[f.contract_id], f.name): f for f in result.functions}


def test_inherited_functions_belong_to_the_deployed_contract(surface) -> None:
    _, functions = surface
    upgrade = functions[("Safe", "upgradeTo")]
    assert upgrade.declared_in == "Upgradeable"
    assert functions[("Safe", "transferOwnership")].declared_in == "Owned"


def test_guard_in_an_overridden_hook_protects_the_caller(surface) -> None:
    _, functions = surface
    assert functions[("Safe", "upgradeTo")].access.restriction is AccessRestriction.CONFIRMED
    # The same function in a contract whose hook has no guard must not borrow one.
    assert functions[("Unsafe", "upgradeTo")].access.restriction is (
        AccessRestriction.NONE_IDENTIFIED
    )


def test_guard_in_an_internal_helper_protects_the_caller(surface) -> None:
    _, functions = surface
    assert functions[("Helper", "sweep")].access.restriction is AccessRestriction.CONFIRMED


def test_writes_follow_internal_and_super_calls(surface) -> None:
    _, functions = surface
    assert functions[("Helper", "claim")].writes == ["owner"]
    assert functions[("TwoStep", "transferOwnership")].writes == ["owner", "pendingOwner"]


def test_takeover_and_arbitrary_call_are_reported(surface) -> None:
    result, _ = surface
    names = {c.id: c.name for c in result.contracts}
    found = {
        (names[o.subject], o.category, e.detail)
        for o in result.observations
        for e in o.evidence
        if o.category in {"unguarded_privileged_write", "unguarded_dangerous_operation"}
    }
    assert found == {
        ("Helper", "unguarded_privileged_write", "claim(address)"),
        ("Helper", "unguarded_dangerous_operation", "run(address,bytes)"),
        ("Unsafe", "unguarded_privileged_write", "upgradeTo(address)"),
    }
    # Takeover paths are listed before context such as "performs external calls".
    first = [o.category for o in result.observations_by_priority()[:3]]
    assert first == [
        "unguarded_dangerous_operation",
        "unguarded_privileged_write",
        "unguarded_privileged_write",
    ]
