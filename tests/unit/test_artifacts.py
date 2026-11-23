"""Artifact discovery: each build system's layout, and the single-file loader.

The loaders treat build output as untrusted, so malformed and oversized payloads
must be reported rather than crashing the scan.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from contractmap.errors import InputError
from contractmap.sources.artifacts import (
    detect_build_system,
    load_artifact_file,
    load_artifacts,
)

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
FOUNDRY = FIXTURES / "foundry"

ABI = [
    {
        "type": "function",
        "name": "poke",
        "inputs": [],
        "outputs": [],
        "stateMutability": "nonpayable",
    }
]


def _foundry_payload(name: str = "Thing") -> dict[str, object]:
    return {
        "abi": ABI,
        "contractName": name,
        "deployedBytecode": {"object": "0x6000"},
        "metadata": {
            "compiler": {"version": "0.8.24+commit.e11b9ed9"},
            "settings": {"compilationTarget": {"src/Thing.sol": name}},
        },
    }


def _hardhat_build_info_payload() -> dict[str, object]:
    return {
        "solcVersion": "0.8.24",
        "input": {"sources": {}},
        "output": {
            "sources": {"src/Thing.sol": {"ast": {"nodeType": "SourceUnit", "nodes": []}}},
            "contracts": {
                "src/Thing.sol": {
                    "Thing": {
                        "abi": ABI,
                        "evm": {"deployedBytecode": {"object": "0x6000"}},
                    }
                }
            },
        },
    }


def _combined_payload() -> dict[str, object]:
    # `solc --combined-json abi,bin` shape: the key is "path:Name".
    return {
        "version": "0.8.24+commit.e11b9ed9",
        "contracts": {
            "src/Thing.sol:Thing": {
                "abi": ABI,
                "bin": "6000",
            }
        },
    }


def _write(path: Path, payload: object) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_detects_foundry_from_the_output_directory(tmp_path: Path) -> None:
    (tmp_path / "out").mkdir()
    assert detect_build_system(tmp_path) == "foundry"


def test_detects_hardhat_from_its_config(tmp_path: Path) -> None:
    (tmp_path / "hardhat.config.ts").write_text("export default {}", encoding="utf-8")
    assert detect_build_system(tmp_path) == "hardhat"


def test_detects_nothing_in_an_empty_directory(tmp_path: Path) -> None:
    assert detect_build_system(tmp_path) is None


def test_single_foundry_artifact_file(tmp_path: Path) -> None:
    path = _write(tmp_path / "out" / "Thing.sol" / "Thing.json", _foundry_payload())
    artifacts = load_artifact_file(path)
    assert [a.contract_name for a in artifacts] == ["Thing"]
    assert artifacts[0].compiler_version == "0.8.24+commit.e11b9ed9"
    assert artifacts[0].build_system == "foundry"


def test_single_hardhat_build_info_file(tmp_path: Path) -> None:
    path = _write(tmp_path / "artifacts" / "build-info" / "x.json", _hardhat_build_info_payload())
    artifacts = load_artifact_file(path)
    assert [a.contract_name for a in artifacts] == ["Thing"]
    assert artifacts[0].ast is not None  # build-info carries the full AST


def test_single_solc_combined_json_file(tmp_path: Path) -> None:
    path = _write(tmp_path / "combined.json", _combined_payload())
    artifacts = load_artifact_file(path)
    assert [a.contract_name for a in artifacts] == ["Thing"]
    assert artifacts[0].build_system == "solc"


def test_unrecognised_json_is_rejected(tmp_path: Path) -> None:
    path = _write(tmp_path / "package.json", {"name": "not-an-artifact"})
    with pytest.raises(InputError, match="recognisable"):
        load_artifact_file(path)


def test_invalid_json_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "broken.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(InputError, match="valid JSON"):
        load_artifact_file(path)


def test_directory_scan_finds_the_fixture_contracts() -> None:
    artifacts, build_system = load_artifacts(FOUNDRY)
    assert build_system == "foundry"
    names = {artifact.contract_name for artifact in artifacts}
    assert names == {"IOracle", "Ownable", "Roles", "Upgradable", "Fees", "Vault"}


def test_directory_scan_ignores_duplicates() -> None:
    """The same contract appears in `out/` and in `out/build-info`; it is reported once."""

    artifacts, _ = load_artifacts(FOUNDRY)
    keys = [(artifact.contract_name, artifact.source_name) for artifact in artifacts]
    assert len(keys) == len(set(keys))


def test_artifact_without_abi_is_skipped(tmp_path: Path) -> None:
    _write(tmp_path / "out" / "Empty.sol" / "Empty.json", {"contractName": "Empty"})
    artifacts, _ = load_artifacts(tmp_path)
    assert artifacts == []
