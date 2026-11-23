"""Discovery and loading of compiler artifacts from Foundry, Hardhat and solc output.

Artifacts are preferred over recompilation: they already contain the ABI and, for
Foundry and Hardhat, the AST and the source map needed for source-level analysis.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from contractmap.errors import InputError

MAX_ARTIFACT_BYTES = 16 * 1024 * 1024


@dataclass(slots=True)
class Artifact:
    path: Path
    contract_name: str
    source_name: str | None
    abi: list[dict[str, Any]]
    bytecode: str | None
    ast: dict[str, Any] | None
    storage_layout: list[dict[str, Any]]
    compiler_version: str | None
    build_system: str


def detect_build_system(root: Path) -> str | None:
    if (root / "foundry.toml").exists() or (root / "out").is_dir():
        return "foundry"
    if (root / "hardhat.config.ts").exists() or (root / "hardhat.config.js").exists():
        return "hardhat"
    if (root / "artifacts").is_dir() and (root / "package.json").exists():
        return "hardhat"
    if (root / "truffle-config.js").exists():
        return "truffle"
    return None


def _read_json(path: Path) -> dict[str, Any]:
    if path.stat().st_size > MAX_ARTIFACT_BYTES:
        raise InputError(f"artifact exceeds {MAX_ARTIFACT_BYTES} bytes: {path}")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise InputError(f"artifact is not valid JSON: {path}: {exc}") from exc


def _foundry_artifact(path: Path, build_system: str) -> Artifact | None:
    payload = _read_json(path)
    abi = payload.get("abi")
    if not isinstance(abi, list):
        return None
    metadata = payload.get("metadata", {}) if isinstance(payload.get("metadata"), dict) else {}
    compiler = None
    if isinstance(metadata.get("compiler"), dict):
        compiler = metadata["compiler"].get("version")
    target = metadata.get("settings", {}).get("compilationTarget", {})
    source_name = next(iter(target), None) if isinstance(target, dict) else None
    deployed = payload.get("deployedBytecode")
    runtime = deployed.get("object") if isinstance(deployed, dict) else None
    # Foundry writes the AST root of the compilation unit at the top level.
    ast = payload.get("ast")
    if not isinstance(ast, dict):
        output = metadata.get("output")
        ast = output.get("ast") if isinstance(output, dict) else None
    if source_name is None and isinstance(ast, dict):
        # Foundry writes extra artifacts (e.g. `out/interfaces/IERC20.sol/`) for
        # re-exported names without a compilation target; the AST still knows the file.
        source_name = ast.get("absolutePath")
    storage = payload.get("storageLayout")
    if not isinstance(storage, dict):
        storage = metadata.get("storageLayout")
    layout = storage.get("storage", []) if isinstance(storage, dict) else []
    return Artifact(
        path=path,
        contract_name=payload.get("contractName", path.stem),
        source_name=source_name,
        abi=abi,
        bytecode=runtime if isinstance(runtime, str) else None,
        ast=ast if isinstance(ast, dict) else None,
        storage_layout=layout if isinstance(layout, list) else [],
        compiler_version=compiler,
        build_system=build_system,
    )


def _hardhat_artifact(path: Path, build_system: str) -> Artifact | None:
    payload = _read_json(path)
    abi = payload.get("abi")
    if not isinstance(abi, list):
        return None
    compiler = payload.get("solcVersion") if isinstance(payload.get("solcVersion"), str) else None
    bytecode = payload.get("bytecode")
    return Artifact(
        path=path,
        contract_name=payload.get("contractName", path.stem),
        source_name=payload.get("sourceName"),
        abi=abi,
        bytecode=bytecode if isinstance(bytecode, str) else None,
        ast=None,
        storage_layout=[],
        compiler_version=compiler,
        build_system=build_system,
    )


def _solc_combined_artifact(path: Path) -> list[Artifact]:
    payload = _read_json(path)
    contracts = payload.get("contracts")
    if not isinstance(contracts, dict):
        return []
    results: list[Artifact] = []
    for source_name, entries in contracts.items():
        if not isinstance(entries, dict):
            continue
        # `solc --combined-json` keys are "path:Name" with the contract body directly;
        # `--standard-json` nests contracts under each source path.
        if ":" in str(source_name) and isinstance(entries.get("abi"), list):
            path_part, _, name_part = str(source_name).rpartition(":")
            results.extend(_combined_entry(path, path_part, name_part, entries))
            continue
        for contract_name, body in entries.items():
            if not isinstance(body, dict) or not isinstance(body.get("abi"), list):
                continue
            results.extend(_combined_entry(path, str(source_name), str(contract_name), body))
    return results


def _combined_entry(
    path: Path, source_name: str, contract_name: str, body: dict[str, Any]
) -> list[Artifact]:
    evm = body.get("evm", {})
    bytecode = (
        (evm.get("deployedBytecode", {}) or {}).get("object") if isinstance(evm, dict) else None
    )
    storage = (body.get("storageLayout", {}) or {}).get("storage", [])
    return [
        Artifact(
            path=path,
            contract_name=contract_name,
            source_name=source_name,
            abi=body["abi"],
            bytecode=bytecode if isinstance(bytecode, str) else None,
            ast=None,
            storage_layout=storage if isinstance(storage, list) else [],
            compiler_version=None,
            build_system="solc",
        )
    ]


def _hardhat_build_info(path: Path) -> list[Artifact]:
    """Hardhat keeps the full solc output (AST included) in ``artifacts/build-info``."""

    payload = _read_json(path)
    output = payload.get("output", {})
    if not isinstance(output, dict):
        return []
    sources = output.get("sources", {})
    compiler = payload.get("solcVersion") if isinstance(payload.get("solcVersion"), str) else None
    results: list[Artifact] = []
    for source_name, entries in output.get("contracts", {}).items():
        if not isinstance(entries, dict):
            continue
        ast = sources.get(source_name, {}).get("ast") if isinstance(sources, dict) else None
        for contract_name, body in entries.items():
            if not isinstance(body, dict) or not isinstance(body.get("abi"), list):
                continue
            evm = body.get("evm", {})
            bytecode = (
                (evm.get("deployedBytecode", {}) or {}).get("object")
                if isinstance(evm, dict)
                else None
            )
            storage = (body.get("storageLayout", {}) or {}).get("storage", [])
            results.append(
                Artifact(
                    path=path,
                    contract_name=contract_name,
                    source_name=source_name,
                    abi=body["abi"],
                    bytecode=bytecode,
                    ast=ast if isinstance(ast, dict) else None,
                    storage_layout=storage if isinstance(storage, list) else [],
                    compiler_version=compiler,
                    build_system="hardhat",
                )
            )
    return results


def load_artifact_file(path: Path) -> list[Artifact]:
    """Load one artifact file, recognising each layout by its own keys.

    Build systems do not label their output, so the payload shape decides: a
    Hardhat build-info carries ``output``, a solc ``--combined-json`` dump carries
    ``contracts``, a Foundry artifact carries ``deployedBytecode``.
    """

    payload = _read_json(path)
    build_system = detect_build_system(path.parent) or "solc"
    if isinstance(payload.get("output"), dict):
        return _hardhat_build_info(path)
    if isinstance(payload.get("contracts"), dict):
        return _solc_combined_artifact(path)
    if "deployedBytecode" in payload:
        single = _foundry_artifact(path, "foundry")
        return [single] if single else []
    if isinstance(payload.get("abi"), list):
        single = _hardhat_artifact(path, build_system)
        return [single] if single else []
    raise InputError(f"not a recognisable solc, Foundry or Hardhat artifact: {path}")


def load_artifacts(root: Path) -> tuple[list[Artifact], str | None]:
    """Walk the conventional output directories. Returns (artifacts, build system)."""

    build_system = detect_build_system(root)
    artifacts: list[Artifact] = []
    seen: set[tuple[str, str]] = set()

    def add(items: list[Artifact]) -> None:
        for item in items:
            key = (item.contract_name, item.source_name or str(item.path))
            if key in seen:
                continue
            seen.add(key)
            artifacts.append(item)

    build_info = root / "artifacts" / "build-info"
    if build_info.is_dir():
        for path in sorted(build_info.glob("*.json")):
            try:
                add(_hardhat_build_info(path))
            except InputError:
                continue
        return artifacts, build_system or "hardhat"

    for search_root in (root / "out", root / "artifacts", root / "build"):
        if not search_root.is_dir():
            continue
        for path in sorted(search_root.rglob("*.json")):
            if path.name.endswith(".dbg.json") or "build-info" in path.parts:
                continue
            try:
                if path.name.endswith(".combined.json"):
                    add(_solc_combined_artifact(path))
                    continue
                if search_root.name == "out":
                    single = _foundry_artifact(path, "foundry")
                    add([single] if single else [])
                else:
                    if path.name.endswith(".json") and path.parent.name == "build":
                        continue
                    single = _hardhat_artifact(path, build_system or "hardhat")
                    add([single] if single else [])
            except InputError:
                continue
    if not artifacts and (root / "build" / "contracts").is_dir():
        for path in sorted((root / "build" / "contracts").rglob("*.json")):
            try:
                add(_solc_combined_artifact(path))
            except InputError:
                continue
    return artifacts, build_system
