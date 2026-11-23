"""Solidity compilation through the compiler's standard-JSON interface."""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from contractmap.errors import OperationalError
from contractmap.sources.solc import find_solc, solc_version

__all__ = [
    "CompiledContract",
    "compile_sources",
    "find_solc",
    "forge_build",
    "iter_compiled",
    "solc_version",
]

COMPILE_TIMEOUT = 600


@dataclass(slots=True)
class CompiledContract:
    source_name: str
    contract_name: str
    abi: list[dict[str, Any]]
    ast: dict[str, Any]
    runtime_bytecode: str | None
    compiler_version: str
    storage_layout: list[dict[str, Any]] = field(default_factory=list)


def compile_sources(
    sources: dict[str, str],
    *,
    solc: str,
    allow_build: bool,
    optimizer: bool = True,
    runs: int = 200,
) -> dict[str, Any]:
    """Invoke solc through its standard JSON interface.

    ``allow_build`` gates execution. solc itself does not run project build scripts,
    but a caller-supplied ``solc`` path can be any executable, so the flag still has
    to be explicit.
    """

    if not allow_build:
        raise OperationalError(
            "compiling the target sources runs an external binary; re-run with "
            "--allow-build to permit it"
        )
    payload = {
        "language": "Solidity",
        "sources": {name: {"content": content} for name, content in sources.items()},
        "settings": {
            "optimizer": {"enabled": optimizer, "runs": runs},
            "outputSelection": {
                "*": {
                    "*": [
                        "abi",
                        "evm.deployedBytecode.object",
                        "evm.deployedBytecode.immutableReferences",
                        "storageLayout",
                    ],
                    "": ["ast"],
                }
            },
            "metadata": {"bytecodeHash": "ipfs"},
        },
    }
    try:
        proc = subprocess.run(
            [solc, "--standard-json"],
            input=json.dumps(payload),
            capture_output=True,
            text=True,
            timeout=COMPILE_TIMEOUT,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise OperationalError(f"solc compilation exceeded {COMPILE_TIMEOUT}s") from exc
    except OSError as exc:
        raise OperationalError(f"could not execute solc at {solc!r}: {exc}") from exc

    stdout = proc.stdout.strip()
    if not stdout.startswith("{"):
        tail = (proc.stderr or stdout or "no output").strip().splitlines()
        raise OperationalError(f"solc did not return standard JSON: {tail[-1][:300]}")
    result = json.loads(stdout)
    errors = [e for e in result.get("errors", []) if e.get("severity") == "error"]
    if errors:
        formatted = "; ".join(_first_line(e) for e in errors[:3])
        raise OperationalError(f"compilation failed: {formatted}")
    return result


def forge_build(root: Path, into: Path) -> None:
    """Build a Foundry project with ASTs into ``into/out``.

    A default ``forge build`` leaves the AST out of its artifacts, and without it no
    guard can be resolved. Building into a separate directory leaves the project's
    own ``out/`` and ``cache/`` untouched. Tests and scripts are skipped.
    """

    forge = shutil.which("forge")
    if forge is None:
        raise OperationalError("forge is not on PATH; install Foundry or run `forge build --ast`")
    command = [
        forge, "build", "--ast", "--skip", "test", "script", "--root", str(root),
        "--out", str(into / "out"), "--cache-path", str(into / "cache"),
    ]  # fmt: skip
    try:
        proc = subprocess.run(
            command, capture_output=True, text=True, timeout=COMPILE_TIMEOUT, check=False
        )
    except subprocess.TimeoutExpired as exc:
        raise OperationalError(f"forge build exceeded {COMPILE_TIMEOUT}s") from exc
    except OSError as exc:
        raise OperationalError(f"could not execute forge: {exc}") from exc
    if proc.returncode != 0:
        lines = [line for line in (proc.stderr or proc.stdout).splitlines() if line.strip()]
        raise OperationalError(f"forge build failed: {(lines or ['no output'])[-1][:300]}")


def _first_line(entry: dict[str, Any]) -> str:
    message = str(entry.get("formattedMessage") or entry.get("message") or "").strip()
    return message.splitlines()[0][:200] if message else "unknown compiler error"


def iter_compiled(result: dict[str, Any]) -> list[CompiledContract]:
    """Flatten a standard-JSON output into per-contract records."""

    version = result.get("version", "unknown")
    source_asts = result.get("sources", {})
    compiled: list[CompiledContract] = []
    for source_name, payload in result.get("contracts", {}).items():
        ast = source_asts.get(source_name, {}).get("ast", {})
        for contract_name, body in payload.items():
            compiled.append(
                CompiledContract(
                    source_name=source_name,
                    contract_name=contract_name,
                    abi=body.get("abi", []),
                    ast=ast,
                    runtime_bytecode=(body.get("evm", {}).get("deployedBytecode", {}) or {}).get(
                        "object"
                    ),
                    compiler_version=version,
                    storage_layout=(body.get("storageLayout", {}) or {}).get("storage", []),
                )
            )
    return compiled
