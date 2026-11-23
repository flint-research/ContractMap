"""Verified-source retrieval: Sourcify v2 and Etherscan v2.

Both APIs are optional inputs. Their responses are treated as untrusted: every
field is validated before it reaches the model, and a failure degrades to
bytecode-only analysis with a warning instead of aborting the scan.
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from typing import Any

import httpx

from contractmap.config import SourceConfig
from contractmap.models import Evidence

MAX_SOURCE_BYTES = 4 * 1024 * 1024


class SourceUnavailable(Exception):
    pass


@dataclass(slots=True)
class VerifiedSource:
    provider: str
    address: str
    abi: list[dict[str, Any]] = field(default_factory=list)
    source_files: dict[str, str] = field(default_factory=dict)
    contract_name: str | None = None
    compiler_version: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    evidence: list[Evidence] = field(default_factory=list)

    @property
    def primary_source(self) -> str | None:
        return next(iter(self.source_files.values()), None)


def _client(timeout: float) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        timeout=httpx.Timeout(timeout),
        headers={"user-agent": "contractmap"},
        follow_redirects=True,
    )


async def fetch_sourcify(
    address: str, chain_id: int, config: SourceConfig, timeout: float = 20.0
) -> VerifiedSource | None:
    """Sourcify v2: ``/v2/contract/{chainId}/{address}?fields=...``."""

    url = f"{config.sourcify_url.rstrip('/')}/v2/contract/{chain_id}/{address.lower()}"
    params = {"fields": "abi,metadata,compilation,sources"}
    try:
        async with _client(timeout) as client:
            response = await client.get(url, params=params)
    except httpx.HTTPError as exc:
        raise SourceUnavailable(f"sourcify request failed: {type(exc).__name__}") from exc
    if response.status_code == 404:
        return None
    if response.status_code >= 400:
        raise SourceUnavailable(f"sourcify returned HTTP {response.status_code}")
    if len(response.content) > MAX_SOURCE_BYTES:
        raise SourceUnavailable("sourcify response exceeded the size limit")
    try:
        payload = response.json()
    except json.JSONDecodeError as exc:
        raise SourceUnavailable("sourcify returned malformed JSON") from exc
    return _parse_sourcify(payload, address, chain_id)


def _parse_sourcify(payload: Any, address: str, chain_id: int) -> VerifiedSource | None:
    if not isinstance(payload, dict):
        return None
    abi = payload.get("abi")
    if isinstance(abi, str):
        try:
            abi = json.loads(abi)
        except json.JSONDecodeError:
            abi = None
    if not isinstance(abi, list):
        abi = []

    files: dict[str, str] = {}
    sources = payload.get("sources")
    if isinstance(sources, list):
        for entry in sources:
            if not isinstance(entry, dict):
                continue
            content = entry.get("content")
            path = entry.get("path") or entry.get("name")
            if isinstance(content, str) and isinstance(path, str):
                files[path] = content
    elif isinstance(sources, dict):
        for name, entry in sources.items():
            if isinstance(entry, dict) and isinstance(entry.get("content"), str):
                files[str(name)] = entry["content"]
            elif isinstance(entry, str):
                files[str(name)] = entry

    metadata = payload.get("metadata")
    if isinstance(metadata, str):
        try:
            metadata = json.loads(metadata)
        except json.JSONDecodeError:
            metadata = {}
    if not isinstance(metadata, dict):
        metadata = {}

    compiler = None
    compilation = payload.get("compilation")
    if isinstance(compilation, dict):
        compiler = compilation.get("compilerVersion") or compilation.get("compiler")
    if not compiler:
        raw = metadata.get("compiler", {})
        compiler = raw.get("version") if isinstance(raw, dict) else None

    name = None
    if isinstance(compilation, dict) and isinstance(compilation.get("name"), str):
        name = compilation["name"]
    settings = metadata.get("settings", {})
    if name is None and isinstance(settings, dict):
        compilation_target = settings.get("compilationTarget", {})
        if isinstance(compilation_target, dict) and compilation_target:
            name = next(iter(compilation_target.values()), None)

    return VerifiedSource(
        provider="sourcify",
        address=address.lower(),
        abi=[entry for entry in abi if isinstance(entry, dict)],
        source_files=files,
        contract_name=name if isinstance(name, str) else None,
        compiler_version=str(compiler) if compiler else None,
        metadata=metadata,
        evidence=[
            Evidence(
                kind="explorer",
                detail="verified source retrieved from Sourcify v2",
                source=f"sourcify:{chain_id}",
                value=address.lower(),
            )
        ],
    )


async def fetch_etherscan(
    address: str, chain_id: int, config: SourceConfig, timeout: float = 20.0
) -> VerifiedSource | None:
    """Etherscan v2: multi-chain ``/v2/api?chainid=`` with a single key."""

    if not config.etherscan_api_key:
        return None
    params = {
        "chainid": str(chain_id),
        "module": "contract",
        "action": "getsourcecode",
        "address": address.lower(),
        "apikey": config.etherscan_api_key,
    }
    url = f"{config.etherscan_url.rstrip('/')}"
    try:
        async with _client(timeout) as client:
            response = await client.get(url, params=params)
    except httpx.HTTPError as exc:
        raise SourceUnavailable(f"etherscan request failed: {type(exc).__name__}") from exc
    if response.status_code >= 400:
        raise SourceUnavailable(f"etherscan returned HTTP {response.status_code}")
    try:
        payload = response.json()
    except json.JSONDecodeError as exc:
        raise SourceUnavailable("etherscan returned malformed JSON") from exc
    if not isinstance(payload, dict) or payload.get("status") != "1":
        return None
    result = payload.get("result")
    if not isinstance(result, list) or not result or not isinstance(result[0], dict):
        return None
    entry = result[0]
    source = entry.get("SourceCode")
    if not isinstance(source, str) or not source.strip():
        return None
    abi_raw = entry.get("ABI")
    try:
        abi = json.loads(abi_raw) if isinstance(abi_raw, str) else []
    except json.JSONDecodeError:
        abi = []
    if not isinstance(abi, list):
        abi = []
    files = _etherscan_sources(source, str(entry.get("ContractName") or "Contract.sol"))
    return VerifiedSource(
        provider="etherscan",
        address=address.lower(),
        abi=[item for item in abi if isinstance(item, dict)],
        source_files=files,
        contract_name=str(entry.get("ContractName") or "") or None,
        compiler_version=str(entry.get("CompilerVersion") or "") or None,
        metadata={"optimizer": entry.get("OptimizationUsed"), "runs": entry.get("Runs")},
        evidence=[
            Evidence(
                kind="explorer",
                detail="verified source retrieved from Etherscan v2",
                source=f"etherscan:{chain_id}",
                value=address.lower(),
            )
        ],
    )


def _etherscan_sources(source: str, default_name: str) -> dict[str, str]:
    """Etherscan returns plain source, or a ``{{...}}`` multi-file standard JSON."""

    stripped = source.strip()
    if stripped.startswith("{{"):
        try:
            parsed = json.loads(stripped[1:-1])
        except json.JSONDecodeError:
            return {default_name: stripped}
        sources = parsed.get("sources", {}) if isinstance(parsed, dict) else {}
        return {
            str(name): entry["content"]
            for name, entry in sources.items()
            if isinstance(entry, dict) and isinstance(entry.get("content"), str)
        }
    return {default_name: stripped}


async def fetch_verified(
    address: str, chain_id: int, config: SourceConfig, timeout: float = 20.0
) -> tuple[VerifiedSource | None, list[str]]:
    """Try configured providers in order. Returns (source, warnings)."""

    warnings: list[str] = []
    providers = []
    if config.etherscan:
        providers.append(("etherscan", fetch_etherscan))
    if config.sourcify:
        providers.append(("sourcify", fetch_sourcify))
    for name, fetcher in providers:
        try:
            found = await asyncio.wait_for(
                fetcher(address, chain_id, config, timeout), timeout=timeout
            )
        except TimeoutError:
            warnings.append(f"{name} lookup timed out")
            continue
        except SourceUnavailable as exc:
            warnings.append(str(exc))
            continue
        if found is not None and (found.abi or found.source_files):
            return found, warnings
    return None, warnings
