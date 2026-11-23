"""Stable graph identities.

Identifiers must survive re-scans and reorderings so ``diff`` compares meaning,
not array positions. Contract identity is the deployment identity when an address
is known, and the source unit otherwise.
"""

from __future__ import annotations

from contractmap.evm.hashing import keccak_hex


def contract_id(
    address: str | None, chain_id: int | None, source_name: str | None, name: str
) -> str:
    if address:
        chain = chain_id if chain_id is not None else 0
        return f"contract:{chain}:{address.lower()}"
    unit = source_name or "local"
    return f"contract:src:{unit}:{name}"


def function_id(owner: str, signature: str) -> str:
    digest = keccak_hex(signature.encode())[:12]
    return f"function:{owner}:{digest}"


def role_id(owner: str | None, name: str) -> str:
    scope = owner or "global"
    return f"role:{scope}:{name}"


def external_target_id(address: str | None, hint: str) -> str:
    if address:
        return f"external:{address.lower()}"
    return f"external:unresolved:{keccak_hex(hint.encode())[:12]}"


def file_digest(content: str) -> str:
    return "sha256:" + keccak_hex(content.encode())
