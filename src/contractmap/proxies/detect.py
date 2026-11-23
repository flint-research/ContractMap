"""Proxy architecture discovery from deployed bytecode and standard storage slots.

Each classification is backed by evidence: a storage slot holding an address, an
exact bytecode template match, or a successful call to a standard interface.
Nothing is inferred from a contract's name.
"""

from __future__ import annotations

from contractmap.evm import abi
from contractmap.evm.bytecode import (
    extract_selectors,
    is_minimal_proxy,
    minimal_proxy_target,
    strip_hex,
)
from contractmap.evm.hashing import address_from_word
from contractmap.evm.storage import (
    ADMIN_SLOTS,
    BEACON_IMPLEMENTATION_SELECTOR,
    DIAMOND_CUT,
    DIAMOND_LOUPE_FACET_ADDRESSES,
    DIAMOND_LOUPE_FACET_SELECTORS,
    ERC1967_ADMIN_SLOT,
    ERC1967_BEACON_SLOT,
    IMPLEMENTATION_SLOTS,
    ChainView,
)
from contractmap.models import Evidence, ProxyInfo, ProxyKind, Resolution
from contractmap.rpc.client import RpcError, UnsupportedMethod

MAX_FACETS = 64


async def _read_slot(view: ChainView, address: str, slot: str) -> str | None:
    try:
        word = await view.get_storage(address, slot)
    except (RpcError, ValueError):
        return None
    return address_from_word(word) if word else None


async def detect_proxy(view: ChainView, address: str, code: str) -> ProxyInfo:
    """Classify a deployed address; UNKNOWN when no standard pattern is proven."""

    if is_minimal_proxy(code):
        target = minimal_proxy_target(code)
        if target:
            return ProxyInfo(
                kind=ProxyKind.ERC1167,
                implementation=target,
                resolution=Resolution.CONFIRMED,
                evidence=[
                    Evidence(
                        kind="bytecode",
                        detail="runtime bytecode matches the ERC-1167 minimal proxy template",
                        value="363d3d373d3d3d363d73...5af43d82803e903d91602b57fd5bf3",
                    )
                ],
            )

    beacon = await _read_slot(view, address, ERC1967_BEACON_SLOT)
    if beacon:
        info = ProxyInfo(
            kind=ProxyKind.ERC1967_BEACON,
            beacon=beacon,
            resolution=Resolution.INFERRED,
            evidence=[
                Evidence(
                    kind="storage",
                    detail="EIP-1967 beacon slot holds a non-zero address",
                    value=f"{ERC1967_BEACON_SLOT} -> {beacon}",
                )
            ],
        )
        try:
            result = await view.eth_call(beacon, BEACON_IMPLEMENTATION_SELECTOR)
            implementation = abi.decode_address(result)
        except (RpcError, ValueError):
            implementation = None
        if implementation:
            info.implementation = implementation
            info.resolution = Resolution.CONFIRMED
            info.evidence.append(
                Evidence(
                    kind="call",
                    detail="beacon.implementation() returned an address",
                    source=beacon,
                    value=implementation,
                )
            )
        else:
            info.evidence.append(
                Evidence(
                    kind="call",
                    detail="beacon.implementation() did not return a usable address",
                    source=beacon,
                )
            )
        return info

    for slot, description in IMPLEMENTATION_SLOTS:
        implementation = await _read_slot(view, address, slot)
        if not implementation:
            continue
        info = ProxyInfo(
            kind=ProxyKind.ERC1967,
            implementation=implementation,
            resolution=Resolution.CONFIRMED,
            evidence=[
                Evidence(
                    kind="storage",
                    detail=f"{description} holds a non-zero address",
                    value=f"{slot} -> {implementation}",
                )
            ],
        )
        for admin_slot, admin_description in ADMIN_SLOTS:
            admin = await _read_slot(view, address, admin_slot)
            if admin:
                info.admin = admin
                info.evidence.append(
                    Evidence(
                        kind="storage",
                        detail=f"{admin_description} holds a non-zero address",
                        value=f"{admin_slot} -> {admin}",
                    )
                )
                break
        if info.admin is None:
            info.evidence.append(
                Evidence(
                    kind="storage",
                    detail="no address in the standard admin slots; consistent with UUPS "
                    "or an immutable implementation pointer, but not proof of either",
                    value=f"{ERC1967_ADMIN_SLOT} is empty",
                )
            )
        return info

    diamond = await _detect_diamond(view, address, code)
    if diamond is not None:
        return diamond

    return ProxyInfo(kind=ProxyKind.UNKNOWN, resolution=Resolution.UNRESOLVED)


async def _detect_diamond(view: ChainView, address: str, code: str) -> ProxyInfo | None:
    """Require the diamondCut selector plus a live loupe call.

    A fallback-only contract that happens to contain the diamondCut selector is not
    enough: without a working loupe the facet set cannot be established, so it stays
    UNRESOLVED rather than becoming a guessed diamond.
    """

    stripped = strip_hex(code)
    if DIAMOND_CUT not in stripped and DIAMOND_CUT not in extract_selectors(code):
        return None

    evidence = [
        Evidence(
            kind="bytecode",
            detail="runtime bytecode references the diamondCut selector",
            value=DIAMOND_CUT,
        )
    ]
    try:
        raw = await view.eth_call(address, DIAMOND_LOUPE_FACET_ADDRESSES)
    except (UnsupportedMethod, RpcError, ValueError):
        return ProxyInfo(
            kind=ProxyKind.DIAMOND,
            resolution=Resolution.UNRESOLVED,
            evidence=[
                *evidence,
                Evidence(
                    kind="call",
                    detail="diamondLoupeFacetAddresses() failed; facet set unknown",
                ),
            ],
        )

    facets = abi.decode_address_array(raw)
    if not facets:
        return ProxyInfo(
            kind=ProxyKind.DIAMOND,
            resolution=Resolution.UNRESOLVED,
            evidence=[*evidence, Evidence(kind="call", detail="loupe returned no facets")],
        )

    selector_map: dict[str, str] = {}
    unresolved = False
    for facet in facets[:MAX_FACETS]:
        try:
            facet_raw = await view.eth_call(
                address, DIAMOND_LOUPE_FACET_SELECTORS + abi.address_word(facet)
            )
        except (UnsupportedMethod, RpcError, ValueError):
            unresolved = True
            continue
        facet_selectors = abi.decode_bytes4_array(facet_raw)
        if not facet_selectors:
            unresolved = True
            continue
        for facet_selector in facet_selectors:
            selector_map.setdefault(facet_selector, facet)
        evidence.append(
            Evidence(
                kind="call",
                detail=f"facetFunctionSelectors({facet}) returned {len(facet_selectors)} selectors",
                source=address,
            )
        )

    if len(facets) > MAX_FACETS:
        unresolved = True
        evidence.append(
            Evidence(
                kind="limit",
                detail=f"facet list truncated at {MAX_FACETS} of {len(facets)} addresses",
            )
        )

    return ProxyInfo(
        kind=ProxyKind.DIAMOND,
        facets=dict(sorted(selector_map.items())),
        resolution=Resolution.UNRESOLVED if unresolved else Resolution.CONFIRMED,
        evidence=evidence,
    )


async def facet_addresses(view: ChainView, address: str) -> list[str]:
    try:
        raw = await view.eth_call(address, DIAMOND_LOUPE_FACET_ADDRESSES)
    except (UnsupportedMethod, RpcError, ValueError):
        return []
    return abi.decode_address_array(raw) or []
