"""Evidence-based attack-surface observations.

An observation records a surface worth reviewing. It never asserts that the surface
is exploitable: the explanation says what was found, and ``resolution`` says how
strongly it was established.
"""

from __future__ import annotations

from collections.abc import Iterable

from contractmap.evm.hashing import keccak_hex
from contractmap.models import (
    AccessRestriction,
    AnalysisResult,
    ContractKind,
    ContractModel,
    Evidence,
    FunctionModel,
    Observation,
    ProxyKind,
    Resolution,
)

ORACLE_NAME_HINTS = ("oracle", "pricefeed", "aggregator", "chainlink", "twap")
TOKEN_CALLS = {"transfer", "transferfrom", "approve", "safetransfer", "safetransferfrom"}
PRIVILEGE_VERBS = (
    "upgrade",
    "set",
    "withdraw",
    "sweep",
    "rescue",
    "pause",
    "unpause",
    "grant",
    "revoke",
    "renounce",
    "mint",
    "burn",
    "initialize",
    "reinitialize",
    "execute",
    "transferownership",
)


def observation_id(category: str, subject: str, key: str = "") -> str:
    digest = keccak_hex(f"{subject}|{key}".encode())[:16]
    return f"obs:{category}:{digest}"


def build_observations(result: AnalysisResult) -> list[Observation]:
    """Contract-level observations, deduplicated by stable id."""

    seen: dict[str, Observation] = {}
    for contract in result.contracts:
        functions = [f for f in result.functions if f.contract_id == contract.id]
        for item in contract_observations(contract, functions):
            seen.setdefault(item.id, item)
    return list(seen.values())


def looks_privileged(name: str) -> bool:
    lowered = name.lower().replace("_", "")
    return any(verb in lowered for verb in PRIVILEGE_VERBS)


def _function_evidence(functions: Iterable[FunctionModel], limit: int = 8) -> list[Evidence]:
    return [
        Evidence(kind="function", detail=f.signature, source=f.source)
        for f in list(functions)[:limit]
    ]


def contract_observations(
    contract: ContractModel, functions: list[FunctionModel]
) -> list[Observation]:
    out: list[Observation] = []
    proxy = contract.proxy

    if (
        proxy is not None
        and proxy.kind != ProxyKind.UNKNOWN
        and (proxy.implementation or proxy.facets)
    ):
        out.append(
            Observation(
                id=observation_id("proxy_upgrade", contract.id),
                category="proxy_upgrade",
                subject=contract.id,
                title=f"{contract.name} exposes an upgradeable {proxy.kind.value} surface",
                explanation=(
                    "Storage and implementation are indirected through proxy storage. Review who "
                    "may change the implementation and whether initialisation can be repeated."
                ),
                evidence=list(proxy.evidence),
                resolution=proxy.resolution,
                confidence=1.0 if proxy.resolution == Resolution.CONFIRMED else 0.6,
                review_area="upgrade authorization and initializer protection",
            )
        )

    if proxy is not None and proxy.kind == ProxyKind.ERC1167:
        out.append(
            Observation(
                id=observation_id("minimal_proxy", contract.id),
                category="proxy_upgrade",
                subject=contract.id,
                title="ERC-1167 minimal proxy clone",
                explanation=(
                    "Every call is delegated to a fixed implementation address, so clone behaviour "
                    "is fully determined by that implementation and its initialisation rules."
                ),
                evidence=list(proxy.evidence),
                resolution=Resolution.CONFIRMED,
            )
        )

    if proxy is not None and proxy.kind == ProxyKind.DIAMOND:
        facet_count = len(set(proxy.facets.values()))
        out.append(
            Observation(
                id=observation_id("diamond", contract.id),
                category="diamond_architecture",
                subject=contract.id,
                title=f"ERC-2535 diamond with {facet_count} facet(s)",
                explanation=(
                    "The external interface is assembled from facets at runtime. Selector "
                    "collisions between facets and facet-level authorization are the primary "
                    "review points."
                ),
                evidence=list(proxy.evidence),
                resolution=proxy.resolution,
                review_area="facet selector ownership and diamondCut authorization",
            )
        )

    # An abstract base is judged through the contracts that inherit it.
    if contract.kind in (ContractKind.ABSTRACT, ContractKind.INTERFACE):
        return out

    unguarded = [
        f
        for f in functions
        if f.is_entry_point
        and looks_privileged(f.name)
        and f.access.restriction == AccessRestriction.NONE_IDENTIFIED
    ]
    if unguarded:
        out.append(
            Observation(
                id=observation_id("unguarded_admin", contract.id),
                category="administrative_function",
                subject=contract.id,
                title="Administrative-looking entry points with no resolved guard",
                explanation=(
                    "No modifier or inline check in the AST guards these entry points. That can be "
                    "intentional (public setters, permissionless claiming) or an omission; the "
                    "result identifies where to look, not a defect."
                ),
                evidence=_function_evidence(unguarded),
                resolution=Resolution.INFERRED,
                confidence=0.5,
                review_area="confirm these entry points are intended to be unrestricted",
            )
        )

    unresolved = [
        f
        for f in functions
        if f.is_entry_point
        and looks_privileged(f.name)
        and f.access.restriction == AccessRestriction.UNRESOLVED
    ]
    if unresolved:
        out.append(
            Observation(
                id=observation_id("unresolved_auth", contract.id),
                category="authorization_unresolved",
                subject=contract.id,
                title="Privileged entry points with unresolved authorization",
                explanation=(
                    "These functions perform privileged-looking actions but their guards could not "
                    "be resolved from the AST. A missing resolved guard is not evidence of "
                    "unrestricted access."
                ),
                evidence=_function_evidence(unresolved),
                resolution=Resolution.UNRESOLVED,
                confidence=0.4,
                review_area="manual review of modifier and inline guard behaviour",
            )
        )
    return out
