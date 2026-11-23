"""Function-level attack-surface observations."""

from __future__ import annotations

from collections import defaultdict

from contractmap.analysis.observations import (
    ORACLE_NAME_HINTS,
    TOKEN_CALLS,
    observation_id,
)
from contractmap.models import (
    AccessRestriction,
    ContractModel,
    Evidence,
    FunctionModel,
    Mutability,
    Observation,
    ProxyKind,
    Resolution,
)


def function_observations(
    contract: ContractModel, functions: list[FunctionModel], uses_delegatecall: bool = False
) -> list[Observation]:
    out: list[Observation] = []
    entry_points = [f for f in functions if f.is_entry_point]

    payable = [f for f in entry_points if f.mutability == Mutability.PAYABLE]
    if payable:
        out.append(
            Observation(
                id=observation_id("payable_entry", contract.id),
                category="payable_entry_point",
                subject=contract.id,
                title=f"{len(payable)} payable entry point(s)",
                explanation=(
                    "These functions accept value. Check that accounting, refunds and native-asset "
                    "balances cannot be desynchronised, and that the fallback cannot lock funds."
                ),
                evidence=[
                    Evidence(kind="function", detail=f.signature, source=f.source)
                    for f in payable[:8]
                ],
                resolution=Resolution.CONFIRMED,
                review_area="value accounting and refund paths",
            )
        )

    is_proxy = contract.proxy is not None and contract.proxy.kind != ProxyKind.UNKNOWN
    if uses_delegatecall and not is_proxy:
        out.append(
            Observation(
                id=observation_id("delegatecall", contract.id),
                category="delegatecall_usage",
                subject=contract.id,
                title="Delegatecall present in executable code",
                explanation=(
                    "Delegatecall runs external code against this contract's storage. The review "
                    "question is whether that target is trusted and immutable; delegatecall alone "
                    "is not a defect."
                ),
                evidence=[
                    Evidence(kind="bytecode", detail="DELEGATECALL or CALLCODE in runtime code"),
                    Evidence(
                        kind="function",
                        detail=f"{len(entry_points)} entry points reach the dispatcher",
                    ),
                ],
                resolution=Resolution.INFERRED,
                confidence=0.7,
                review_area="delegatecall target trust and storage-layout compatibility",
            )
        )
    return out


def dangerous_operation_observations(
    contract: ContractModel, functions: list[FunctionModel], operations: dict[str, str]
) -> list[Observation]:
    """Entry points with no guard that reach ``selfdestruct`` or ``delegatecall``.

    ``operations`` maps a function signature to the operation its body performs.
    A proxy's fallback delegates by design, so fallback and receive are skipped.
    """

    exposed = [
        f
        for f in functions
        if f.signature in operations
        and f.is_entry_point
        and not (f.is_fallback or f.is_receive or f.is_constructor)
        and f.access.restriction == AccessRestriction.NONE_IDENTIFIED
    ]
    if not exposed:
        return []
    kinds = sorted({operations[f.signature] for f in exposed})
    return [
        Observation(
            id=observation_id("unguarded_dangerous", contract.id),
            category="unguarded_dangerous_operation",
            subject=contract.id,
            title=f"Entry point with no guard reaches {' and '.join(kinds)}",
            explanation=(
                "Anyone can call these functions, and their body runs selfdestruct, "
                "delegatecall, or a low-level call to an address taken from the arguments. "
                "Unless that is intended, any caller can destroy the contract, run code "
                "against its storage, or make it call anything with its own balance and "
                "approvals."
            ),
            evidence=[
                Evidence(kind="function", detail=f.signature, source=f.source) for f in exposed
            ],
            resolution=Resolution.INFERRED,
            confidence=0.8,
            review_area="who may call selfdestruct and delegatecall paths",
        )
    ]


# State that decides who controls the contract. Writing it without a guard hands
# control to whoever calls first.
PRIVILEGED_STATE = (
    "owner",
    "admin",
    "governance",
    "governor",
    "implementation",
    "authority",
    "guardian",
    "operator",
    "pauser",
    "minter",
    "timelock",
    "controller",
    "keeper",
    "paused",
)
# One-time setup guards: callable by anyone, but only once.
INITIALIZER_MODIFIERS = {"initializer", "reinitializer", "onlyInitializing"}


def privileged_write_observations(
    contract: ContractModel, functions: list[FunctionModel]
) -> list[Observation]:
    """Entry points with no guard that write ownership, admin or upgrade state."""

    exposed: list[tuple[FunctionModel, list[str]]] = []
    for function in functions:
        if (
            not function.is_entry_point
            or function.is_constructor
            or function.access.restriction != AccessRestriction.NONE_IDENTIFIED
            or INITIALIZER_MODIFIERS & set(function.modifiers)
        ):
            continue
        hits = [w for w in function.writes if any(h in w.lower() for h in PRIVILEGED_STATE)]
        if hits:
            exposed.append((function, hits))
    if not exposed:
        return []
    written = sorted({name for _, hits in exposed for name in hits})
    return [
        Observation(
            id=observation_id("unguarded_privileged_write", contract.id),
            category="unguarded_privileged_write",
            subject=contract.id,
            title=f"Anyone can change {', '.join(written)}",
            explanation=(
                "No guard was found on these functions, and they write state that decides "
                "who controls the contract. If that is not intended, the first caller takes "
                "control."
            ),
            evidence=[
                Evidence(
                    kind="function",
                    detail=function.signature,
                    source=function.source,
                    value=",".join(hits),
                )
                for function, hits in exposed
            ],
            resolution=Resolution.INFERRED,
            confidence=0.8,
            review_area="who may set ownership, admin and upgrade state",
        )
    ]


def inheritance_observations(contracts: list[ContractModel]) -> list[Observation]:
    """Report multiple inheritance with shared ancestors, which changes override resolution."""

    graph: dict[str, set[str]] = defaultdict(set)
    for contract in contracts:
        graph[contract.name].update(contract.base_contracts)
    out: list[Observation] = []
    for contract in contracts:
        shared = shared_ancestors(graph, contract.name)
        if not shared:
            continue
        out.append(
            Observation(
                id=observation_id("multiple_inheritance", contract.id, ",".join(sorted(shared))),
                category="inheritance_structure",
                subject=contract.id,
                title="Multiple inheritance with shared ancestors",
                explanation=(
                    f"{contract.name} inherits from bases that share "
                    f"{', '.join(sorted(shared))}. Linearisation order decides which override "
                    "wins, which is worth confirming against the intended design."
                ),
                evidence=[
                    Evidence(kind="ast", detail=f"shared ancestor {name}")
                    for name in sorted(shared)
                ],
                resolution=Resolution.CONFIRMED,
                confidence=0.8,
            )
        )
    return out


def ancestors(graph: dict[str, set[str]], name: str, seen: set[str] | None = None) -> set[str]:
    seen = seen if seen is not None else set()
    for base in graph.get(name, set()):
        if base in seen:
            continue
        seen.add(base)
        ancestors(graph, base, seen)
    return seen


def shared_ancestors(graph: dict[str, set[str]], name: str) -> set[str]:
    direct = graph.get(name, set())
    if len(direct) < 2:
        return set()
    counts: dict[str, int] = defaultdict(int)
    for base in direct:
        for ancestor in ancestors(graph, base):
            counts[ancestor] += 1
    return {ancestor for ancestor, count in counts.items() if count > 1}


def dependency_observations(
    contract: ContractModel,
    functions: list[FunctionModel],
    call_targets: list[str],
) -> list[Observation]:
    """Observations about what the contract depends on at runtime."""

    out: list[Observation] = []
    entry_points = [f for f in functions if f.is_entry_point]

    external = [f for f in entry_points if f.calls_external]
    if external:
        out.append(
            Observation(
                id=observation_id("external_calls", contract.id),
                category="external_call",
                subject=contract.id,
                title=f"{len(external)} entry point(s) perform external calls",
                explanation=(
                    "Control leaves the contract in these paths, so reentrancy and return-value "
                    "handling apply. Whether either is exploitable depends on state ordering and "
                    "on how far the target is trusted."
                ),
                evidence=[
                    Evidence(kind="function", detail=f.signature, source=f.source)
                    for f in external[:8]
                ],
                resolution=Resolution.INFERRED,
                confidence=0.7,
                review_area="state changes relative to external calls",
            )
        )

    tokens = sorted(
        {target for target in call_targets if target.split(".")[-1].lower() in TOKEN_CALLS}
    )
    if tokens:
        out.append(
            Observation(
                id=observation_id("token_interaction", contract.id, ",".join(tokens)),
                category="token_interaction",
                subject=contract.id,
                title="External token-transfer interactions",
                explanation=(
                    "Non-standard token behaviour (fee-on-transfer, hooks, missing return values) "
                    "changes the balance assumptions of these paths."
                ),
                evidence=[Evidence(kind="call", detail=target) for target in tokens[:8]],
                resolution=Resolution.INFERRED,
                confidence=0.6,
                review_area="token return-value checks and balance accounting",
            )
        )

    oracles = sorted(
        {
            name
            for name in [*contract.base_contracts, *contract.interfaces, *contract.libraries]
            if any(hint in name.lower() for hint in ORACLE_NAME_HINTS)
        }
    )
    if oracles:
        out.append(
            Observation(
                id=observation_id("oracle_dependency", contract.id, ",".join(oracles)),
                category="oracle_dependency",
                subject=contract.id,
                title="Oracle-related dependency in the source graph",
                explanation=(
                    "Price or data feeds appear among this contract's dependencies. Feed "
                    "staleness, decimals and manipulation resistance are the review areas."
                ),
                evidence=[Evidence(kind="dependency", detail=name) for name in oracles],
                resolution=Resolution.INFERRED,
                confidence=0.5,
                review_area="oracle staleness, decimals and manipulation resistance",
            )
        )
    return out


def selector_observations(
    contract: ContractModel,
    selectors: dict[str, int],
    known: set[str] | dict[str, str],
) -> list[Observation]:
    """Report deployed selectors with no matching verified ABI entry."""

    missing = sorted(set(selectors) - set(known))
    if not missing:
        return []
    return [
        Observation(
            id=observation_id("unmapped_selectors", contract.id, ",".join(missing)),
            category="unverified_dispatch",
            subject=contract.id,
            title=f"{len(missing)} deployed selector(s) without verified ABI metadata",
            explanation=(
                "These selectors appear in the dispatcher but no verified ABI entry explains "
                "them. Four-byte selectors are not unique, so the function names stay unknown "
                "until source verification succeeds."
            ),
            evidence=[Evidence(kind="bytecode", detail=sel) for sel in missing[:12]],
            resolution=Resolution.UNRESOLVED,
            confidence=0.5,
        )
    ]
