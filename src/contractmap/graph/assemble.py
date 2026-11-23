"""Turns analysed contracts and function facts into the canonical graph."""

from __future__ import annotations

from collections.abc import Iterable

from contractmap.graph import identity
from contractmap.graph.builder import GraphBuilder
from contractmap.models import (
    ContractKind,
    ContractModel,
    EdgeKind,
    Evidence,
    FunctionModel,
    Node,
    NodeKind,
    Resolution,
    RoleModel,
)


def short_address(address: str) -> str:
    return f"{address[:10]}…{address[-4:]}"


def external_node(address: str, kind: NodeKind, kind_hint: str, chain_id: int | None) -> Node:
    return Node(
        id=identity.external_target_id(address, kind_hint),
        kind=kind,
        label=short_address(address),
        address=address.lower(),
        detail=kind_hint,
        attributes={"chain_id": str(chain_id) if chain_id is not None else "unknown"},
    )


def account_node(address: str, kind_hint: str, chain_id: int | None) -> Node:
    base = external_node(address, NodeKind.PRIVILEGED_ACCOUNT, kind_hint, chain_id)
    return base.model_copy(update={"id": base.id.replace("external:", "account:")})


def _link(builder: GraphBuilder, known: dict[str, str], stub: Node) -> str:
    """Point at the scanned contract when there is one, else at a stub node."""

    existing = known.get(stub.address or "")
    if existing is not None:
        return existing
    builder.add_node(stub)
    return stub.id


def add_contract(
    builder: GraphBuilder, contract: ContractModel, known: dict[str, str] | None = None
) -> str:
    """Add a contract and its proxy wiring. ``known`` maps scanned addresses to nodes."""

    known = known or {}
    node = builder.contract_node(contract)
    proxy = contract.proxy
    if proxy is None:
        return node

    if proxy.implementation:
        impl = _link(
            builder,
            known,
            external_node(
                proxy.implementation, NodeKind.IMPLEMENTATION, str(proxy.kind), contract.chain_id
            ),
        )
        builder.add_edge(
            EdgeKind.PROXIES_TO,
            node,
            impl,
            resolution=proxy.resolution,
            evidence=[e for e in proxy.evidence if "implementation" in e.detail.lower()],
        )

    if proxy.beacon:
        beacon = _link(
            builder,
            known,
            external_node(proxy.beacon, NodeKind.BEACON, "beacon", contract.chain_id),
        )
        builder.add_edge(
            EdgeKind.RESOLVES_VIA_BEACON,
            node,
            beacon,
            resolution=proxy.resolution,
            evidence=[e for e in proxy.evidence if "beacon" in e.detail.lower()],
        )

    if proxy.admin:
        admin = account_node(proxy.admin, "proxy admin", contract.chain_id)
        builder.add_node(admin)
        builder.add_edge(
            EdgeKind.CONTROLLED_BY,
            node,
            admin.id,
            label="proxy admin",
            evidence=[e for e in proxy.evidence if "admin" in e.detail.lower()],
        )

    facets: dict[str, list[str]] = {}
    for selector, facet in proxy.facets.items():
        facets.setdefault(facet, []).append(selector)
    for facet, selectors in sorted(facets.items()):
        facet_node = _link(
            builder,
            known,
            external_node(facet, NodeKind.FACET, "diamond facet", contract.chain_id),
        )
        builder.add_edge(
            EdgeKind.HAS_FACET,
            node,
            facet_node,
            label=f"{len(selectors)} selector" + ("s" if len(selectors) != 1 else ""),
            resolution=proxy.resolution,
            evidence=[
                Evidence(
                    kind="loupe",
                    detail="facetFunctionSelectors maps these selectors to the facet",
                    value=",".join(sorted(selectors)),
                )
            ],
        )
    return node


def add_inheritance(
    builder: GraphBuilder,
    contracts: Iterable[ContractModel],
    node_of: dict[str, str],
) -> None:
    by_name = {contract.name: contract for contract in contracts}
    for contract in contracts:
        source_node = node_of.get(contract.id)
        if source_node is None:
            continue
        for base in contract.base_contracts:
            base_contract = by_name.get(base)
            target = node_of.get(base_contract.id) if base_contract else None
            if base_contract is None or target is None:
                continue
            builder.add_edge(
                inheritance_edge(contract, base_contract),
                source_node,
                target,
                evidence=[
                    Evidence(
                        kind="ast", detail=f"{contract.name} inherits {base}", source=contract.id
                    )
                ],
            )
        for library in contract.libraries:
            library_contract = by_name.get(library)
            target = node_of.get(library_contract.id) if library_contract else None
            if target is not None:
                builder.add_edge(EdgeKind.USES_LIBRARY, source_node, target, label=library)


def inheritance_edge(derived: ContractModel, base: ContractModel) -> EdgeKind:
    # An abstract base carries code, so deriving from it is inheritance.
    if base.kind == ContractKind.INTERFACE:
        return EdgeKind.IMPLEMENTS
    return EdgeKind.INHERITS


def add_functions(
    builder: GraphBuilder,
    contract: ContractModel,
    functions: Iterable[FunctionModel],
    owner_node: str,
) -> None:
    for function in functions:
        if function.contract_id != contract.id or not function.is_entry_point:
            continue
        node = Node(
            id=f"node:{NodeKind.FUNCTION.value}:{function.id}",
            kind=NodeKind.FUNCTION,
            label=function.signature,
            contract_id=contract.id,
            address=contract.address,
            detail=function.mutability.value,
            attributes={
                "visibility": function.visibility.value,
                "selector": function.selector or "",
                "access": str(function.access.restriction),
                **({"roles": ", ".join(function.access.roles)} if function.access.roles else {}),
                **({"writes": ", ".join(function.writes)} if function.writes else {}),
                **({"declared_in": function.declared_in} if function.declared_in else {}),
            },
        )
        if not builder.add_node(node):
            continue
        builder.add_edge(EdgeKind.EXPOSES, owner_node, node.id, label=function.signature)


def add_access(
    builder: GraphBuilder,
    contract: ContractModel,
    functions: Iterable[FunctionModel],
    roles: Iterable[RoleModel],
    owner_node: str,
) -> None:
    role_nodes: dict[str, str] = {}
    for role in roles:
        if role.contract_id not in (None, contract.id):
            continue
        node = Node(
            id=f"node:{NodeKind.ROLE.value}:{role.id}",
            kind=NodeKind.ROLE,
            label=role.name,
            contract_id=contract.id,
            detail=role.kind,
            attributes={"kind": role.kind},
        )
        if builder.add_node(node):
            role_nodes[role.name] = node.id
            builder.add_edge(
                EdgeKind.PROTECTED_BY,
                owner_node,
                node.id,
                label=role.name,
                resolution=Resolution.CONFIRMED,
                evidence=role.evidence,
            )

    for function in functions:
        if function.contract_id != contract.id or not function.is_entry_point:
            continue
        function_node = f"node:{NodeKind.FUNCTION.value}:{function.id}"
        for role_name in function.access.roles:
            target = role_nodes.get(role_name)
            if target is None:
                continue
            confirmed = function.access.restriction == "confirmed"
            builder.add_edge(
                EdgeKind.PROTECTED_BY,
                function_node,
                target,
                label=role_name,
                resolution=Resolution.CONFIRMED if confirmed else Resolution.INFERRED,
                confidence=0.95 if confirmed else 0.6,
                evidence=function.access.evidence,
            )


def add_call_edges(
    builder: GraphBuilder,
    contract: ContractModel,
    calls: Iterable[tuple[FunctionModel, str, str]],
    node_of: dict[str, str],
    contracts_by_name: dict[str, ContractModel],
) -> None:
    """``calls`` yields (function, callee label, edge kind)."""

    for function, callee, kind in calls:
        source_node = f"node:{NodeKind.FUNCTION.value}:{function.id}"
        target_contract = contracts_by_name.get(callee.split(".")[0])
        if target_contract is not None and target_contract.id in node_of:
            builder.add_edge(
                EdgeKind(kind),
                source_node,
                node_of[target_contract.id],
                label=callee,
                resolution=Resolution.CONFIRMED,
                evidence=[
                    Evidence(
                        kind="ast",
                        detail=f"{function.signature} calls {callee}",
                        source=function.source,
                    )
                ],
            )
            continue
        unresolved = Node(
            id=identity.external_target_id(None, f"{contract.id}:{callee}"),
            kind=NodeKind.EXTERNAL_TARGET,
            label=callee,
            detail="unresolved call target",
            attributes={"resolution": "unresolved"},
        )
        if builder.add_node(unresolved):
            builder.add_edge(
                EdgeKind(kind),
                source_node,
                unresolved.id,
                label=callee,
                resolution=Resolution.UNRESOLVED,
                confidence=0.3,
                evidence=[
                    Evidence(
                        kind="ast",
                        detail=(
                            f"{function.signature} calls {callee}; target not resolved statically"
                        ),
                        source=function.source,
                    )
                ],
            )
