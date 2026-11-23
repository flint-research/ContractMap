"""Semantic comparison of two analyses.

Comparison uses stable identities (deployment address, source unit, selector, role
id, observation id) rather than array position or raw JSON text. Run-specific
metadata is excluded, so diffing a graph against itself is always empty.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import Field

from contractmap.models import (
    SCHEMA_VERSION,
    AnalysisResult,
    Base,
    ContractModel,
    FunctionModel,
)


class ChangeKind(StrEnum):
    ADDED = "added"
    REMOVED = "removed"
    CHANGED = "changed"


class DiffCategory(StrEnum):
    CONTRACT = "contract"
    PROXY = "proxy"
    FUNCTION = "function"
    SELECTOR = "selector"
    ACCESS = "access"
    ROLE = "role"
    DEPENDENCY = "dependency"
    EDGE = "edge"
    OBSERVATION = "observation"


class DiffEntry(Base):
    id: str
    kind: ChangeKind
    category: DiffCategory
    subject: str
    label: str
    before: str | None = None
    after: str | None = None


class DiffSide(Base):
    digest: str | None = None
    target: str = ""
    chain_id: int | None = None
    block_number: int | None = None
    complete: bool = True
    tool_version: str | None = None


class AnalysisDiff(Base):
    schema_version: str = SCHEMA_VERSION
    tool: str = "contractmap-diff"
    before: DiffSide
    after: DiffSide
    comparable: bool = True
    caveats: list[str] = Field(default_factory=list)
    changes: list[DiffEntry] = Field(default_factory=list)
    unchanged: dict[str, int] = Field(default_factory=dict)

    def counts(self) -> dict[str, int]:
        tally: dict[str, int] = {}
        for change in self.changes:
            key = f"{change.kind.value}.{change.category.value}"
            tally[key] = tally.get(key, 0) + 1
        return dict(sorted(tally.items()))

    def significant(self) -> list[DiffEntry]:
        order = {
            DiffCategory.PROXY: 0,
            DiffCategory.ACCESS: 1,
            DiffCategory.ROLE: 2,
            DiffCategory.SELECTOR: 3,
            DiffCategory.FUNCTION: 4,
            DiffCategory.CONTRACT: 5,
            DiffCategory.DEPENDENCY: 6,
            DiffCategory.OBSERVATION: 7,
            DiffCategory.EDGE: 8,
        }
        return sorted(
            self.changes,
            key=lambda c: (order.get(c.category, 99), c.kind.value, c.subject, c.label),
        )


def _side(result: AnalysisResult) -> DiffSide:
    return DiffSide(
        digest=result.metadata.digest or result.digest(),
        target=result.target.identifier,
        chain_id=result.chain.chain_id or result.target.chain_id,
        block_number=result.chain.block_number or result.target.block_number,
        complete=result.metadata.analysis_complete,
        tool_version=result.metadata.tool_version,
    )


def _names(*results: AnalysisResult) -> dict[str, str]:
    names: dict[str, str] = {}
    for result in results:
        for contract in result.contracts:
            names[contract.id] = contract.name
    return names


def compare(before: AnalysisResult, after: AnalysisResult) -> AnalysisDiff:
    caveats: list[str] = []
    before_side, after_side = _side(before), _side(after)

    if before.metadata.schema_version != after.metadata.schema_version:
        caveats.append(
            f"schema versions differ ({before.metadata.schema_version} vs "
            f"{after.metadata.schema_version}); comparison is best effort"
        )
    if before_side.chain_id != after_side.chain_id:
        caveats.append(
            f"chain ids differ ({before_side.chain_id} vs {after_side.chain_id}); "
            "address-keyed differences reflect different chains, not architecture drift"
        )
    if (
        before_side.block_number is not None
        and after_side.block_number is not None
        and before_side.block_number != after_side.block_number
    ):
        caveats.append(
            f"analysed at different blocks ({before_side.block_number} vs "
            f"{after_side.block_number})"
        )
    if not before_side.complete:
        caveats.append("the earlier analysis was incomplete; absent data can look like a removal")
    if not after_side.complete:
        caveats.append("the later analysis was incomplete; absent data can look like a removal")
    if before.metadata.tool_version != after.metadata.tool_version:
        caveats.append(
            f"tool versions differ ({before.metadata.tool_version} vs "
            f"{after.metadata.tool_version})"
        )
    if before.target.kind != after.target.kind:
        caveats.append(f"target kinds differ ({before.target.kind} vs {after.target.kind})")

    unchanged: dict[str, int] = {}
    changes: list[DiffEntry] = []
    changes.extend(_diff_contracts(before, after, unchanged))
    changes.extend(_diff_proxies(before, after, unchanged))
    changes.extend(_diff_functions(before, after, unchanged))
    changes.extend(_diff_access(before, after, unchanged))
    changes.extend(_diff_roles(before, after, unchanged))
    changes.extend(_diff_observations(before, after, unchanged))
    changes.extend(_diff_edges(before, after, unchanged))

    return AnalysisDiff(
        before=before_side,
        after=after_side,
        comparable=before_side.complete and after_side.complete,
        caveats=caveats,
        changes=sorted(changes, key=lambda c: (c.category.value, c.kind.value, c.subject, c.label)),
        unchanged=dict(sorted(unchanged.items())),
    )


def _describe_contract(contract: ContractModel) -> str:
    parts = [contract.kind.value]
    if contract.address:
        parts.append(contract.address)
    if contract.compiler_version:
        parts.append(f"solc {contract.compiler_version}")
    return ", ".join(parts)


def _joined(value: object) -> str | None:
    if isinstance(value, list):
        return ", ".join(str(item) for item in value) or None
    return str(value) if value is not None else None


def _diff_contracts(
    before: AnalysisResult, after: AnalysisResult, unchanged: dict[str, int]
) -> list[DiffEntry]:
    old = {contract.id: contract for contract in before.contracts}
    new = {contract.id: contract for contract in after.contracts}
    entries: list[DiffEntry] = []

    for contract_id in sorted(new.keys() - old.keys()):
        contract = new[contract_id]
        entries.append(
            DiffEntry(
                id=f"contract:added:{contract_id}",
                kind=ChangeKind.ADDED,
                category=DiffCategory.CONTRACT,
                subject=contract_id,
                label=contract.name,
                after=_describe_contract(contract),
            )
        )
    for contract_id in sorted(old.keys() - new.keys()):
        contract = old[contract_id]
        entries.append(
            DiffEntry(
                id=f"contract:removed:{contract_id}",
                kind=ChangeKind.REMOVED,
                category=DiffCategory.CONTRACT,
                subject=contract_id,
                label=contract.name,
                before=_describe_contract(contract),
            )
        )

    for contract_id in sorted(old.keys() & new.keys()):
        old_contract, new_contract = old[contract_id], new[contract_id]
        for attribute, label in (
            ("base_contracts", "inheritance"),
            ("interfaces", "interfaces"),
            ("libraries", "library dependencies"),
        ):
            old_text = _joined(getattr(old_contract, attribute))
            new_text = _joined(getattr(new_contract, attribute))
            if old_text != new_text:
                entries.append(
                    DiffEntry(
                        id=f"dependency:{contract_id}:{attribute}",
                        kind=ChangeKind.CHANGED,
                        category=DiffCategory.DEPENDENCY,
                        subject=contract_id,
                        label=f"{new_contract.name} {label}",
                        before=old_text,
                        after=new_text,
                    )
                )
        if old_contract.source_kind != new_contract.source_kind:
            entries.append(
                DiffEntry(
                    id=f"contract:{contract_id}:source_kind",
                    kind=ChangeKind.CHANGED,
                    category=DiffCategory.CONTRACT,
                    subject=contract_id,
                    label=f"{new_contract.name} source provenance",
                    before=old_contract.source_kind.value,
                    after=new_contract.source_kind.value,
                )
            )
        if old_contract.code_hash != new_contract.code_hash:
            entries.append(
                DiffEntry(
                    id=f"contract:{contract_id}:code_hash",
                    kind=ChangeKind.CHANGED,
                    category=DiffCategory.CONTRACT,
                    subject=contract_id,
                    label=f"{new_contract.name} runtime code",
                    before=old_contract.code_hash,
                    after=new_contract.code_hash,
                )
            )
    unchanged["contracts"] = len(old.keys() & new.keys())
    return entries


def _diff_proxies(
    before: AnalysisResult, after: AnalysisResult, unchanged: dict[str, int]
) -> list[DiffEntry]:
    old = {contract.id: contract.proxy for contract in before.contracts}
    new = {contract.id: contract.proxy for contract in after.contracts}
    names = _names(before, after)
    entries: list[DiffEntry] = []

    for contract_id in sorted(old.keys() | new.keys()):
        old_proxy, new_proxy = old.get(contract_id), new.get(contract_id)
        if old_proxy is None and new_proxy is None:
            continue
        name = names.get(contract_id, contract_id)
        for attribute, label in (
            ("kind", "proxy type"),
            ("implementation", "implementation"),
            ("admin", "proxy admin"),
            ("beacon", "beacon"),
        ):
            old_value = getattr(old_proxy, attribute, None) if old_proxy else None
            new_value = getattr(new_proxy, attribute, None) if new_proxy else None
            old_text = str(old_value) if old_value is not None else None
            new_text = str(new_value) if new_value is not None else None
            if old_text == new_text:
                continue
            if old_text is None:
                kind = ChangeKind.ADDED
            elif new_text is None:
                kind = ChangeKind.REMOVED
            else:
                kind = ChangeKind.CHANGED
            entries.append(
                DiffEntry(
                    id=f"proxy:{contract_id}:{attribute}",
                    kind=kind,
                    category=DiffCategory.PROXY,
                    subject=contract_id,
                    label=f"{name} {label}",
                    before=old_text,
                    after=new_text,
                )
            )
        entries.extend(_diff_facets(contract_id, name, old_proxy, new_proxy))
    unchanged["proxies"] = sum(
        1 for key in old.keys() & new.keys() if old[key] is not None or new[key] is not None
    )
    return entries


def _diff_facets(
    contract_id: str, name: str, old_proxy: object, new_proxy: object
) -> list[DiffEntry]:
    old_facets = dict(getattr(old_proxy, "facets", None) or {})
    new_facets = dict(getattr(new_proxy, "facets", None) or {})
    entries: list[DiffEntry] = []
    for selector in sorted(new_facets.keys() - old_facets.keys()):
        entries.append(
            DiffEntry(
                id=f"selector:{contract_id}:{selector}",
                kind=ChangeKind.ADDED,
                category=DiffCategory.SELECTOR,
                subject=contract_id,
                label=f"{name} selector {selector}",
                after=new_facets[selector],
            )
        )
    for selector in sorted(old_facets.keys() - new_facets.keys()):
        entries.append(
            DiffEntry(
                id=f"selector:{contract_id}:{selector}",
                kind=ChangeKind.REMOVED,
                category=DiffCategory.SELECTOR,
                subject=contract_id,
                label=f"{name} selector {selector}",
                before=old_facets[selector],
            )
        )
    for selector in sorted(old_facets.keys() & new_facets.keys()):
        if old_facets[selector] != new_facets[selector]:
            entries.append(
                DiffEntry(
                    id=f"selector:{contract_id}:{selector}",
                    kind=ChangeKind.CHANGED,
                    category=DiffCategory.SELECTOR,
                    subject=contract_id,
                    label=f"{name} selector {selector}",
                    before=old_facets[selector],
                    after=new_facets[selector],
                )
            )
    return entries


def _function_label(function: FunctionModel, name: str) -> str:
    return f"{name}.{function.signature}"


def _describe_access(function: FunctionModel) -> str:
    roles = ", ".join(function.access.roles) if function.access.roles else "no resolved role"
    return f"{function.access.restriction.value} ({roles})"


def _diff_functions(
    before: AnalysisResult, after: AnalysisResult, unchanged: dict[str, int]
) -> list[DiffEntry]:
    old = {function.id: function for function in before.functions}
    new = {function.id: function for function in after.functions}
    names = _names(before, after)
    entries: list[DiffEntry] = []

    for function_id in sorted(new.keys() - old.keys()):
        function = new[function_id]
        entries.append(
            DiffEntry(
                id=f"function:added:{function_id}",
                kind=ChangeKind.ADDED,
                category=DiffCategory.FUNCTION,
                subject=function_id,
                label=_function_label(function, names.get(function.contract_id, "?")),
                after=f"{function.visibility.value} {function.mutability.value}",
            )
        )
    for function_id in sorted(old.keys() - new.keys()):
        function = old[function_id]
        entries.append(
            DiffEntry(
                id=f"function:removed:{function_id}",
                kind=ChangeKind.REMOVED,
                category=DiffCategory.FUNCTION,
                subject=function_id,
                label=_function_label(function, names.get(function.contract_id, "?")),
                before=f"{function.visibility.value} {function.mutability.value}",
            )
        )
    unchanged["functions"] = len(old.keys() & new.keys())
    return entries


def _diff_access(
    before: AnalysisResult, after: AnalysisResult, unchanged: dict[str, int]
) -> list[DiffEntry]:
    old = {function.id: function for function in before.functions}
    new = {function.id: function for function in after.functions}
    names = _names(before, after)
    entries: list[DiffEntry] = []

    for function_id in sorted(old.keys() & new.keys()):
        old_function, new_function = old[function_id], new[function_id]
        if old_function.access.restriction == new_function.access.restriction and sorted(
            old_function.access.roles
        ) == sorted(new_function.access.roles):
            continue
        entries.append(
            DiffEntry(
                id=f"access:{function_id}",
                kind=ChangeKind.CHANGED,
                category=DiffCategory.ACCESS,
                subject=function_id,
                label=_function_label(new_function, names.get(new_function.contract_id, "?")),
                before=_describe_access(old_function),
                after=_describe_access(new_function),
            )
        )
    unchanged["access"] = len(old.keys() & new.keys())
    return entries


def _diff_roles(
    before: AnalysisResult, after: AnalysisResult, unchanged: dict[str, int]
) -> list[DiffEntry]:
    old = {role.id: role for role in before.roles}
    new = {role.id: role for role in after.roles}
    entries: list[DiffEntry] = []
    for role_id in sorted(new.keys() - old.keys()):
        role = new[role_id]
        entries.append(
            DiffEntry(
                id=f"role:added:{role_id}",
                kind=ChangeKind.ADDED,
                category=DiffCategory.ROLE,
                subject=role_id,
                label=role.name,
                after=role.kind,
            )
        )
    for role_id in sorted(old.keys() - new.keys()):
        role = old[role_id]
        entries.append(
            DiffEntry(
                id=f"role:removed:{role_id}",
                kind=ChangeKind.REMOVED,
                category=DiffCategory.ROLE,
                subject=role_id,
                label=role.name,
                before=role.kind,
            )
        )
    unchanged["roles"] = len(old.keys() & new.keys())
    return entries


def _diff_observations(
    before: AnalysisResult, after: AnalysisResult, unchanged: dict[str, int]
) -> list[DiffEntry]:
    old = {obs.id: obs for obs in before.observations}
    new = {obs.id: obs for obs in after.observations}
    entries: list[DiffEntry] = []
    for obs_id in sorted(new.keys() - old.keys()):
        observation = new[obs_id]
        entries.append(
            DiffEntry(
                id=f"observation:added:{obs_id}",
                kind=ChangeKind.ADDED,
                category=DiffCategory.OBSERVATION,
                subject=observation.subject,
                label=observation.title,
                after=observation.category,
            )
        )
    for obs_id in sorted(old.keys() - new.keys()):
        observation = old[obs_id]
        entries.append(
            DiffEntry(
                id=f"observation:removed:{obs_id}",
                kind=ChangeKind.REMOVED,
                category=DiffCategory.OBSERVATION,
                subject=observation.subject,
                label=observation.title,
                before=observation.category,
            )
        )
    unchanged["observations"] = len(old.keys() & new.keys())
    return entries


def _describe_edge(kind: str, source: str, target: str, labels: dict[str, str]) -> str:
    return f"{labels.get(source, source)} --{kind}--> {labels.get(target, target)}"


def _diff_edges(
    before: AnalysisResult, after: AnalysisResult, unchanged: dict[str, int]
) -> list[DiffEntry]:
    old = {edge.id: edge for edge in before.edges}
    new = {edge.id: edge for edge in after.edges}
    labels = {node.id: node.label for node in [*before.nodes, *after.nodes]}
    entries: list[DiffEntry] = []
    for edge_id in sorted(new.keys() - old.keys()):
        edge = new[edge_id]
        entries.append(
            DiffEntry(
                id=f"edge:added:{edge_id}",
                kind=ChangeKind.ADDED,
                category=DiffCategory.EDGE,
                subject=edge.source,
                label=_describe_edge(edge.kind.value, edge.source, edge.target, labels),
                after=edge.resolution.value,
            )
        )
    for edge_id in sorted(old.keys() - new.keys()):
        edge = old[edge_id]
        entries.append(
            DiffEntry(
                id=f"edge:removed:{edge_id}",
                kind=ChangeKind.REMOVED,
                category=DiffCategory.EDGE,
                subject=edge.source,
                label=_describe_edge(edge.kind.value, edge.source, edge.target, labels),
                before=edge.resolution.value,
            )
        )
    unchanged["edges"] = len(old.keys() & new.keys())
    return entries
