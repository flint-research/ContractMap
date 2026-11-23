"""Graph construction from analysed contracts.

The builder owns node/edge deduplication, the node budget and nothing else. It is
deliberately free of rendering concerns so it can be reused by the HTML viewer,
the DOT exporter and the diff engine.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence

from contractmap.models import (
    AnalysisResult,
    ChainInfo,
    ContractModel,
    Edge,
    EdgeKind,
    Evidence,
    FunctionModel,
    Metadata,
    Node,
    NodeKind,
    Observation,
    Resolution,
    RoleModel,
    TargetInfo,
    WarningItem,
)

KIND_ORDER = {
    NodeKind.PROXY: 0,
    NodeKind.IMPLEMENTATION: 1,
    NodeKind.FACET: 2,
    NodeKind.BEACON: 3,
    NodeKind.CONTRACT: 4,
    NodeKind.LIBRARY: 5,
    NodeKind.ROLE: 6,
    NodeKind.PRIVILEGED_ACCOUNT: 7,
    NodeKind.EXTERNAL_TARGET: 8,
    NodeKind.FUNCTION: 9,
}


class GraphBuilder:
    def __init__(self, max_nodes: int = 400) -> None:
        self.max_nodes = max_nodes
        self._nodes: dict[str, Node] = {}
        self._edges: dict[str, Edge] = {}
        self._truncated = False
        self._warnings: list[WarningItem] = []

    @property
    def nodes(self) -> list[Node]:
        return sorted(self._nodes.values(), key=lambda n: (KIND_ORDER.get(n.kind, 99), n.id))

    @property
    def edges(self) -> list[Edge]:
        return sorted(self._edges.values(), key=lambda e: e.id)

    @property
    def warnings(self) -> list[WarningItem]:
        return list(self._warnings)

    def warn(
        self, code: str, message: str, subject: str | None = None, *, partial: bool = False
    ) -> None:
        """Record a warning. ``partial`` marks the analysis incomplete (exit code 4)."""

        self._truncated = self._truncated or partial
        self._warnings.append(WarningItem(code=code, message=message, subject=subject))

    def has_room(self) -> bool:
        return len(self._nodes) < self.max_nodes

    def add_node(self, node: Node) -> bool:
        if node.id in self._nodes:
            return True
        if len(self._nodes) >= self.max_nodes:
            if not self._truncated:
                self._truncated = True
                self.warn(
                    "graph_truncated",
                    f"node budget of {self.max_nodes} reached; remaining nodes were dropped",
                )
            return False
        self._nodes[node.id] = node
        return True

    def add_edge(
        self,
        kind: EdgeKind,
        source: str,
        target: str,
        *,
        label: str | None = None,
        resolution: Resolution = Resolution.CONFIRMED,
        confidence: float = 1.0,
        evidence: Iterable[Evidence] = (),
    ) -> bool:
        if source not in self._nodes or target not in self._nodes:
            return False
        edge_id = f"{kind.value}:{source}->{target}" + (f":{label}" if label else "")
        if edge_id in self._edges:
            existing = self._edges[edge_id]
            if resolution == Resolution.CONFIRMED and existing.resolution != Resolution.CONFIRMED:
                existing.resolution = resolution
                existing.confidence = max(existing.confidence, confidence)
                existing.evidence.extend(evidence)
            return True
        self._edges[edge_id] = Edge(
            id=edge_id,
            kind=kind,
            source=source,
            target=target,
            label=label,
            resolution=resolution,
            confidence=confidence,
            evidence=list(evidence),
        )
        return True

    def contract_node(
        self,
        contract: ContractModel,
        kind: NodeKind | None = None,
        label: str | None = None,
        detail: str | None = None,
    ) -> str:
        resolved_kind = kind or _default_node_kind(contract)
        attributes: dict[str, str] = {}
        if contract.proxy is not None:
            attributes["proxy_kind"] = str(contract.proxy.kind)
            attributes["resolution"] = str(contract.proxy.resolution)
        if contract.compiler_version:
            attributes["compiler"] = contract.compiler_version
        attributes["source"] = str(contract.source_kind)
        node_id = _node_key(contract.id, resolved_kind)
        self.add_node(
            Node(
                id=node_id,
                kind=resolved_kind,
                label=label or contract.name,
                contract_id=contract.id,
                address=contract.address,
                detail=detail,
                attributes=attributes,
            )
        )
        return node_id

    def result(
        self,
        *,
        target: TargetInfo,
        chain: ChainInfo,
        metadata: Metadata,
        contracts: Sequence[ContractModel],
        functions: Sequence[FunctionModel],
        roles: Sequence[RoleModel],
        observations: Sequence[Observation],
    ) -> AnalysisResult:
        complete = not self._truncated
        result = AnalysisResult(
            target=target,
            chain=chain,
            metadata=metadata.model_copy(update={"analysis_complete": complete}),
            contracts=sorted(contracts, key=lambda c: c.id),
            functions=sorted(functions, key=lambda f: f.id),
            roles=sorted(roles, key=lambda r: r.id),
            nodes=self.nodes,
            edges=self.edges,
            observations=sorted(observations, key=lambda o: o.id),
            warnings=self.warnings,
        )
        result.metadata.digest = result.digest()
        return result


def _node_key(contract_id: str, kind: NodeKind) -> str:
    return f"node:{kind.value}:{contract_id}"


def _default_node_kind(contract: ContractModel) -> NodeKind:
    if contract.kind.value == "library":
        return NodeKind.LIBRARY
    proxy = contract.proxy
    if proxy is not None and (proxy.implementation or proxy.beacon or proxy.facets):
        return NodeKind.PROXY
    if contract.address:
        return NodeKind.CONTRACT
    return NodeKind.CONTRACT
