"""Graphviz DOT export.

The DOT document is a straight projection of the canonical graph, so the image
produced by ``dot`` and the HTML viewer show the same nodes and edges.
"""

from __future__ import annotations

from contractmap.models import AnalysisResult, EdgeKind, NodeKind, Resolution

SHAPES = {
    NodeKind.PROXY: "component",
    NodeKind.IMPLEMENTATION: "box3d",
    NodeKind.BEACON: "hexagon",
    NodeKind.FACET: "folder",
    NodeKind.CONTRACT: "box",
    NodeKind.LIBRARY: "tab",
    NodeKind.ROLE: "octagon",
    NodeKind.PRIVILEGED_ACCOUNT: "ellipse",
    NodeKind.EXTERNAL_TARGET: "note",
    NodeKind.FUNCTION: "plaintext",
}

STYLES = {
    EdgeKind.PROXIES_TO: ("bold", "solid"),
    EdgeKind.RESOLVES_VIA_BEACON: ("bold", "dashed"),
    EdgeKind.HAS_FACET: ("solid", "dotted"),
    EdgeKind.DELEGATECALLS: ("bold", "dashed"),
    EdgeKind.CONTROLLED_BY: ("bold", "dotted"),
    EdgeKind.PROTECTED_BY: ("solid", "dotted"),
    EdgeKind.INHERITS: ("solid", "solid"),
    EdgeKind.IMPLEMENTS: ("dashed", "solid"),
    EdgeKind.EXPOSES: ("", "solid"),
}


def _quote(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")
    return f'"{escaped}"'


def to_dot(result: AnalysisResult, *, title: str | None = None) -> str:
    heading = title or f"contractmap: {result.target.identifier}"
    lines = [
        "digraph contractmap {",
        '  graph [rankdir=LR, fontname="Helvetica", bgcolor="#12151c", '
        'fontcolor="#e6e9ef", labelloc=t, pad=0.4, nodesep=0.35, ranksep=0.9];',
        '  node [fontname="Helvetica", fontsize=10, style="filled", '
        'fillcolor="#1b1f29", color="#3d4557", fontcolor="#e6e9ef"];',
        '  edge [fontname="Helvetica", fontsize=8, color="#5c657a", fontcolor="#9aa4b8"];',
        f"  label={_quote(heading)};",
        "",
    ]

    for node in result.nodes:
        attributes = {
            "label": node.label,
            "shape": SHAPES.get(node.kind, "box"),
        }
        if node.kind == NodeKind.FUNCTION:
            attributes["fontcolor"] = "#9aa4b8"
        if node.kind == NodeKind.EXTERNAL_TARGET:
            attributes["style"] = "filled,dashed"
        if node.kind in (NodeKind.PROXY, NodeKind.IMPLEMENTATION, NodeKind.BEACON, NodeKind.FACET):
            attributes["penwidth"] = "2"
        lines.append(f"  {_quote(node.id)} [{_attributes(attributes)}];")

    lines.append("")
    for edge in result.edges:
        style, line_style = STYLES.get(edge.kind, ("", "solid"))
        attributes = {
            "color": "#7f8ba3" if edge.resolution == Resolution.CONFIRMED else "#a6803f",
        }
        if style:
            attributes["style"] = style
        if line_style and line_style != "solid":
            attributes["style"] = line_style
        label = edge.label or edge.kind.value
        if len(label) > 48:
            label = label[:45] + "..."
        attributes["label"] = label
        if edge.resolution == Resolution.UNRESOLVED:
            attributes["style"] = "dotted"
        lines.append(
            f"  {_quote(edge.source)} -> {_quote(edge.target)} [{_attributes(attributes)}];"
        )

    lines.append("}")
    return "\n".join(lines) + "\n"


def _attributes(values: dict[str, str]) -> str:
    return ", ".join(f"{key}={_quote(str(value))}" for key, value in sorted(values.items()))
