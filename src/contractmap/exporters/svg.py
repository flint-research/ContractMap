"""Dependency-free SVG rendering.

Layout is deliberately simple: nodes are stacked into columns by their role in the
system (proxy, beacon, implementation, contract, function, role). Deterministic
input ordering gives deterministic output, which keeps golden-file tests stable.
"""

from __future__ import annotations

from dataclasses import dataclass

from contractmap.models import AnalysisResult, EdgeKind, NodeKind, Resolution

COLUMN_ORDER = (
    NodeKind.PROXY,
    NodeKind.BEACON,
    NodeKind.IMPLEMENTATION,
    NodeKind.FACET,
    NodeKind.CONTRACT,
    NodeKind.LIBRARY,
    NodeKind.ROLE,
    NodeKind.PRIVILEGED_ACCOUNT,
    NodeKind.EXTERNAL_TARGET,
    NodeKind.FUNCTION,
)

PALETTE = {
    NodeKind.PROXY: ("#1d2a3f", "#5b8def"),
    NodeKind.BEACON: ("#2a2335", "#a479e8"),
    NodeKind.IMPLEMENTATION: ("#1b2f2a", "#3ec9a0"),
    NodeKind.FACET: ("#2c2a1d", "#d3b354"),
    NodeKind.CONTRACT: ("#1b1f29", "#48536b"),
    NodeKind.LIBRARY: ("#22201b", "#9a8f6b"),
    NodeKind.ROLE: ("#2b1f24", "#e0698a"),
    NodeKind.PRIVILEGED_ACCOUNT: ("#26191e", "#c9647c"),
    NodeKind.EXTERNAL_TARGET: ("#1a1c22", "#6b7488"),
    NodeKind.FUNCTION: ("#14161c", "#3d4557"),
}

NODE_WIDTH = 210
NODE_HEIGHT = 42
COLUMN_GAP = 90
ROW_GAP = 16
MARGIN = 40


@dataclass(slots=True)
class Placed:
    node_id: str
    label: str
    kind: NodeKind
    x: float
    y: float
    w: float
    h: float


def layout(result: AnalysisResult) -> tuple[list[Placed], int, int]:
    by_kind: dict[NodeKind, list[str]] = {}
    for node in result.nodes:
        by_kind.setdefault(node.kind, []).append(node.id)

    index = {node.id: node for node in result.nodes}
    placed: list[Placed] = []
    cursor_x = float(MARGIN)
    tallest = 1

    for kind in COLUMN_ORDER:
        ids = by_kind.get(kind, [])
        if not ids:
            continue
        width = NODE_WIDTH if kind != NodeKind.FUNCTION else NODE_WIDTH + 40
        y = float(MARGIN)
        for node_id in ids:
            placed.append(
                Placed(
                    node_id=node_id,
                    label=index[node_id].label,
                    kind=kind,
                    x=cursor_x,
                    y=y,
                    w=width,
                    h=NODE_HEIGHT,
                )
            )
            y += NODE_HEIGHT + ROW_GAP
        tallest = max(tallest, len(ids))
        cursor_x += width + COLUMN_GAP

    width = int(max(cursor_x + MARGIN - COLUMN_GAP, MARGIN * 2 + NODE_WIDTH))
    height = int(max(tallest * (NODE_HEIGHT + ROW_GAP) + MARGIN * 2, 240))
    return placed, width, height


def _escape(text: str) -> str:
    return (
        text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
    )


def _elide(text: str, limit: int = 30) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "\u2026"


def _edge_path(source: Placed, target: Placed) -> tuple[str, bool]:
    if source.x <= target.x:
        x1, x2 = source.x + source.w, target.x
    else:
        x1, x2 = source.x, target.x + target.w
    y1, y2 = source.y + source.h / 2, target.y + target.h / 2
    curvature = max(40.0, abs(x2 - x1) * 0.4)
    direction = 1 if x2 >= x1 else -1
    path = (
        f"M {x1:.1f} {y1:.1f} C {x1 + curvature * direction:.1f} {y1:.1f}, "
        f"{x2 - curvature * direction:.1f} {y2:.1f}, {x2:.1f} {y2:.1f}"
    )
    return path, source.x > target.x


def render_svg(result: AnalysisResult, *, title: str | None = None) -> str:
    placed, width, height = layout(result)
    positions = {item.node_id: item for item in placed}
    heading = _escape(title or f"contractmap: {result.target.identifier}")

    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}" font-family="Helvetica, Arial, sans-serif">',
        f"<title>{heading}</title>",
        f'<rect width="{width}" height="{height}" fill="#0f1218"/>',
        "<defs>",
        '<marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" '
        'markerHeight="7" orient="auto-start-reverse">',
        '<path d="M 0 0 L 10 5 L 0 10 z" fill="#5c657a"/>',
        "</marker>",
        '<marker id="arrow-unresolved" viewBox="0 0 10 10" refX="9" refY="5" '
        'markerWidth="7" markerHeight="7" orient="auto-start-reverse">',
        '<path d="M 0 0 L 10 5 L 0 10 z" fill="#a6803f"/>',
        "</marker>",
        "</defs>",
    ]

    for edge in result.edges:
        source, target = positions.get(edge.source), positions.get(edge.target)
        if source is None or target is None:
            continue
        path, reversed_layout = _edge_path(source, target)
        confirmed = edge.resolution == Resolution.CONFIRMED
        colour = "#5c657a" if confirmed else "#a6803f"
        dash = ' stroke-dasharray="4 3"' if reversed_layout or not confirmed else ""
        marker = "arrow" if confirmed else "arrow-unresolved"
        parts.append(
            f'<path d="{path}" fill="none" stroke="{colour}" stroke-width="1.3"{dash} '
            f'marker-end="url(#{marker})" opacity="0.85"/>'
        )

    for item in placed:
        fill, stroke = PALETTE.get(item.kind, ("#1b1f29", "#48536b"))
        parts.append(
            f'<g><rect x="{item.x:.1f}" y="{item.y:.1f}" width="{item.w}" height="{item.h}" '
            f'rx="6" fill="{fill}" stroke="{stroke}" stroke-width="1.4"/>'
            f'<text x="{item.x + 12:.1f}" y="{item.y + 18:.1f}" fill="#e6e9ef" '
            f'font-size="12">{_escape(_elide(item.label, 32))}</text>'
            f'<text x="{item.x + 12:.1f}" y="{item.y + 32:.1f}" fill="#7b8598" '
            f'font-size="9">{item.kind.value}</text></g>'
        )

    parts.append("</svg>")
    return "\n".join(parts) + "\n"


def edge_style(kind: EdgeKind) -> str:
    return kind.value
