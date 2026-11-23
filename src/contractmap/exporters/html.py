"""Offline interactive HTML report.

The page is fully self-contained: CSS and JavaScript are inlined from the package
resources, there is no CDN reference and no third-party bundle. The analysis JSON
is embedded in a ``<script type="application/json">`` block, so contract names and
metadata cannot break out into executable markup.
"""

from __future__ import annotations

import html
import json
from importlib import resources

from contractmap.models import AnalysisResult

_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>__TITLE__</title>
<style>
__STYLE__
</style>
</head>
<body>
<header class="bar">
  <span class="product">ContractMap</span>
  <span class="target mono">__TARGET__</span>
  <span class="facts">__FACTS__</span>
  <button type="button" class="quiet" id="print">Print report</button>
</header>
<nav class="legend" id="legend" aria-label="Tick mark legend and filters"></nav>
<div class="banner" id="banner" hidden></div>
<div class="layout">
  <aside class="rail" aria-label="Contracts">
    <label class="search"><span class="sr">Filter functions</span>
      <input id="search" type="search" autocomplete="off" spellcheck="false"
             placeholder="Filter by function, role or state">
    </label>
    <div id="contracts"></div>
  </aside>
  <main class="work">
    <div class="tabs" role="tablist" aria-label="Views">
      <button type="button" role="tab" id="tab-register" aria-controls="register"
              aria-selected="true">Register</button>
      <button type="button" role="tab" id="tab-map" aria-controls="map"
              aria-selected="false">Map</button>
      <label class="toggle"><input type="checkbox" id="changing" checked>
        State-changing only</label>
    </div>
    <section id="register" role="tabpanel" aria-labelledby="tab-register"></section>
    <section id="map" role="tabpanel" aria-labelledby="tab-map" hidden>
      <svg id="plan" role="img" aria-label="Map of contracts, their functions and links"
           xmlns="http://www.w3.org/2000/svg"><g id="viewport"></g></svg>
      <div class="map-tools" aria-label="Map controls">
        <button type="button" id="zoom-in" aria-label="Zoom in">+</button>
        <button type="button" id="zoom-out" aria-label="Zoom out">&minus;</button>
        <button type="button" id="zoom-fit">Fit</button>
        <button type="button" id="export-svg">Save SVG</button>
      </div>
      <p class="map-key" id="map-key"></p>
    </section>
  </main>
  <aside class="detail" id="detail" aria-live="polite" aria-label="Selection"></aside>
</div>
<script id="analysis" type="application/json">__DATA__</script>
<script>
__SCRIPT__
</script>
</body>
</html>
"""


def _asset(name: str) -> str:
    return resources.files("contractmap.viewer").joinpath(name).read_text(encoding="utf-8")


def _facts(result: AnalysisResult) -> str:
    pieces: list[str] = []
    if result.chain.chain_id is not None:
        pieces.append(f"chain {result.chain.chain_id}")
    if result.chain.block_number is not None:
        pieces.append(f"block {result.chain.block_number}")
    if result.target.build_system:
        pieces.append(result.target.build_system)
    if result.metadata.compiler:
        pieces.append(f"solc {result.metadata.compiler.split('+')[0]}")
    pieces.append(f"{len(result.contracts)} contracts")
    if not result.metadata.analysis_complete:
        pieces.append("partial")
    return " · ".join(pieces)


def _payload(result: AnalysisResult) -> str:
    # The whole analysis: the report shows every function's evidence, writes and
    # roles, not only the graph. The priority order is the one terminal and
    # Markdown use, so all three list findings the same way.
    data = result.sorted_copy().model_dump(mode="json")
    data["observation_order"] = [o.id for o in result.observations_by_priority()]
    text = json.dumps(data, ensure_ascii=False, sort_keys=True)
    # ``</`` inside a script block ends it early; JSON escapes make this safe.
    return text.replace("</", "<\\/")


def to_html(result: AnalysisResult, *, title: str | None = None) -> str:
    heading = title or f"ContractMap · {result.target.identifier}"
    replacements = {
        "__TITLE__": html.escape(heading),
        "__TARGET__": html.escape(result.target.identifier),
        "__FACTS__": html.escape(_facts(result)),
        "__STYLE__": _asset("app.css"),
        "__SCRIPT__": _asset("app.js"),
        "__DATA__": _payload(result),
    }
    page = _TEMPLATE
    for placeholder, value in replacements.items():
        page = page.replace(placeholder, value)
    return page
