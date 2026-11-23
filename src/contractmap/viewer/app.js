(function () {
  "use strict";

  const data = JSON.parse(document.getElementById("analysis").textContent);
  const SVGNS = "http://www.w3.org/2000/svg";

  // One legend for the whole report. Order is severity for sorting.
  const GRADES = [
    { key: "none_identified", label: "Open", what: "No guard: anyone can call", term: "no guard found" },
    { key: "inferred", label: "Named, not traced", what: "A guard exists; who passes is unknown", term: "likely restricted" },
    { key: "unresolved", label: "No source", what: "Not read; not the same as open", term: "unresolved" },
    { key: "confirmed", label: "Verified", what: "Guard found in the source", term: "restricted" }
  ];
  const GRADE = {};
  GRADES.forEach(function (g, i) { g.rank = i; GRADE[g.key] = g; });
  // Findings drawn in red pencil: paths to takeover. Everything else is context.
  const EXCEPTIONS = new Set(["unguarded_dangerous_operation", "unguarded_privileged_write", "administrative_function"]);
  const BASE_KINDS = new Set(["abstract", "interface", "library"]);
  const ROW_LIMIT = 400;

  const state = { grade: null, exceptions: false, contract: null, query: "", changing: true, sort: { key: "ref", dir: 1 }, all: false };
  let selection = null;

  function esc(text) {
    return String(text == null ? "" : text).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }
  function pad(n) { return n < 10 ? "0" + n : String(n); }
  // Signatures wrap after an opening bracket or a comma, never inside a type name.
  function sig(text) { return esc(text).replace(/([(,])/g, "$1<wbr>"); }

  // ---- Model: stable references, exceptions, lookups ----------------------
  const contracts = data.contracts.slice().sort(function (a, b) {
    const ba = BASE_KINDS.has(a.kind) ? 1 : 0;
    const bb = BASE_KINDS.has(b.kind) ? 1 : 0;
    return ba - bb || a.name.localeCompare(b.name) || a.id.localeCompare(b.id);
  });
  const contractById = new Map();
  contracts.forEach(function (c, i) {
    c.ref = "C" + (i + 1);
    c.base = BASE_KINDS.has(c.kind);
    c.fns = [];
    c.findings = [];
    contractById.set(c.id, c);
  });
  const anyDeployable = contracts.some(function (c) { return !c.base; });

  const fns = [];
  const fnByKey = new Map();
  const fnById = new Map();
  data.functions.forEach(function (f) {
    const isEntry = !f.is_constructor && (f.visibility === "public" || f.visibility === "external");
    const owner = contractById.get(f.contract_id);
    if (!isEntry || !owner) { return; }
    f.owner = owner;
    f.grade = GRADE[f.access.restriction] ? f.access.restriction : "unresolved";
    f.changing = f.mutability !== "view" && f.mutability !== "pure";
    f.findings = [];
    f.exception = false;
    owner.fns.push(f);
    fnByKey.set(f.contract_id + "|" + f.signature, f);
    fnById.set(f.id, f);
    fns.push(f);
  });
  contracts.forEach(function (c) {
    c.fns.sort(function (a, b) { return a.name.localeCompare(b.name) || a.signature.localeCompare(b.signature); });
    c.fns.forEach(function (f, i) { f.ref = c.ref + "." + pad(i + 1); });
  });

  const order = new Map((data.observation_order || []).map(function (id, i) { return [id, i]; }));
  const findings = data.observations.slice().sort(function (a, b) {
    return (order.has(a.id) ? order.get(a.id) : 1e9) - (order.has(b.id) ? order.get(b.id) : 1e9);
  });
  let exceptionCount = 0;
  let noteCount = 0;
  findings.forEach(function (o) {
    o.exception = EXCEPTIONS.has(o.category);
    o.ref = o.exception ? "E" + (++exceptionCount) : "N" + (++noteCount);
    o.owner = contractById.get(o.subject) || null;
    if (o.owner) { o.owner.findings.push(o); }
    o.fns = [];
    o.evidence.forEach(function (e) {
      if (e.kind !== "function") { return; }
      const f = fnByKey.get(o.subject + "|" + e.detail);
      if (!f) { return; }
      o.fns.push(f);
      f.findings.push(o);
      if (o.exception) { f.exception = true; }
    });
  });
  const refIndex = new Map();
  contracts.forEach(function (c) { refIndex.set(c.ref, { type: "contract", item: c }); });
  fns.forEach(function (f) { refIndex.set(f.ref, { type: "fn", item: f }); });
  findings.forEach(function (o) { refIndex.set(o.ref, { type: "finding", item: o }); });

  function who(f) {
    if (f.grade === "none_identified") { return "anyone"; }
    if (f.grade === "unresolved") { return "unknown"; }
    const roles = f.access.roles.filter(function (r) { return r !== "role"; });
    if (roles.length) { return roles.join(", "); }
    return f.access.modifiers.join(", ") || "a guarded caller";
  }

  // ---- Tick marks (authored SVG) -----------------------------------------
  const PENCIL = '<path class="pencil" d="M4 6.5C7.5 1 19.5 1.6 21.4 9.6c1.6 7-8.4 12.3-15.6 9.4C1.4 17.2 0.6 11.6 3.6 8.2"/>';
  function tick(grade, exception, size) {
    const s = size || 20;
    let body = "";
    if (grade === "confirmed") {
      body = '<path d="M6 12.5l4 4 8-10" fill="none" stroke="#1e6b45" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"/>';
    } else if (grade === "inferred") {
      body = '<path d="M6 12.5l4 4 8-10" fill="none" stroke="#2b5c8a" stroke-width="2.2" stroke-linecap="round" stroke-dasharray="3.2 2.6"/>';
    } else if (grade === "none_identified") {
      body = '<path d="M8 17.5L16 6.5" stroke="#202326" stroke-width="2.4" stroke-linecap="round"/><path d="M6.5 12h11" stroke="#202326" stroke-width="2.4" stroke-linecap="round"/>';
    } else {
      body = '<circle cx="12" cy="12" r="6" fill="none" stroke="#7d848a" stroke-width="1.8" stroke-dasharray="1.5 2.6" stroke-linecap="round"/>';
    }
    return '<svg class="tickmark" width="' + s + '" height="' + s + '" viewBox="0 0 24 24" aria-hidden="true">' +
      body + (exception ? PENCIL : "") + "</svg>";
  }

  // ---- Filtering ----------------------------------------------------------
  function scope(f) {
    if (state.contract) { return f.owner.id === state.contract; }
    return !anyDeployable || !f.owner.base;
  }
  function matches(f) {
    if (!scope(f)) { return false; }
    if (state.changing && !f.changing) { return false; }
    if (state.grade && f.grade !== state.grade) { return false; }
    if (state.exceptions && !f.exception) { return false; }
    if (state.query) {
      const hay = [f.ref, f.owner.name, f.signature, f.selector, who(f), f.writes.join(" "),
        f.access.modifiers.join(" "), f.declared_in].join(" ").toLowerCase();
      if (hay.indexOf(state.query) === -1) { return false; }
    }
    return true;
  }
  function filtering() { return Boolean(state.grade || state.exceptions || state.contract || state.query); }

  // ---- Legend -------------------------------------------------------------
  const legend = document.getElementById("legend");
  function renderLegend() {
    const inScope = fns.filter(function (f) { return scope(f) && (!state.changing || f.changing); });
    const items = GRADES.slice().reverse().map(function (g) {
      const n = inScope.filter(function (f) { return f.grade === g.key; }).length;
      return '<button type="button" data-grade="' + g.key + '" aria-pressed="' + (state.grade === g.key) + '">' +
        tick(g.key, false, 24) + '<span class="label">' + esc(g.label) + '<span class="count">' + n + "</span></span>" +
        '<span class="what">' + esc(g.what) + "</span></button>";
    });
    const ex = inScope.filter(function (f) { return f.exception; }).length;
    items.push('<button type="button" class="exception" data-exceptions="1" aria-pressed="' + state.exceptions + '">' +
      tick("none_identified", true, 24) + '<span class="label">Exception<span class="count">' + ex + "</span></span>" +
      '<span class="what">Circled: named in a takeover finding</span></button>');
    if (filtering()) { items.push('<button type="button" class="clear" data-clear="1">Clear filters</button>'); }
    legend.innerHTML = items.join("");
  }
  legend.addEventListener("click", function (event) {
    const button = event.target.closest("button");
    if (!button) { return; }
    if (button.dataset.clear) {
      state.grade = null; state.exceptions = false; state.contract = null; state.query = "";
      document.getElementById("search").value = "";
    } else if (button.dataset.exceptions) {
      state.exceptions = !state.exceptions;
    } else {
      state.grade = state.grade === button.dataset.grade ? null : button.dataset.grade;
    }
    refresh();
  });

  // ---- Contracts rail -----------------------------------------------------
  const rail = document.getElementById("contracts");
  function tally(list) {
    const parts = GRADES.slice().reverse().map(function (g) {
      const n = list.filter(function (f) { return f.grade === g.key; }).length;
      return n ? "<span title=\"" + esc(g.label) + "\">" + tick(g.key, false, 14) + n + "</span>" : "";
    });
    const ex = list.filter(function (f) { return f.exception; }).length;
    if (ex) { parts.push('<span class="ex" title="Exceptions">' + ex + " exc.</span>"); }
    return parts.join("");
  }
  function renderRail() {
    let html = "";
    let lastBase = null;
    contracts.forEach(function (c) {
      if (c.base !== lastBase) {
        html += '<div class="group">' + (c.base ? "Bases, interfaces, libraries" : "Deployable") + "</div>";
        lastBase = c.base;
      }
      const list = c.fns.filter(function (f) { return !state.changing || f.changing; });
      html += '<button type="button" class="contract" data-contract="' + esc(c.id) + '" aria-pressed="' + (state.contract === c.id) + '">' +
        '<span class="ref mono">' + c.ref + '</span><span class="name">' + esc(c.name) + '</span><span class="kind">' +
        esc(c.proxy && c.proxy.kind !== "unknown" ? c.proxy.kind : c.kind) + "</span>" +
        '<span class="tally">' + (tally(list) || "no entry points") + "</span></button>";
    });
    rail.innerHTML = html || '<p class="empty">No contracts in this analysis.</p>';
  }
  rail.addEventListener("click", function (event) {
    const button = event.target.closest("[data-contract]");
    if (!button) { return; }
    const id = button.dataset.contract;
    state.contract = state.contract === id ? null : id;
    refresh();
    if (state.contract) { select({ type: "contract", item: contractById.get(id) }); }
  });

  // ---- Register -----------------------------------------------------------
  const register = document.getElementById("register");
  const SORTS = {
    tick: function (f) { return [GRADE[f.grade].rank, f.exception ? 0 : 1]; },
    ref: function (f) { return [contracts.indexOf(f.owner), f.ref]; },
    fn: function (f) { return [f.name.toLowerCase(), f.signature]; },
    who: function (f) { return [who(f)]; },
    writes: function (f) { return [f.writes.length ? 0 : 1, f.writes.join(",")]; },
    from: function (f) { return [f.declared_in || "", f.ref]; }
  };
  function compare(a, b) {
    const key = SORTS[state.sort.key];
    const x = key(a);
    const y = key(b);
    for (let i = 0; i < x.length; i++) {
      if (x[i] < y[i]) { return -state.sort.dir; }
      if (x[i] > y[i]) { return state.sort.dir; }
    }
    return a.ref < b.ref ? -1 : 1;
  }
  function findingRow(o) {
    const chips = o.fns.map(function (f) {
      return '<button type="button" class="chip" data-ref="' + f.ref + '">' + esc(f.ref + " " + f.signature) + "</button>";
    }).join("");
    return '<li class="finding' + (o.exception ? " exception" : "") + '"><span class="ref">' + o.ref + "</span>" +
      '<span><button type="button" class="title" data-ref="' + o.ref + '">' + esc(o.title) + "</button><br>" +
      '<span class="where">' + esc(o.owner ? o.owner.name : "Whole system") + "</span></span>" +
      '<span class="res">' + esc(o.resolution) + "</span>" + (chips ? '<span class="fns">' + chips + "</span>" : "") + "</li>";
  }
  function header(key, label) {
    const sort = state.sort.key === key ? (state.sort.dir > 0 ? "ascending" : "descending") : "none";
    return '<th aria-sort="' + sort + '"><button type="button" data-sort="' + key + '">' + label + "</button></th>";
  }
  function renderRegister() {
    const relevant = function (o) {
      return (!state.contract || (o.owner && o.owner.id === state.contract)) &&
        (!state.exceptions || o.exception);
    };
    const exceptions = findings.filter(function (o) { return o.exception && relevant(o); });
    const notes = findings.filter(function (o) { return !o.exception && relevant(o); });
    const rows = fns.filter(matches).sort(compare);
    const total = fns.filter(scope).length;
    const shown = state.all ? rows : rows.slice(0, ROW_LIMIT);
    let html = "";

    html += "<h2>Exceptions</h2>";
    if (exceptions.length) {
      html += '<p class="lede">Functions anyone can call that change who controls the contract, reach <span class="mono">selfdestruct</span> or <span class="mono">delegatecall</span>, call an address the caller picks, or look administrative. Each one says where to look, not that something is broken.</p>';
      html += '<ul class="findings">' + exceptions.map(findingRow).join("") + "</ul>";
    } else {
      html += '<p class="lede">No exceptions recorded' + (filtering() ? " for this filter." : ". No function anyone can call was found taking control, destroying the contract or calling an address the caller picks.") + "</p>";
    }

    html += "<h2>Entry points</h2>";
    html += '<p class="lede">' + rows.length + " of " + total + " shown" +
      (state.changing ? ", view and pure functions hidden" : "") + ". Select a row to read its evidence.</p>";
    if (rows.length) {
      html += '<table class="ledger"><thead><tr>' + header("tick", '<span class="sr">Grade</span>') + header("ref", "Ref") +
        header("fn", "Function") + header("who", "Who can call") + header("writes", "Writes") + header("from", "Declared in") +
        "</tr></thead><tbody>";
      shown.forEach(function (f) {
        const selected = selection && selection.type === "fn" && selection.item === f;
        html += '<tr tabindex="0" data-ref="' + f.ref + '" aria-selected="' + Boolean(selected) + '"' + (f.exception ? ' class="exception"' : "") + ">" +
          '<td class="tick" title="' + esc(GRADE[f.grade].label) + '">' + tick(f.grade, f.exception, 22) + "</td>" +
          '<td class="mono">' + f.ref + "</td>" +
          '<td class="fn"><span class="mono"><b>' + esc(f.owner.name) + "</b>." + sig(f.signature) + "</span></td>" +
          '<td class="who' + (f.grade === "none_identified" ? " anyone" : "") + '">' + esc(who(f)) + "</td>" +
          '<td class="mono">' + (f.writes.length ? esc(f.writes.join(", ")) : "&ndash;") + "</td>" +
          "<td>" + (f.declared_in ? esc(f.declared_in) : '<span class="from">here</span>') + "</td></tr>";
      });
      html += "</tbody></table>";
      if (rows.length > shown.length) {
        html += '<button type="button" class="more" data-all="1">Show all ' + rows.length + " entry points</button>";
      }
    } else {
      html += '<p class="empty">No entry point matches. ' + (filtering() ? '<button type="button" class="linkish" data-clear="1">Clear filters</button>' : "") + "</p>";
    }

    if (notes.length) {
      html += "<h2>Notes</h2>";
      html += '<p class="lede">Context worth knowing during review: proxies, payable functions, external calls, dependencies.</p>';
      html += '<ul class="findings">' + notes.map(findingRow).join("") + "</ul>";
    }
    if (data.warnings.length) {
      html += "<h2>Warnings</h2>";
      html += '<ul class="findings">' + data.warnings.map(function (w, i) {
        return '<li class="finding"><span class="ref">W' + (i + 1) + "</span><span>" + esc(w.message) +
          '<br><span class="where mono">' + esc(w.code) + "</span></span><span></span></li>";
      }).join("") + "</ul>";
    }
    register.innerHTML = html;
  }
  register.addEventListener("click", function (event) {
    const sortButton = event.target.closest("[data-sort]");
    if (sortButton) {
      const key = sortButton.dataset.sort;
      state.sort = { key: key, dir: state.sort.key === key ? -state.sort.dir : 1 };
      renderRegister();
      return;
    }
    if (event.target.closest("[data-all]")) { state.all = true; renderRegister(); return; }
    if (event.target.closest("[data-clear]")) { legend.querySelector("[data-clear]").click(); return; }
    const target = event.target.closest("[data-ref]");
    if (target) { selectRef(target.dataset.ref); }
  });
  register.addEventListener("keydown", function (event) {
    const row = event.target.closest("tr[data-ref]");
    if (!row) { return; }
    if (event.key === "Enter" || event.key === " ") { event.preventDefault(); selectRef(row.dataset.ref); }
    if (event.key === "ArrowDown" || event.key === "ArrowUp") {
      event.preventDefault();
      const next = event.key === "ArrowDown" ? row.nextElementSibling : row.previousElementSibling;
      if (next) { next.focus(); selectRef(next.dataset.ref, true); }
    }
  });

  // ---- Map ----------------------------------------------------------------
  const svg = document.getElementById("plan");
  const viewport = document.getElementById("viewport");
  const anchors = new Map();
  const plots = new Map();
  const parcels = new Map();
  let view = { x: 0, y: 0, k: 1 };
  let bounds = { x: 0, y: 0, w: 1, h: 1 };
  let mapBuilt = false;

  function node(name, attrs, parent) {
    const el = document.createElementNS(SVGNS, name);
    Object.keys(attrs || {}).forEach(function (key) { el.setAttribute(key, attrs[key]); });
    if (parent) { parent.appendChild(el); }
    return el;
  }
  function short(text, limit) { return text.length > limit ? text.slice(0, limit - 1) + "…" : text; }

  function buildMap() {
    mapBuilt = true;
    viewport.textContent = "";
    const linkLayer = node("g", {}, viewport);
    const parcelLayer = node("g", {}, viewport);
    const shownContracts = contracts.filter(function (c) { return !c.base || c.fns.length || !anyDeployable; });
    const W = 316;
    const CELL = 26;
    const GAP = 40;
    // Lay out to the space the map has, so it opens readable rather than shrunk to fit.
    const usable = (svg.getBoundingClientRect().width || 1100) / 0.85;
    const columns = Math.max(1, Math.min(6, Math.floor((usable + GAP) / (W + GAP))));
    const heights = new Array(columns).fill(0);

    shownContracts.forEach(function (c) {
      const list = c.fns;
      const held = data.roles.filter(function (r) { return r.contract_id === c.id; }).map(function (r) { return r.name; });
      const HEAD = held.length ? 82 : 64;
      const h = HEAD + Math.max(1, list.length) * CELL + 12;
      let col = 0;
      for (let i = 1; i < columns; i++) { if (heights[i] < heights[col]) { col = i; } }
      const x = col * (W + GAP);
      const y = heights[col];
      heights[col] += h + GAP;
      const g = node("g", { class: "parcel" + (c.base ? " base" : ""), transform: "translate(" + x + "," + y + ")" }, parcelLayer);
      node("rect", { class: "parcel-frame", width: W, height: h, rx: 2 }, g);
      const title = node("text", { class: "parcel-title", x: 14, y: 24 }, g);
      title.textContent = c.ref + "  " + short(c.name, 28);
      const sub = node("text", { class: "parcel-sub", x: 14, y: 44 }, g);
      const proxy = c.proxy && c.proxy.kind !== "unknown" ? c.proxy.kind + " proxy" : c.kind;
      sub.textContent = proxy + " · " + list.length + " entry point" + (list.length === 1 ? "" : "s");
      if (held.length) {
        const holders = node("text", { class: "parcel-sub", x: 14, y: 64 }, g);
        holders.textContent = "Held by " + short(held.join(", "), 34);
      }
      node("line", { class: "parcel-rule", x1: 0, x2: W, y1: HEAD - 8, y2: HEAD - 8 }, g);
      g.addEventListener("click", function (event) {
        if (!event.target.closest(".plot")) { select({ type: "contract", item: c }); }
      });
      parcels.set(c.id, { g: g, x: x, y: y, w: W, h: h, c: c });
      anchors.set("c:" + c.id, { x: x, y: y, w: W, h: h });
      list.forEach(function (f, i) {
        const py = HEAD + i * CELL;
        const p = node("g", { class: "plot", transform: "translate(0," + py + ")", tabindex: "0", role: "button",
          "aria-label": f.ref + " " + c.name + "." + f.signature + ", " + GRADE[f.grade].label + (f.exception ? ", exception" : "") }, g);
        node("rect", { class: "hit", x: 4, y: 0, width: W - 8, height: CELL - 2, rx: 2 }, p);
        const holder = node("g", { transform: "translate(10,1)" }, p);
        holder.innerHTML = tick(f.grade, f.exception, 22).replace(/^<svg[^>]*>|<\/svg>$/g, "");
        holder.setAttribute("transform", "translate(10,1) scale(0.92)");
        const label = node("text", { x: 40, y: 17 }, p);
        label.textContent = short(f.signature, 34);
        const tip = node("title", {}, p);
        tip.textContent = f.ref + " " + c.name + "." + f.signature + " — " + who(f);
        p.addEventListener("click", function () { select({ type: "fn", item: f }); });
        p.addEventListener("keydown", function (event) {
          if (event.key === "Enter" || event.key === " ") { event.preventDefault(); select({ type: "fn", item: f }); }
        });
        plots.set(f, { g: p, x: x, y: y + py, w: W });
        anchors.set("f:" + f.id, { x: x, y: y + py, w: W, h: CELL });
      });
    });

    // Holders lane: roles, accounts and contracts outside the scan.
    const laneX = columns * (W + GAP) + 140;
    // Roles are listed inside their contract's parcel ("Held by"), not as boxes.
    const holderKinds = { privileged_account: "Accounts", external_target: "Called contracts",
      implementation: "Implementations", beacon: "Beacons", facet: "Facets" };
    const nodeToAnchor = new Map();
    data.nodes.forEach(function (n) {
      if (n.kind === "function") {
        const f = fnById.get(n.id.replace(/^node:function:/, ""));
        if (f && anchors.has("f:" + f.id)) { nodeToAnchor.set(n.id, anchors.get("f:" + f.id)); }
      } else if (n.contract_id && parcels.has(n.contract_id) && !holderKinds[n.kind] && n.kind !== "role") {
        nodeToAnchor.set(n.id, anchors.get("c:" + n.contract_id));
      }
    });
    let laneY = 0;
    Object.keys(holderKinds).forEach(function (kind) {
      const list = data.nodes.filter(function (n) { return n.kind === kind && !nodeToAnchor.has(n.id); });
      if (!list.length) { return; }
      const head = node("text", { class: "lane-title", x: laneX, y: laneY + 14 }, parcelLayer);
      head.textContent = holderKinds[kind];
      laneY += 26;
      list.forEach(function (n) {
        const box = node("g", { class: "holder" + (kind === "privileged_account" ? " account" : ""), transform: "translate(" + laneX + "," + laneY + ")" }, parcelLayer);
        node("rect", { class: "holder-frame", width: 220, height: n.address ? 44 : 30, rx: 2 }, box);
        const t = node("text", { x: 10, y: 19 }, box);
        // `.call` is a low-level call to an address chosen at run time.
        t.textContent = short(n.label.charAt(0) === "." ? "low-level " + n.label.slice(1) : n.label, 28);
        if (n.address) {
          const a = node("text", { class: "addr", x: 10, y: 36 }, box);
          a.textContent = short(n.address, 30);
        }
        nodeToAnchor.set(n.id, { x: laneX, y: laneY, w: 220, h: n.address ? 44 : 30 });
        laneY += (n.address ? 44 : 30) + 10;
      });
      laneY += 18;
    });

    data.edges.forEach(function (e) {
      if (e.kind === "exposes") { return; }
      const a = nodeToAnchor.get(e.source);
      const b = nodeToAnchor.get(e.target);
      if (!a || !b || a === b) { return; }
      const forward = b.x >= a.x + a.w;
      const sx = forward ? a.x + a.w : a.x;
      const tx = forward ? b.x : b.x + b.w;
      const sy = a.y + Math.min(a.h, 26) / 2;
      const ty = b.y + Math.min(b.h, 26) / 2;
      const bend = Math.max(60, Math.abs(tx - sx) / 2);
      const d = forward
        ? "M" + sx + "," + sy + " C" + (sx + bend) + "," + sy + " " + (tx - bend) + "," + ty + " " + tx + "," + ty
        : "M" + sx + "," + sy + " C" + (sx - 60) + "," + sy + " " + (tx + 60) + "," + ty + " " + tx + "," + ty;
      // Inheritance would criss-cross every parcel; it shows for the selected contract.
      const quiet = ["protected_by", "inherits", "implements", "uses_library"].indexOf(e.kind) !== -1;
      const path = node("path", { class: "link " + e.kind + (quiet ? " quiet" : ""), d: d }, linkLayer);
      if (quiet) { path.style.opacity = "0"; }
      path.dataset.source = e.source;
      path.dataset.target = e.target;
      const tip = node("title", {}, path);
      tip.textContent = e.kind.replace(/_/g, " ") + (e.label ? ": " + e.label : "");
    });

    const box = viewport.getBBox();
    bounds = { x: box.x - 40, y: box.y - 40, w: box.width + 80, h: box.height + 80 };
    document.getElementById("map-key").textContent =
      "Scroll to pan, Ctrl + scroll to zoom. Blue: proxy wiring · dashed: calls out · dotted: control · inheritance shows for the selected contract.";
    fit();
    paintMap();
  }

  function apply() { viewport.setAttribute("transform", "translate(" + view.x + "," + view.y + ") scale(" + view.k + ")"); }
  function fit() {
    const r = svg.getBoundingClientRect();
    if (!r.width || !r.height) { return; }
    // Never shrink below reading size: a big protocol is panned, not squinted at.
    const k = Math.max(0.8, Math.min(1, r.width / bounds.w, r.height / bounds.h));
    const x = bounds.w * k < r.width ? (r.width - bounds.w * k) / 2 - bounds.x * k : 16 - bounds.x * k;
    const y = bounds.h * k < r.height ? (r.height - bounds.h * k) / 2 - bounds.y * k : 16 - bounds.y * k;
    view = { k: k, x: x, y: y };
    apply();
  }
  function zoom(factor, cx, cy) {
    const r = svg.getBoundingClientRect();
    const px = cx === undefined ? r.width / 2 : cx;
    const py = cy === undefined ? r.height / 2 : cy;
    const k = Math.max(0.15, Math.min(4, view.k * factor));
    view.x = px - (px - view.x) * (k / view.k);
    view.y = py - (py - view.y) * (k / view.k);
    view.k = k;
    apply();
  }
  function centreOn(anchor) {
    const r = svg.getBoundingClientRect();
    if (!r.width) { return; }
    view.k = Math.max(view.k, 0.9);
    view.x = r.width / 2 - (anchor.x + anchor.w / 2) * view.k;
    view.y = r.height / 2 - (anchor.y + 12) * view.k;
    apply();
  }
  svg.addEventListener("wheel", function (event) {
    event.preventDefault();
    if (!event.ctrlKey && !event.metaKey) {
      view.x -= event.deltaX;
      view.y -= event.deltaY;
      apply();
      return;
    }
    const r = svg.getBoundingClientRect();
    zoom(event.deltaY < 0 ? 1.12 : 1 / 1.12, event.clientX - r.left, event.clientY - r.top);
  }, { passive: false });
  let drag = null;
  svg.addEventListener("pointerdown", function (event) {
    if (event.target.closest(".plot") || event.button !== 0) { return; }
    drag = { x: event.clientX, y: event.clientY, vx: view.x, vy: view.y, moved: false };
    svg.setPointerCapture(event.pointerId);
  });
  svg.addEventListener("pointermove", function (event) {
    if (!drag) { return; }
    const dx = event.clientX - drag.x;
    const dy = event.clientY - drag.y;
    if (Math.abs(dx) + Math.abs(dy) > 3) { drag.moved = true; svg.classList.add("dragging"); }
    view.x = drag.vx + dx;
    view.y = drag.vy + dy;
    apply();
  });
  svg.addEventListener("pointerup", function () { drag = null; svg.classList.remove("dragging"); });
  svg.addEventListener("click", function (event) {
    if (drag && drag.moved) { event.stopPropagation(); }
  }, true);
  document.getElementById("zoom-in").addEventListener("click", function () { zoom(1.25); });
  document.getElementById("zoom-out").addEventListener("click", function () { zoom(1 / 1.25); });
  document.getElementById("zoom-fit").addEventListener("click", fit);
  document.getElementById("export-svg").addEventListener("click", function () {
    const clone = svg.cloneNode(true);
    clone.querySelector("#viewport").setAttribute("transform", "translate(" + -bounds.x + "," + -bounds.y + ")");
    clone.setAttribute("viewBox", "0 0 " + bounds.w + " " + bounds.h);
    clone.setAttribute("width", bounds.w);
    clone.setAttribute("height", bounds.h);
    const rules = [];
    Array.from(document.styleSheets).forEach(function (sheet) {
      Array.from(sheet.cssRules || []).forEach(function (rule) {
        if (/^(:root|\.parcel|\.plot|\.link|\.holder|\.lane|\.tickmark|\.pencil)/.test(rule.selectorText || "")) { rules.push(rule.cssText); }
      });
    });
    const style = document.createElementNS(SVGNS, "style");
    style.textContent = rules.join("\n");
    clone.insertBefore(style, clone.firstChild);
    const blob = new Blob([new XMLSerializer().serializeToString(clone)], { type: "image/svg+xml" });
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = "contractmap.svg";
    link.click();
    setTimeout(function () { URL.revokeObjectURL(link.href); }, 1000);
  });

  function paintMap() {
    if (!mapBuilt) { return; }
    const active = filtering() || state.changing;
    plots.forEach(function (entry, f) {
      entry.g.classList.toggle("dim", active && !matches(f));
      entry.g.classList.toggle("selected", Boolean(selection && selection.type === "fn" && selection.item === f));
    });
    parcels.forEach(function (entry, id) {
      entry.g.classList.toggle("dim", Boolean(state.contract && state.contract !== id));
      entry.g.classList.toggle("selected", Boolean(selection && selection.type === "contract" && selection.item.id === id));
    });
    const hot = new Set();
    if (selection && selection.type === "fn") { hot.add("node:function:" + selection.item.id); }
    if (selection && selection.type === "contract") {
      data.nodes.forEach(function (n) { if (n.contract_id === selection.item.id && n.kind !== "function") { hot.add(n.id); } });
    }
    viewport.querySelectorAll(".link").forEach(function (path) {
      const on = hot.has(path.dataset.source) || hot.has(path.dataset.target);
      path.classList.toggle("hot", on);
      if (path.classList.contains("quiet")) { path.style.opacity = on ? "1" : "0"; }
    });
  }

  // ---- Selection and detail ----------------------------------------------
  const detail = document.getElementById("detail");
  function facts(rows) {
    return '<dl class="facts">' + rows.filter(function (r) { return r[1] !== null && r[1] !== undefined && r[1] !== ""; })
      .map(function (r) { return "<dt>" + r[0] + "</dt><dd>" + r[1] + "</dd>"; }).join("") + "</dl>";
  }
  function refLink(ref, text) { return '<button type="button" class="linkish" data-ref="' + ref + '">' + esc(text) + "</button>"; }

  function renderIntro() {
    const open = fns.filter(function (f) { return scope(f) && f.changing && f.grade === "none_identified"; }).length;
    const ex = fns.filter(function (f) { return scope(f) && f.exception && (!state.changing || f.changing); }).length;
    detail.innerHTML = '<div class="intro"><h2>Reading this report</h2>' +
      "<p>Every function someone can call carries one tick mark. The legend above filters by it.</p><ol>" +
      "<li><b>Exceptions</b> first: " + ex + " function" + (ex === 1 ? "" : "s") + " circled in red.</li>" +
      "<li><b>Open</b> functions: " + open + " state-changing ones take no guard.</li>" +
      "<li>Select any row or map plot to read who can call it, what it writes and the evidence.</li></ol>" +
      "<p>A verified tick says a check exists, not that the check is right.</p></div>";
  }

  function renderFn(f) {
    const g = GRADE[f.grade];
    const exceptions = f.findings.filter(function (o) { return o.exception; });
    let html = '<div class="grade' + (f.exception ? " exception" : "") + '">' + tick(f.grade, f.exception, 26) +
      esc(g.label) + " · " + esc(g.term) + "</div>";
    html += '<h2 class="mono">' + esc(f.owner.name) + ".<wbr>" + sig(f.signature) + "</h2>";
    html += '<p class="sub"><span class="mono">' + f.ref + (f.selector ? " · " + esc(f.selector) : "") + "</span> · " +
      esc(f.visibility) + " · " + esc(f.mutability) + "</p>";
    exceptions.forEach(function (o) {
      html += '<div class="callout"><b>' + o.ref + " " + esc(o.title) + "</b><br>" + esc(o.explanation) + "</div>";
    });
    html += facts([
      ["Who can call", esc(who(f))],
      ["Guard", f.access.modifiers.length ? '<span class="mono">' + esc(f.access.modifiers.join(", ")) + "</span>" : "none on the function"],
      ["Writes", f.writes.length ? '<span class="mono">' + esc(f.writes.join(", ")) + "</span>" : "no state found"],
      ["Declared in", f.declared_in ? esc(f.declared_in) + " (inherited)" : esc(f.owner.name)],
      ["Calls out", f.calls_external ? "yes, to other contracts" : "no"],
      ["Source", f.source ? '<span class="mono">' + esc(f.source) + "</span>" : null]
    ]);
    if (f.access.evidence.length) {
      html += "<h3>Evidence for the grade</h3><ul class=\"evidence\">" + f.access.evidence.map(function (e) {
        return "<li>" + esc(e.detail) + (e.source ? '<span class="src">' + esc(e.source) + "</span>" : "") + "</li>";
      }).join("") + "</ul>";
    }
    const others = f.findings.filter(function (o) { return !o.exception; });
    if (others.length) {
      html += "<h3>Also noted</h3><ul class=\"evidence\">" + others.map(function (o) {
        return "<li>" + refLink(o.ref, o.ref + " " + o.title) + "</li>";
      }).join("") + "</ul>";
    }
    html += '<div class="actions"><button type="button" data-show-map="1">Show on map</button>' +
      '<button type="button" data-ref="' + f.owner.ref + '">Open ' + esc(f.owner.name) + "</button></div>";
    return html;
  }

  function renderContract(c) {
    const list = c.fns;
    let html = '<h2>' + esc(c.name) + "</h2>";
    html += '<p class="sub"><span class="mono">' + c.ref + "</span> · " + esc(c.kind) +
      (c.address ? ' · <span class="mono">' + esc(c.address) + "</span>" : "") + "</p>";
    const p = c.proxy && c.proxy.kind !== "unknown" ? c.proxy : null;
    const roles = data.roles.filter(function (r) { return r.contract_id === c.id; }).map(function (r) { return r.name; });
    const accounts = data.nodes.filter(function (n) { return n.contract_id === c.id && n.kind === "privileged_account"; });
    html += facts([
      ["Entry points", list.length + " (" + list.filter(function (f) { return f.changing; }).length + " change state)"],
      ["Exceptions", String(list.filter(function (f) { return f.exception; }).length)],
      ["Proxy", p ? esc(p.kind) + " · " + esc(p.resolution) : null],
      ["Implementation", p && p.implementation ? '<span class="mono">' + esc(p.implementation) + "</span>" : null],
      ["Admin", p && p.admin ? '<span class="mono">' + esc(p.admin) + "</span>" : null],
      ["Beacon", p && p.beacon ? '<span class="mono">' + esc(p.beacon) + "</span>" : null],
      ["Facets", p && Object.keys(p.facets).length ? String(new Set(Object.values(p.facets)).size) : null],
      ["Roles", roles.length ? esc(roles.join(", ")) : null],
      ["Accounts", accounts.length ? accounts.map(function (a) { return esc(a.label) + ' <span class="mono">' + esc(a.address) + "</span>"; }).join("<br>") : null],
      ["Inherits", c.base_contracts.length ? esc(c.base_contracts.join(", ")) : null],
      ["Source", c.source_files.length ? '<span class="mono">' + esc(c.source_files.join(", ")) + "</span>" : null],
      ["Compiler", c.compiler_version ? esc(c.compiler_version) : null]
    ]);
    if (c.findings.length) {
      html += "<h3>Findings</h3><ul class=\"evidence\">" + c.findings.map(function (o) {
        return "<li>" + refLink(o.ref, o.ref + " " + o.title) + "</li>";
      }).join("") + "</ul>";
    }
    if (c.notes.length) {
      html += "<h3>Notes</h3><ul class=\"evidence\">" + c.notes.map(function (n) { return "<li>" + esc(n) + "</li>"; }).join("") + "</ul>";
    }
    html += '<div class="actions"><button type="button" data-show-map="1">Show on map</button>' +
      '<button type="button" data-filter="' + esc(c.id) + '">' + (state.contract === c.id ? "Show all contracts" : "Only this contract") + "</button></div>";
    return html;
  }

  function renderFinding(o) {
    let html = '<div class="grade' + (o.exception ? " exception" : "") + '">' + (o.exception ? tick("none_identified", true, 26) : "") +
      (o.exception ? "Exception " : "Note ") + o.ref + "</div>";
    html += "<h2>" + esc(o.title) + "</h2>";
    html += '<p class="sub">' + (o.owner ? refLink(o.owner.ref, o.owner.name) : "Whole system") + " · " + esc(o.category.replace(/_/g, " ")) + "</p>";
    html += "<p>" + esc(o.explanation) + "</p>";
    html += facts([
      ["Resolution", esc(o.resolution) + " · confidence " + Math.round(o.confidence * 100) + "%"],
      ["Review", o.review_area ? esc(o.review_area) : null]
    ]);
    if (o.fns.length) {
      html += "<h3>Functions</h3><ul class=\"evidence\">" + o.fns.map(function (f) {
        return "<li>" + refLink(f.ref, f.ref + " " + f.owner.name + "." + f.signature) + "</li>";
      }).join("") + "</ul>";
    }
    const rest = o.evidence.filter(function (e) { return e.kind !== "function"; });
    if (rest.length) {
      html += "<h3>Evidence</h3><ul class=\"evidence\">" + rest.map(function (e) {
        return "<li>" + esc(e.detail) + (e.source || e.value ? '<span class="src">' + esc([e.source, e.value].filter(Boolean).join(" · ")) + "</span>" : "") + "</li>";
      }).join("") + "</ul>";
    }
    return html;
  }

  function select(target, keepFocus) {
    selection = target;
    if (!target) { renderIntro(); }
    else if (target.type === "fn") { detail.innerHTML = renderFn(target.item); }
    else if (target.type === "contract") { detail.innerHTML = renderContract(target.item); }
    else { detail.innerHTML = renderFinding(target.item); }
    if (target && history.replaceState) {
      const onMap = document.getElementById("map").hidden === false;
      history.replaceState(null, "", "#" + (onMap ? "map:" : "") + target.item.ref);
    }
    register.querySelectorAll("tr[data-ref]").forEach(function (row) {
      row.setAttribute("aria-selected", String(Boolean(target && target.type === "fn" && row.dataset.ref === target.item.ref)));
    });
    if (target && target.type === "fn" && !keepFocus) {
      const row = register.querySelector('tr[data-ref="' + target.item.ref + '"]');
      if (row && !register.hidden) { row.scrollIntoView({ block: "nearest" }); }
    }
    paintMap();
    drawPencil();
  }
  function selectRef(ref, keepFocus) {
    const hit = refIndex.get(ref);
    if (hit) { select(hit, keepFocus); }
  }
  function drawPencil() {
    viewport.querySelectorAll(".plot.selected .pencil").forEach(function (path) {
      path.classList.remove("draw");
      void path.getBoundingClientRect();
      path.classList.add("draw");
    });
  }
  detail.addEventListener("click", function (event) {
    const show = event.target.closest("[data-show-map]");
    if (show) {
      showTab("map");
      const item = selection && selection.item;
      const anchor = selection && (selection.type === "fn" ? anchors.get("f:" + item.id) : anchors.get("c:" + item.id));
      if (anchor) { centreOn(anchor); }
      return;
    }
    const filter = event.target.closest("[data-filter]");
    if (filter) {
      state.contract = state.contract === filter.dataset.filter ? null : filter.dataset.filter;
      refresh();
      return;
    }
    const target = event.target.closest("[data-ref]");
    if (target) { selectRef(target.dataset.ref); }
  });

  // ---- Tabs, search, toggles ---------------------------------------------
  function showTab(name) {
    const map = name === "map";
    document.getElementById("tab-register").setAttribute("aria-selected", String(!map));
    document.getElementById("tab-map").setAttribute("aria-selected", String(map));
    register.hidden = map;
    document.getElementById("map").hidden = !map;
    if (map && !mapBuilt) { buildMap(); }
  }
  document.getElementById("tab-register").addEventListener("click", function () { showTab("register"); });
  document.getElementById("tab-map").addEventListener("click", function () { showTab("map"); });
  document.querySelector(".tabs").addEventListener("keydown", function (event) {
    if (event.key === "ArrowRight" || event.key === "ArrowLeft") {
      const map = document.getElementById("tab-map").getAttribute("aria-selected") !== "true";
      showTab(map ? "map" : "register");
      document.getElementById(map ? "tab-map" : "tab-register").focus();
    }
  });
  let searchTimer = null;
  document.getElementById("search").addEventListener("input", function (event) {
    clearTimeout(searchTimer);
    const value = event.target.value.trim().toLowerCase();
    searchTimer = setTimeout(function () { state.query = value; refresh(); }, 120);
  });
  document.getElementById("changing").addEventListener("change", function (event) {
    state.changing = event.target.checked;
    refresh();
  });
  document.getElementById("print").addEventListener("click", function () {
    showTab("register");
    state.all = true;
    renderRegister();
    window.print();
  });

  function refresh() {
    renderLegend();
    renderRail();
    renderRegister();
    paintMap();
    if (selection && selection.type === "contract") { detail.innerHTML = renderContract(selection.item); }
  }

  if (!data.metadata.analysis_complete) {
    const banner = document.getElementById("banner");
    banner.hidden = false;
    banner.textContent = "Partial analysis: a node or request budget ran out, so this map is incomplete. Raise --max-nodes or --max-requests and scan again.";
  }
  refresh();
  // Deep links: #C4.12 selects in the register, #map or #map:C4.12 opens the map.
  let initial = decodeURIComponent((location.hash || "").slice(1));
  if (initial === "map" || initial.indexOf("map:") === 0) {
    showTab("map");
    initial = initial.slice(4);
  }
  if (initial && refIndex.has(initial)) {
    selectRef(initial);
    const hit = refIndex.get(initial);
    const anchor = hit.type === "fn" ? anchors.get("f:" + hit.item.id) : hit.type === "contract" ? anchors.get("c:" + hit.item.id) : null;
    if (anchor && !document.getElementById("map").hidden) { centreOn(anchor); }
  } else {
    renderIntro();
  }
})();
