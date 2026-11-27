// tarav viewer (M3: interactive review). Input is the Go graph
// (internal/graph, with reachability per entry point), the lint findings,
// their graph links (D18) and the raw item, embedded as application/json.
// Layout is ELK layered with orthogonal routing, called directly (SPEC D4);
// bend points are drawn as Cytoscape segment edges.
(function () {
  "use strict";
  const read = (id) => JSON.parse(document.getElementById(id).textContent);
  const G = read("tarav-graph"), FINDINGS = read("tarav-findings") || [], LINKS = read("tarav-links") || [];
  const ITEM = read("tarav-item"), CONFIG = read("tarav-config");

  document.getElementById("title").textContent = G.item.name;
  document.getElementById("itemid").textContent = G.item.item_id;

  const css = getComputedStyle(document.documentElement);
  const v = (n) => css.getPropertyValue(n).trim();
  const LEVELS = ["encrypted", "mac_freshness", "mac", "crc", "none", "unknown", "physical", "diagnostic"];
  const PCOL = Object.fromEntries(LEVELS.map((l) => [l, v("--p-" + l)]));
  const PLABEL = { none: "none", crc: "CRC only", mac: "MAC", mac_freshness: "MAC + freshness", encrypted: "encrypted",
    unknown: "unknown", physical: "physical access (n/a)", diagnostic: "diagnostic route" };
  // D19: weakest first. unknown sits just above none because it may be none.
  const STRENGTH = { none: 0, unknown: 1, crc: 2, mac: 3, mac_freshness: 4, encrypted: 5 };
  const SEVCOL = { error: v("--bad"), warning: v("--warn"), info: v("--info") };

  // ---------------------------------------------------------------- data
  function at(ptr) {
    let o = ITEM;
    for (const t of ptr.split("/").slice(1)) o = o == null ? o : o[t.replace(/~1/g, "/").replace(/~0/g, "~")];
    return o;
  }
  const nodeById = new Map(G.nodes.map((n) => [n.id, n]));
  const edgeById = new Map(G.edges.map((e) => [e.id, e]));
  const zoneById = new Map(G.zones.map((z) => [z.id, z]));
  const compByID = new Map();
  for (const c of ITEM.components || []) if (!compByID.has(c.component_id)) compByID.set(c.component_id, c);
  const connByID = new Map();
  for (const c of ITEM.connections || []) if (!connByID.has(c.connection_id)) connByID.set(c.connection_id, c);
  const assetsOf = (cid) => (ITEM.assets || []).filter((a) => a.parent_component === cid);
  const assetsOn = (connId) => (ITEM.assets || []).filter((a) => (a.associated_connections || []).includes(connId));
  const assetLabel = new Map(G.assets.map((a) => [a.id, a.label]));
  const membersOf = new Map(); // component -> instance node IDs
  for (const n of G.nodes) if (n.kind === "instance") membersOf.set(n.parent, [...(membersOf.get(n.parent) || []), n.id]);
  const zoneOf = (id) => { const n = nodeById.get(id); return !n ? null : n.kind === "instance" ? zoneOf(n.parent) : n.zone || null; };

  // Findings per graph element, through the Go-computed links.
  const findingsAt = new Map();
  FINDINGS.forEach((f, i) => { const l = LINKS[i]; if (l) findingsAt.set(l, [...(findingsAt.get(l) || []), i]); });
  const flaggedIds = new Set([...findingsAt].filter(([, is]) => is.some((i) => FINDINGS[i].severity !== "info")).map(([id]) => id));

  // ---------------------------------------------------------------- state
  const layers = { zones: true, entries: true, protection: true, assets: false, asil: true, diag: true, labels: true };
  const expanded = new Set(); // components showing their instances
  const collapsed = new Set(); // zones folded into one box (D19)

  // Which drawn element stands for graph node id right now: a collapsed
  // group's instance is drawn as the group, anything in a collapsed zone as
  // the zone box. null if not drawn (entry points with that layer off).
  function visNode(id) {
    const n = nodeById.get(id);
    if (!n) return null;
    if (n.kind === "entry" || n.kind === "external") return layers.entries ? id : null;
    const z = zoneOf(id);
    if (z && collapsed.has(z)) return z;
    if (n.kind === "instance" && !expanded.has(n.parent)) return n.parent;
    return id;
  }
  const edgeShown = (e) => e.kind !== "diagnostic" || layers.diag;

  // ---------------------------------------------------------------- element list
  function edgeLabel(e) {
    if (!layers.labels) return "";
    let l = e.label || "";
    if (layers.assets && e.kind === "connection") {
      const a = assetsOn(e.element_id);
      if (a.length) l += (l ? "\n" : "") + "◆ " + a.map((x) => assetLabel.get(x.asset_id) || x.asset_id).join(" ");
    }
    if (flaggedIds.has(e.id)) l = "⚠ " + l;
    return l;
  }

  // Flat element list for the current state. Cytoscape compound parents are
  // not used: zones and expanded groups are plain boxes drawn at ELK's
  // geometry, so edges ELK routed around them line up.
  function elementsFor() {
    const out = [], drawn = new Set();
    for (const z of G.zones) {
      const comps = G.nodes.filter((n) => n.kind === "component" && n.zone === z.id).length;
      out.push({ data: collapsed.has(z.id)
        ? { id: z.id, kind: "zonebox", label: `${z.label}\n▣ ${comps} component${comps === 1 ? "" : "s"}` }
        : { id: z.id, kind: "zone", label: z.label } });
      drawn.add(z.id);
    }
    for (const n of G.nodes) {
      if (visNode(n.id) !== n.id) continue;
      const d = { id: n.id, kind: n.kind === "external" ? "entry" : n.kind, label: n.label, asil: n.asil || "",
        instanceCount: n.instance_count || 0, physical: !!n.physical, external: n.kind === "external" };
      if (n.kind === "component") d.container = n.zone;
      if (n.kind === "instance") { d.container = n.parent; d.group = n.parent; }
      out.push({ data: d });
      drawn.add(n.id);
    }
    const merged = new Map();
    for (const e of G.edges) {
      if (!edgeShown(e)) continue;
      // Edges to undefined references (L001) are dropped; lint reports them.
      const s = visNode(e.source), t = visNode(e.target);
      if (!s || !t || !drawn.has(s) || !drawn.has(t)) continue;
      if (collapsed.has(s) || collapsed.has(t)) {
        if (s === t) continue; // inside one collapsed zone
        const cls = e.protection ? "p" : e.kind;
        const key = `${cls}|${s}|${t}`;
        const m = merged.get(key) || { members: [], s, t, cls, kind: e.protection ? "merged" : e.kind };
        m.members.push(e);
        merged.set(key, m);
        continue;
      }
      const d = { id: "e:" + e.id, ref: e.id, source: s, target: t, loop: s === t, kind: e.kind, label: edgeLabel(e),
        protection: e.protection ? e.protection.level : e.kind, dashed: e.kind === "physical" || e.kind === "diagnostic",
        flagged: flaggedIds.has(e.id) };
      const inst = (e.target_instances || []).filter((i) => visNode(i) === i);
      if (inst.length && t === e.target && expanded.has(e.target)) {
        // fan out to the instances; label only the first so it isn't repeated
        inst.forEach((i, k) => out.push({ data: Object.assign({}, d, { id: d.id + "@" + i, target: i, split: k > 0 }) }));
        continue;
      }
      out.push({ data: d });
    }
    for (const [key, m] of merged) {
      const weakest = m.cls === "p"
        ? m.members.map((e) => e.protection.level).sort((a, b) => STRENGTH[a] - STRENGTH[b])[0]
        : m.cls;
      const one = m.members.length === 1;
      const flagged = m.members.some((e) => flaggedIds.has(e.id));
      const label = !layers.labels ? "" : (flagged ? "⚠ " : "") + (one ? m.members[0].label : `${m.members.length} edges`);
      out.push({ data: { id: "m:" + key, members: m.members.map((e) => e.id), ref: one ? m.members[0].id : null,
        source: m.s, target: m.t, kind: m.kind, label, protection: weakest, dashed: m.cls !== "p", flagged } });
    }
    return out;
  }

  // ---------------------------------------------------------------- card badges
  const CARD = { w: 160, h: 60 }, INST = { w: 88, h: 46 }, ENTRY = 30, ZBOX = { w: 190, h: 70 };
  const ASILCOL = { "ASIL-D": "#1c1c1a", "ASIL-C": "#4d4d48", "ASIL-B": "#6b6b66", "ASIL-A": "#8a8880", QM: "#e2e1dc" };
  const ASILTXT = { QM: "#1c1c1a" };
  // A card shows a red dot if it, or a collapsed instance it stands for, has findings.
  const hasFlag = (id) => flaggedIds.has(id) || (!expanded.has(id) && (membersOf.get(id) || []).some((m) => flaggedIds.has(m)));
  function cardSvg(n) {
    const kind = n.data("kind"), inst = kind === "instance";
    if (kind === "component" && expanded.has(n.id())) return "none";
    const { w, h } = inst ? INST : CARD;
    const parts = [];
    const asil = n.data("asil");
    if (layers.asil && asil && !inst) {
      const txt = asil.replace("ASIL-", "ASIL ");
      const bw = 8 + txt.length * 6.2;
      parts.push(`<rect x="7" y="7" rx="3" width="${bw}" height="15" fill="${ASILCOL[asil] || "#1c1c1a"}"/>` +
        `<text x="${7 + bw / 2}" y="18" font-family="system-ui,sans-serif" font-size="10" font-weight="700" fill="${ASILTXT[asil] || "#fff"}" text-anchor="middle">${esc(txt)}</text>`);
    }
    if (hasFlag(n.id())) parts.push(`<circle cx="${w - 12}" cy="13" r="5" fill="#c0392b" stroke="#fff" stroke-width="1.5"/>`);
    const cnt = n.data("instanceCount");
    if (cnt && !expanded.has(n.id())) {
      parts.push(`<rect x="${w - 42}" y="${h - 21}" rx="3" width="34" height="15" fill="#f2f1ec" stroke="#9a988f"/>` +
        `<text x="${w - 25}" y="${h - 10}" font-family="system-ui,sans-serif" font-size="10" font-weight="700" fill="#1c1c1a" text-anchor="middle">×${cnt} ▸</text>`);
    }
    if (!parts.length) return "none";
    return "data:image/svg+xml;utf8," + encodeURIComponent(
      `<svg xmlns="http://www.w3.org/2000/svg" width="${w}" height="${h}" viewBox="0 0 ${w} ${h}">${parts.join("")}</svg>`);
  }
  function nodeLabel(n) {
    let l = n.data("label");
    if (n.data("instanceCount") && expanded.has(n.id())) l += "  ▾";
    if (layers.assets && n.data("kind") === "component") {
      const a = assetsOf(n.id());
      if (a.length) l += "\n◆ " + a.map((x) => assetLabel.get(x.asset_id) || x.asset_id).join("  ");
    }
    return l;
  }
  const edgeColor = (e) => (layers.protection || e.data("dashed") ? PCOL[e.data("protection")] || PCOL.unknown : "#9a988f");

  // ---------------------------------------------------------------- layout
  const elk = new ELK();
  const measure = document.createElement("canvas").getContext("2d");
  function textBox(t, font) {
    measure.font = font;
    const lines = String(t).split("\n");
    return { width: Math.ceil(Math.max(...lines.map((l) => measure.measureText(l).width))) + 8, height: lines.length * 14 + 4 };
  }
  const ELK_ROOT = {
    "elk.algorithm": "layered", "elk.direction": "RIGHT", "elk.hierarchyHandling": "INCLUDE_CHILDREN",
    "elk.edgeRouting": "ORTHOGONAL", "elk.randomSeed": "1",
    "elk.layered.considerModelOrder.strategy": "NODES_AND_EDGES",
    "elk.spacing.nodeNode": "40", "elk.layered.spacing.nodeNodeBetweenLayers": "50",
    "elk.spacing.edgeNode": "18", "elk.spacing.edgeEdge": "12", "elk.layered.spacing.edgeNodeBetweenLayers": "18",
    "elk.layered.spacing.edgeEdgeBetweenLayers": "12", "elk.spacing.edgeLabel": "4",
    "elk.edgeLabels.placement": "CENTER", "elk.spacing.componentComponent": "50",
    "elk.layered.mergeEdges": "true",
    "elk.padding": "[top=20,left=20,bottom=20,right=20]",
  };
  const ZONE_PAD = "[top=44,left=20,bottom=20,right=20]", GROUP_PAD = "[top=14,left=14,bottom=34,right=14]";

  async function layoutElements(els) {
    const byId = new Map(), root = { id: "__root", layoutOptions: ELK_ROOT, children: [], edges: [] };
    const nodes = els.filter((e) => !e.data.source), edges = els.filter((e) => e.data.source);
    for (const { data: d } of nodes) {
      const n = { id: d.id, children: [] };
      if (d.kind === "zone") n.layoutOptions = { "elk.padding": ZONE_PAD };
      else if (d.kind === "zonebox") Object.assign(n, { width: ZBOX.w, height: ZBOX.h });
      else if (d.kind === "component" && expanded.has(d.id)) n.layoutOptions = { "elk.padding": GROUP_PAD };
      else if (d.kind === "instance") Object.assign(n, { width: INST.w, height: INST.h });
      else if (d.kind === "entry") {
        Object.assign(n, { width: ENTRY, height: ENTRY, labels: [Object.assign({ text: d.label }, textBox(d.label, "12px system-ui, sans-serif"))],
          layoutOptions: { "elk.nodeLabels.placement": "OUTSIDE V_BOTTOM H_CENTER" } });
      } else Object.assign(n, { width: CARD.w, height: CARD.h });
      byId.set(d.id, n);
    }
    for (const { data: d } of nodes) (d.container && byId.has(d.container) ? byId.get(d.container).children : root.children).push(byId.get(d.id));
    for (const { data: d } of edges) {
      const t = d.split ? "" : d.label || "";
      root.edges.push({ id: d.id, sources: [d.source], targets: [d.target],
        labels: t ? [Object.assign({ text: t }, textBox(t, "11px system-ui, sans-serif"))] : [] });
    }
    const res = await elk.layout(root);

    // ELK coordinates are relative to the parent node; edges are relative to
    // their `container` (elkjs 0.9 ignores elk.json.edgeCoords).
    const abs = new Map([["__root", { x: 0, y: 0, w: 0, h: 0 }]]);
    (function walk(n, ox, oy) {
      for (const c of n.children || []) {
        abs.set(c.id, { x: ox + c.x, y: oy + c.y, w: c.width, h: c.height });
        walk(c, ox + c.x, oy + c.y);
      }
    })(res, 0, 0);
    const routes = new Map();
    (function walkEdges(n) {
      for (const e of n.edges || []) {
        const o = abs.get(e.container || n.id) || abs.get("__root");
        const s = e.sections[0];
        const pts = [s.startPoint, ...(s.bendPoints || []), s.endPoint].map((p) => ({ x: p.x + o.x, y: p.y + o.y }));
        routes.set(e.id, { pts, labels: (e.labels || []).map((l) => ({ text: l.text, x: l.x + o.x, y: l.y + o.y, w: l.width, h: l.height })) });
      }
      for (const c of n.children || []) walkEdges(c);
    })(res);

    const out = [];
    for (const { data: d } of nodes) {
      const b = abs.get(d.id);
      const box = d.kind === "zone" || (d.kind === "component" && expanded.has(d.id));
      out.push({ data: Object.assign({}, d, box ? { w: b.w, h: b.h, box: true } : {}), position: { x: b.x + b.w / 2, y: b.y + b.h / 2 } });
    }
    for (const { data: d } of edges) {
      const r = routes.get(d.id), sb = abs.get(d.source), tb = abs.get(d.target);
      const sc = { x: sb.x + sb.w / 2, y: sb.y + sb.h / 2 }, tc = { x: tb.x + tb.w / 2, y: tb.y + tb.h / 2 };
      const A = r.pts[0], B = r.pts[r.pts.length - 1];
      // Bend points as segments relative to the start→end line
      // ("edge-distances: endpoints"): weight along it, signed distance from it.
      const dx = B.x - A.x, dy = B.y - A.y, L2 = dx * dx + dy * dy || 1, L = Math.sqrt(L2);
      const bends = r.pts.slice(1, -1);
      const segW = bends.map((p) => (((p.x - A.x) * dx + (p.y - A.y) * dy) / L2).toFixed(4)).join(" ");
      const segD = bends.map((p) => (((p.y - A.y) * dx - (p.x - A.x) * dy) / L).toFixed(2)).join(" ");
      out.push({ data: Object.assign({}, d, {
        pts: r.pts, segW, segD, bent: bends.length > 0,
        srcEp: `${(A.x - sc.x).toFixed(2)}px ${(A.y - sc.y).toFixed(2)}px`,
        tgtEp: `${(B.x - tc.x).toFixed(2)}px ${(B.y - tc.y).toFixed(2)}px` }) });
      for (const l of r.labels) {
        out.push({ data: { id: "lbl:" + d.id, kind: "elabel", edge: d.id, label: l.text, w: l.w, h: l.h, flagged: !!d.flagged },
          position: { x: l.x + l.w / 2, y: l.y + l.h / 2 } });
      }
    }
    return out;
  }

  // ---------------------------------------------------------------- cytoscape
  const cy = cytoscape({
    container: document.getElementById("cy"),
    elements: [],
    minZoom: 0.15, maxZoom: 3, autoungrabify: true,
    style: [
      { selector: "node", style: { "font-family": "system-ui, sans-serif", "font-size": 13, color: "#1c1c1a",
          "text-wrap": "wrap", "text-max-width": 150, "z-index-compare": "manual", "z-index": 10 } },
      { selector: "node[?box]", style: { shape: "round-rectangle", width: "data(w)", height: "data(h)", "z-index": 0 } },
      { selector: "node[kind='zone']", style: {
          "background-color": "#f2f1ec", "border-width": 1, "border-color": "#d6d4cc",
          label: "data(label)", "text-valign": "top", "text-halign": "center", "text-margin-y": 26, "font-size": 13,
          "text-max-width": 600, color: "#6b6b66", "font-weight": 600, "text-transform": "uppercase" } },
      { selector: "node[kind='zone'].flat", style: { "background-opacity": 0, "border-width": 0, label: "" } },
      { selector: "node[kind='zonebox']", style: {
          shape: "round-rectangle", width: ZBOX.w, height: ZBOX.h, "background-color": "#f2f1ec", "border-width": 1.5,
          "border-style": "dashed", "border-color": "#9a988f", label: "data(label)", "text-valign": "center", "text-halign": "center",
          "font-size": 12, "font-weight": 600, color: "#4d4d48", "text-max-width": 180 } },
      { selector: "node[kind='component'], node[kind='instance']", style: {
          shape: "round-rectangle", width: CARD.w, height: CARD.h, "background-color": "#fff",
          "border-width": 1, "border-color": "#c8c6bd", label: nodeLabel,
          "text-valign": "center", "text-halign": "center", "text-margin-y": 7, "font-size": 15, "font-weight": 600,
          "background-image": cardSvg, "background-fit": "none", "background-width": "100%", "background-height": "100%",
          "background-clip": "none", "background-image-containment": "over" } },
      // long names without an abbreviation shrink to fit the card
      { selector: "node[kind='component'][!box]", style: { "font-size": (n) => (n.data("label").length > 18 ? 12 : 15) } },
      { selector: "node[kind='component'][?instanceCount]", style: { "border-width": 2, "border-style": "double", "border-color": "#9a988f" } },
      // group frame: after the card rule, which would otherwise impose the card size
      { selector: "node[kind='component'][?box]", style: { width: "data(w)", height: "data(h)",
          "background-color": "#fbfbf8", "text-valign": "bottom", "text-margin-y": -12, "border-style": "solid", "border-width": 1,
          "border-color": "#c8c6bd", "z-index": 1, "font-size": 13 } },
      { selector: "node[kind='instance']", style: { width: INST.w, height: INST.h, "font-weight": 500, "font-size": 13, "text-margin-y": 0 } },
      { selector: "node[kind='entry']", style: {
          shape: "diamond", width: ENTRY, height: ENTRY, "background-color": "#1c1c1a",
          label: "data(label)", "text-valign": "bottom", "text-margin-y": 5, "font-size": 12, "text-max-width": 200 } },
      { selector: "node[kind='entry'][?physical]", style: { "background-color": "#fff", "border-width": 2.5, "border-color": "#1c1c1a" } },
      { selector: "node[kind='entry'][?external]", style: { "background-color": "#9a988f" } },
      { selector: "node[kind='elabel']", style: {
          shape: "round-rectangle", width: "data(w)", height: "data(h)", "background-color": "#fafaf9", "background-opacity": 0.95,
          label: "data(label)", "font-size": 11, color: "#3d3d39", "text-valign": "center", "text-halign": "center", "z-index": 15 } },
      { selector: "node[kind='elabel'][?flagged]", style: { color: "#c0392b" } },
      { selector: "edge", style: {
          width: 3, "curve-style": "straight", "target-arrow-shape": "triangle", "arrow-scale": 1,
          "line-color": edgeColor, "target-arrow-color": edgeColor, "z-index-compare": "manual", "z-index": 5,
          "source-endpoint": "data(srcEp)", "target-endpoint": "data(tgtEp)" } },
      { selector: "edge[?bent]", style: { "curve-style": "segments", "edge-distances": "endpoints",
          "segment-distances": "data(segD)", "segment-weights": "data(segW)", "segment-radius": 6, "radius-type": "arc-radius" } },
      // Self-loops: drawn by Cytoscape as loops (after the segments rule, which would win otherwise).
      { selector: "edge[?loop]", style: { "curve-style": "bezier", "source-endpoint": "outside-to-node", "target-endpoint": "outside-to-node",
          "loop-direction": "-45deg", "loop-sweep": "-90deg", "control-point-step-size": 60 } },
      { selector: "edge[?dashed]", style: { "line-style": "dashed", "line-dash-pattern": [7, 5] } },
      { selector: "edge[kind='message']", style: { width: 1.75 } },
      { selector: "edge[kind='merged']", style: { width: 4.5 } },
      { selector: "edge[kind='diagnostic']", style: { width: 2, "target-arrow-shape": "vee" } },
      { selector: ".dim", style: { opacity: 0.12 } },
      { selector: "node.sel, node.match", style: { "border-width": 3, "border-color": "#2e86c1" } },
      { selector: "edge.sel", style: { width: 5 } },
    ],
  });

  // Wheel zoom. Cytoscape's default step is large and its wheelSensitivity
  // option logs a warning, so wheel input is handled here: one standard
  // notch (100 px) zooms about 7%, smaller trackpad deltas zoom
  // proportionally less, bursts are capped, and the point under the cursor
  // stays put. Pinch gestures arrive as ctrl+wheel with small deltas and get
  // a steeper curve. Each event moves a target level; an animation eases the
  // view towards it (instant with prefers-reduced-motion), so quick notches
  // accumulate smoothly. Any other zoom (fit, select) cancels the animation.
  cy.userZoomingEnabled(false);
  const cyEl = document.getElementById("cy");
  const reducedMotion = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  const WHEEL_K = -Math.log(0.93) / 100, PINCH_K = 0.01;
  const wz = { target: 0, at: null, last: 0, frame: 0, timer: 0, done: null, resolve: null };
  // Next animation frame, with a timer as backup for hosts that stall
  // requestAnimationFrame (headless test browsers); whichever fires first wins.
  function schedule() {
    const tick = () => { cancelAnimationFrame(wz.frame); clearTimeout(wz.timer); wheelStep(performance.now()); };
    wz.frame = requestAnimationFrame(tick);
    wz.timer = setTimeout(tick, 32);
  }
  const clampZoom = (z) => Math.max(cy.minZoom(), Math.min(cy.maxZoom(), z));
  function wheelStep(now) {
    if (cy.zoom() !== wz.last) return wheelStop(); // someone else zoomed: let them win
    const dt = Math.min(64, now - (wz.t || now)); wz.t = now;
    const z = cy.zoom(), next = z + (wz.target - z) * (1 - Math.exp(-dt / 70));
    const final = Math.abs(wz.target - next) < wz.target * 0.001;
    cy.zoom({ level: final ? wz.target : next, renderedPosition: wz.at });
    wz.last = cy.zoom();
    if (final) return wheelStop();
    schedule();
  }
  function wheelStop() {
    cancelAnimationFrame(wz.frame); clearTimeout(wz.timer); wz.frame = 0; wz.timer = 0; wz.t = 0;
    if (wz.resolve) { wz.resolve(); wz.resolve = null; }
  }
  function wheelZoom(e) {
    e.preventDefault();
    const px = e.deltaMode === 1 ? e.deltaY * 33 : e.deltaMode === 2 ? e.deltaY * 400 : e.deltaY;
    const step = Math.max(-200, Math.min(200, px));
    const r = cyEl.getBoundingClientRect();
    wz.at = { x: e.clientX - r.left, y: e.clientY - r.top };
    const base = wz.frame ? wz.target : cy.zoom();
    wz.target = clampZoom(base * Math.exp(-step * (e.ctrlKey ? PINCH_K : WHEEL_K)));
    if (reducedMotion) { cy.zoom({ level: wz.target, renderedPosition: wz.at }); return; }
    if (!wz.frame) {
      wz.done = new Promise((res) => { wz.resolve = res; });
      wz.last = cy.zoom();
      schedule();
    }
  }
  cyEl.addEventListener("wheel", wheelZoom, { passive: false });

  function fitView() {
    const vis = cy.elements(":visible");
    if (!vis.length) return;
    cy.fit(vis, 36);
    if (cy.zoom() > 1.6) { cy.zoom(1.6); cy.center(vis); }
  }
  const applyStyleLayers = () => { cy.nodes("[kind='zone']").toggleClass("flat", !layers.zones); cy.style().update(); };
  // Rebuild + lay out, serialised so rapid toggles can't interleave.
  let pending = Promise.resolve();
  function rebuild() {
    pending = pending.then(async () => {
      const els = await layoutElements(elementsFor());
      cy.batch(() => { cy.elements().remove(); cy.add(els); });
      applyStyleLayers();
      clearHighlight();
      fitView();
    }).catch((e) => { console.error("layout failed:", e); banner("Layout failed: " + e.message); });
    return pending;
  }
  let rt;
  window.addEventListener("resize", () => { clearTimeout(rt); rt = setTimeout(() => cy.resize(), 120); });
  function banner(t) { const b = document.getElementById("banner"); b.textContent = t; b.style.display = t ? "block" : "none"; }
  const statusEl = document.getElementById("status");
  function setStatus(t) { statusEl.textContent = t || ""; statusEl.style.display = t ? "block" : "none"; }

  // ---------------------------------------------------------------- tooltip
  const tip = document.getElementById("tip");
  cy.on("mouseover", "node, edge", (e) => {
    const d = e.target.data();
    let t = "";
    if (d.kind === "entry" && !d.external) t = "Click: show what is reachable from this entry point";
    else if (d.instanceCount) t = expanded.has(d.id) ? "Double-click to collapse instances" : `Double-click to expand ${d.instanceCount} instances`;
    else if (d.kind === "zone") t = "Double-click to fold this zone";
    else if (d.kind === "zonebox") t = "Double-click to unfold this zone";
    else if (e.target.isEdge()) t = `${PLABEL[d.protection] || d.protection}${d.members && d.members.length > 1 ? ` (weakest of ${d.members.length})` : ""} — click for details`;
    else if (d.kind !== "elabel") t = "Click: details and neighbours";
    if (!t) return;
    tip.textContent = t; tip.style.display = "block";
  });
  cy.on("mouseout", "node, edge", () => { tip.style.display = "none"; });
  document.getElementById("cy").addEventListener("mousemove", (e) => { tip.style.left = e.clientX + 14 + "px"; tip.style.top = e.clientY + 14 + "px"; });

  // ---------------------------------------------------------------- drawer
  // A floating inspector: header (kind, title, description, summary tiles,
  // JSON pointer), then sections of facts, rows and cards. Status is a dot
  // plus words, never a glyph or colour alone.
  const pane = document.getElementById("pane");
  function esc(s) { return String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]); }
  const human = (k) => k.replace(/_/g, " ");
  const isVague = (s) => typeof s === "string" && (/^\s*not specified\s*$/i.test(s) || /^not modeled$/i.test(s.trim()) || (/^Configured\b/.test(s) && !/\d/.test(s)));
  // Boolean polarity heuristic: true is the secure value unless the key
  // names something risky. A display aid only; lint does not use it.
  const TRUE_IS_BAD = /overrid|^allow|allowed_while_driving|forwarding_enabled|runs_as_root|root_login|^hardcoded|unlocked/;
  const NEUTRAL = /^vendor_kernel_modifications$/;
  const TONE = { good: "var(--good)", bad: "var(--bad)", warn: "var(--warn)", neutral: "var(--text-4)", ink: "var(--ink)" };
  const SEVTONE = { error: "bad", warning: "warn", info: "neutral" };
  const dot = (tone) => `<i class="dot" style="background:${TONE[tone] || tone}"></i>`;
  const boolTone = (k, val) => (NEUTRAL.test(k) ? "neutral" : (TRUE_IS_BAD.test(k) ? !val : val) ? "good" : "bad");

  // Small stroke icons for the header tile (drawn here, no icon font).
  const ICONS = {
    component: '<rect x="4" y="4" width="16" height="16" rx="3"/><path d="M9 9h6v6H9z"/>',
    instance: '<rect x="8" y="8" width="12" height="12" rx="2"/><path d="M4 16V6a2 2 0 0 1 2-2h10"/>',
    entry: '<path d="M12 3l9 9-9 9-9-9z"/>',
    physical: '<path d="M9 3v5M15 3v5M6 8h12v3a6 6 0 0 1-12 0zM12 17v4"/>',
    connection: '<path d="M4 12h15M14 7l5 5-5 5"/>',
    message: '<path d="M4 5h16v11H9l-5 4z"/>',
    diagnostic: '<path d="M14 7a4 4 0 0 1 5 5l-7 7a2.8 2.8 0 0 1-4-4z"/><path d="M14 7l-2-2"/>',
    zone: '<rect x="3" y="3" width="18" height="18" rx="4" stroke-dasharray="3 3"/>',
    merged: '<path d="M4 7h16M4 12h16M4 17h16"/>',
    close: '<path d="M6 6l12 12M18 6L6 18"/>',
    copy: '<rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V6a2 2 0 0 1 2-2h9"/>',
  };
  const icon = (k) => `<svg viewBox="0 0 24 24" aria-hidden="true">${ICONS[k]}</svg>`;

  // ---- building blocks
  const section = (title, body, count) => (body
    ? `<section class="sec"><h3>${esc(title)}${count != null ? ` <span class="c">${count}</span>` : ""}</h3>${body}</section>` : "");
  // A cross-reference that selects its graph element.
  const jump = (id, text) => ((nodeById.has(id) || edgeById.has(id) || zoneById.has(id))
    ? `<button type="button" class="link" data-jump="${esc(id)}">${esc(text || id)}</button>` : `<code>${esc(text || id)}</code>`);
  const connJump = (cid, text) => {
    const e = G.edges.find((x) => x.element_id === cid && x.kind !== "physical" && x.kind !== "diagnostic");
    return e ? jump(e.id, text || cid) : esc(text || cid);
  };
  const jumpable = (id) => nodeById.has(id) || edgeById.has(id) || zoneById.has(id);
  // A list row: dot, name, optional description and path; a button when it selects something.
  function row({ id, tone, name, desc, path, extra }) {
    const body = `${dot(tone || "neutral")}<span class="rt"><span class="rn">${name}</span>${desc ? `<span class="rd">${desc}</span>` : ""}` +
      `${path ? `<span class="rp" title="${esc(path)}">${esc(path)}</span>` : ""}</span>${extra ? `<span class="rc">${extra}</span>` : ""}`;
    return id && jumpable(id) ? `<button type="button" class="row" data-jump="${esc(id)}">${body}</button>` : `<div class="row">${body}</div>`;
  }
  const list = (rows) => (rows.length ? `<div class="list">${rows.join("")}</div>` : "");
  const note = (tone, html) => `<p class="note">${dot(tone)}<span>${html}</span></p>`;
  const tags = (items, cls) => (items.length ? `<div class="tags">${items.map((x) => `<span class="tag ${cls || ""}" title="${esc(x)}">${esc(x)}</span>`).join("")}</div>` : "");
  const stats = (cells) => `<div class="stats">${cells.filter(Boolean).map(([v, l]) => `<div><b title="${esc(v)}">${esc(v)}</b><span>${esc(l)}</span></div>`).join("")}</div>`;
  const level = (lvl) => `<span class="level" style="--c:${PCOL[lvl] || PCOL.unknown}">${dot(PCOL[lvl] || PCOL.unknown)}${esc(PLABEL[lvl] || lvl)}</span>`;

  // Facts: label left, value right. Booleans and unquantified values get a
  // status dot; risky values sort first so problems are seen before the rest.
  function factRow(label, value, title) {
    return `<div${title ? ` title="${esc(title)}"` : ""}><dt>${esc(label)}</dt><dd>${value}</dd></div>`;
  }
  function factOf(k, val, path) {
    if (typeof val === "boolean") return [boolTone(k, val) === "bad" ? 0 : 2, factRow(human(k), `${dot(boolTone(k, val))}${val ? "yes" : "no"}`, path)];
    if (isVague(val)) return [1, factRow(human(k), `${dot("warn")}${esc(val)} <span class="src">no concrete value</span>`, path)];
    if (val && typeof val === "object" && !Array.isArray(val)) return [3, `<div class="nest" title="${esc(path)}"><p class="group-label">${esc(human(k))}</p>${facts(val, path)}</div>`];
    const shown = Array.isArray(val) ? val.map((x) => (typeof x === "object" ? `<code>${esc(JSON.stringify(x))}</code>` : esc(x))).join(", ") : esc(val);
    return [3, factRow(human(k), shown, path)];
  }
  function facts(obj, path, skip) {
    const rows = Object.entries(obj || {}).filter(([k]) => !(skip || []).includes(k))
      .map(([k, val], i) => [...factOf(k, val, path + "/" + k), i]).sort((a, b) => a[0] - b[0] || a[2] - b[2]);
    return rows.length ? `<dl class="facts">${rows.map((r) => r[1]).join("")}</dl>` : "";
  }

  function head({ kind, label, color, title, desc, stat, path, actions }) {
    return `<section class="sec"><div class="ph"><span class="ico" style="--c:${color || "var(--ink)"}">${icon(kind)}</span>` +
      `<span class="kindlabel">${esc(label)}</span>` +
      `<button type="button" class="iconbtn" data-close aria-label="Close details" title="Close (Esc)">${icon("close")}</button></div>` +
      `<h2 class="pt">${esc(title)}</h2>${desc ? `<p class="pd">${desc}</p>` : ""}${stat ? stats(stat) : ""}` +
      `${actions ? `<div class="actions">${actions}</div>` : ""}` +
      `${path ? `<div class="pp"><span>${esc(path)}</span><button type="button" class="iconbtn" data-copy="${esc(path)}" aria-label="Copy JSON pointer" title="Copy JSON pointer">${icon("copy")}</button></div>` : ""}</section>`;
  }
  function findingIdx(ids) { return [...new Set(ids.flatMap((id) => findingsAt.get(id) || []))].sort((a, b) => a - b); }
  function findingsSection(ids) {
    const idx = findingIdx(ids);
    return section("Lint findings", list(idx.map((i) => { const f = FINDINGS[i];
      return row({ tone: SEVTONE[f.severity], name: `${esc(f.rule)} <span class="rc">${esc(f.severity)}</span>`, desc: esc(f.message), path: f.json_path }); })), idx.length);
  }
  function rawSection(ptr) {
    const o = ptr ? at(ptr) : undefined;
    if (o === undefined) return "";
    return `<section class="sec"><details class="raw"><summary>Raw JSON</summary><pre>${esc(JSON.stringify(o, null, 2))}</pre></details></section>`;
  }
  function assetsHtml(list) {
    return list.map((a) => {
      const i = ITEM.assets.indexOf(a);
      const ds = (a.damage_scenarios || []).map((d) => {
        const s = d.expected_sfop_impact || {};
        return `<div class="card-sub"><p class="rd"><code>${esc(d.damage_id)}</code> ${esc(d.description || "")}</p>` +
          `<div class="sfop">${["Safety", "Financial", "Operational", "Privacy"].map((k) =>
            `<div class="sev-${esc(s[k] || "Negligible")}"><small>${k}</small>${esc(s[k] || "—")}</div>`).join("")}</div></div>`;
      }).join("") || note("bad", "No damage scenario (L003)");
      return `<div class="card" title="/assets/${i}"><h4>${esc(a.name)}</h4><p class="rd"><code>${esc(a.asset_id)}</code> · parent ${jump(a.parent_component)}</p>` +
        `${tags(a.cybersecurity_properties || [], "sans")}${ds}</div>`;
    }).join("");
  }
  function receiverBehaviour(c) {
    if (!c) return "";
    const ci = ITEM.components.indexOf(c), rows = [];
    (c.hosted_software || []).forEach((s, j) => {
      for (const [k, val] of Object.entries(s.operational_parameters || {})) {
        if (/timeout|invalid|recovery|acceptance/.test(k)) rows.push([k, val, `/components/${ci}/hosted_software/${j}/operational_parameters/${k}`]);
      }
    });
    if (!rows.length) return note("warn", `No timeout, invalid-input or recovery behaviour defined on ${esc(c.component_id)}.`);
    return `<dl class="facts">${rows.map(([k, val, p]) => factRow(human(k), isVague(val) ? `${dot("warn")}${esc(val)}` : esc(val), p)).join("")}</dl>`;
  }
  function messageHtml(m, conn) {
    const fields = (m.payload_fields || []).map((f) => `<tr><td>${esc(f.name)}</td><td>${esc(f.unit || f.type || f.target_instance || "")}</td><td>${esc(f.meaning || "")}</td></tr>`).join("");
    const src = m.source_component || conn.source_component, tgt = m.target_component || conn.target_component;
    return `<div class="card"><h4><code>${esc(m.can_id)}</code> ${esc(m.name)}</h4>` +
      `<p class="rd">${jump(src)} → ${jump(tgt)}${m.payload_unit ? " · unit " + esc(m.payload_unit) : ""}</p>` +
      (fields ? `<table>${fields}</table>` : "") +
      (m.receiver_behavior ? `<p class="rd">Receiver behaviour: ${esc(m.receiver_behavior)}</p>` : "") + `</div>`;
  }
  function protectionSection(e, conn) {
    if (!e.protection) return section("Protection", note("neutral", `No protection level applies to a ${e.kind === "physical" ? "physical access path" : "diagnostic route"} (D13).`));
    const p = e.protection, NAMES = { encrypted: "Encrypted", mac: "MAC", freshness: "Freshness", e2e_crc: "E2E CRC" };
    // One row per flag: the value, and where it was read from.
    const rows = ["encrypted", "mac", "freshness", "e2e_crc"].map((k) => {
      const f = e.flags[k];
      return row({ tone: !f.set ? "warn" : f.on ? "good" : "bad", name: `${NAMES[k]} <span class="rc">${!f.set ? "not stated" : f.on ? "yes" : "no"}</span>`,
        desc: f.set ? esc(f.source) : "", path: f.set ? f.json_path : "" });
    });
    const auth = conn && conn.authenticated;
    if (auth) rows.push(row({ tone: /^none\b/i.test(auth) ? "bad" : "neutral", name: "Authenticated", desc: esc(auth) }));
    return section("Protection", `<p>${level(p.level)}</p>` +
      (p.missing && p.missing.length ? `<div style="margin-top:8px">${note("warn", `Not stated: ${esc(p.missing.join(", "))}. The level could be higher if these were known.`)}</div>` : "") +
      `<div style="margin-top:6px">${list(rows)}</div>`);
  }
  const reachCount = (n) => n.reach.nodes.filter((id) => ["component", "instance"].includes((nodeById.get(id) || {}).kind)).length;

  function componentHtml(n) {
    const c = at(n.json_path) || {}, P = n.json_path;
    const groups = [];
    if (c.security_configuration) groups.push(["Component", facts(c.security_configuration, P + "/security_configuration")]);
    (c.hosted_software || []).forEach((s, j) => { if (s.security_configuration) groups.push([s.name, facts(s.security_configuration, `${P}/hosted_software/${j}/security_configuration`)]); });
    const sec = groups.map(([l, h]) => `<div class="group"><p class="group-label">${esc(l)}</p>${h}</div>`).join("");
    const os = c.os ? `<div class="card"><h4>${esc(c.os.name)} <span class="rc">${esc(c.os.version || c.os.kernel_version || "")}</span></h4>` +
      `${c.os.cpe ? tags([c.os.cpe]) : note("warn", "No CPE")}${facts(c.os, P + "/os", ["name", "version", "cpe"])}</div>` : "";
    const sw = (c.hosted_software || []).map((s, j) => {
      const p = `${P}/hosted_software/${j}`;
      return `<div class="card" title="${esc(p)}"><h4>${esc(s.name)} <span class="rc">${esc(s.version || "")}</span></h4>` +
        (s.role ? `<p class="rd">${esc(s.role)}</p>` : "") +
        `${s.cpe || s.listening_port != null ? tags([s.cpe, s.listening_port != null ? `port ${s.listening_port}` : ""].filter(Boolean)) : ""}` +
        (s.cpe ? "" : note("warn", "No CPE")) +
        (s.operational_parameters ? `<details class="ops"><summary>Operational parameters</summary>${facts(s.operational_parameters, p + "/operational_parameters")}</details>` : "") + `</div>`;
    }).join("");
    const diag = (c.diagnostic_services || []).map((d, j) =>
      `<div class="card"><h4>${esc(d.service_id ? "UDS " + d.service_id : "")} ${esc(d.routine || d.operation || "")}</h4>${facts(d, `${P}/diagnostic_services/${j}`, ["service_id", "routine", "operation"])}</div>`).join("");
    const insts = membersOf.get(n.id) || [];
    const nf = findingIdx([n.id, ...insts]).length;
    return head({ kind: "component", label: "Component", title: c.name || n.label,
        desc: `<code>${esc(n.id)}</code>${c.type ? " · " + esc(c.type) : ""} · in ${jump(n.zone, (zoneById.get(n.zone) || {}).label)}` + (c.role ? `<br>${esc(c.role)}` : ""),
        stat: [n.asil ? [n.asil.replace("ASIL-", "ASIL "), "safety"] : ["—", "no ASIL"], [String(nf), nf === 1 ? "finding" : "findings"],
          insts.length ? [String(insts.length), "instances"] : [String(assetsOf(n.id).length), "assets"]],
        actions: insts.length ? `<button type="button" class="pill-btn" data-toggle="${esc(n.id)}">${expanded.has(n.id) ? "Collapse" : "Expand"} ${insts.length} instances</button>` : "",
        path: P }) +
      findingsSection([n.id, ...insts]) +
      section("Security configuration", sec || note("warn", "No security_configuration on this component or its software.")) +
      section("Instances", list(insts.map((x) => row({ id: x, tone: "ink", name: esc(nodeById.get(x).label), path: x }))), insts.length || null) +
      section("Hardware", c.hardware ? `<p>${esc(c.hardware)}</p>` : "") +
      section("Operating system", os) +
      section("Software", sw, (c.hosted_software || []).length || null) +
      section("Diagnostic services", diag, (c.diagnostic_services || []).length || null) +
      section("Diagnostic programming", c.diagnostic_programming ? facts(c.diagnostic_programming, P + "/diagnostic_programming") : "") +
      section("Physical access", c.physical_access ? facts(c.physical_access, P + "/physical_access") : "") +
      section("Hosted assets", assetsHtml(assetsOf(n.id)), assetsOf(n.id).length || null) +
      section("Interfaces", tags(c.interfaces || []), (c.interfaces || []).length) +
      rawSection(P);
  }
  function instanceHtml(n) {
    const c = at(nodeById.get(n.parent).json_path) || {};
    return head({ kind: "instance", label: "Instance", title: n.id, desc: `Instance of ${jump(n.parent, c.name)}`, path: n.json_path }) +
      findingsSection([n.id]) +
      section("Inherited from the component", note("neutral", `${n.asil ? esc(n.asil) + ". " : ""}Hardware, software and security configuration are declared on the component.`)) +
      rawSection(n.json_path);
  }
  function entryHtml(n) {
    const label = n.kind === "external" ? "External end" : n.physical ? "Physical access point" : "Remote entry point";
    const decl = at(n.json_path);
    const comps = n.reach ? n.reach.nodes.filter((id) => ["component", "instance"].includes((nodeById.get(id) || {}).kind)) : [];
    return head({ kind: n.physical ? "physical" : "entry", label, title: n.label,
        desc: `Attached to ${(n.reaches || []).map((x) => jump(x)).join(", ") || "—"}`,
        stat: n.reach ? [[String(reachCount(n)), "reachable"], [String(findingIdx([n.id]).length), "findings"]] : null, path: n.json_path }) +
      findingsSection([n.id]) +
      section("Access", decl && typeof decl === "object" ? facts(decl, n.json_path, ["interface_id", "messages", "entry_points", "diagnostic_access", "connection_id", "source_component", "target_component", "name"]) : "") +
      (n.reach ? section("Reachable", list(comps.map((id) => { const m = nodeById.get(id);
        return row({ id, tone: "ink", name: esc(m.label), desc: m.name && m.name !== m.label ? esc(m.name) : "", path: id }); })) +
        note("neutral", "Follows declared source → target directions (D17). Topology only, not attack feasibility."), comps.length) : "") +
      rawSection(n.json_path);
  }
  function edgeStats(e, conn) {
    return [[PLABEL[e.protection ? e.protection.level : e.kind], "protection"], [String(findingIdx([e.id]).length), "findings"],
      [String(((conn || {}).messages || []).length), "messages"]];
  }
  const edgeColor_ = (e) => PCOL[e.protection ? e.protection.level : e.kind] || PCOL.unknown;
  function connectionHtml(e) {
    const conn = connByID.get(e.element_id) || {};
    return head({ kind: "connection", label: "Connection", color: edgeColor_(e), title: conn.name || e.label,
        desc: `<code>${esc(e.element_id)}</code> · ${jump(e.source)} → ${jump(e.target)}` +
          ((conn.adjacent_components || []).length ? `<br>Also on the bus: ${conn.adjacent_components.map((x) => jump(x)).join(", ")}` : "") +
          (conn.purpose ? `<br>${esc(conn.purpose)}` : ""),
        stat: edgeStats(e, conn), path: e.json_path }) +
      findingsSection([e.id]) +
      protectionSection(e, conn) +
      section("Transport", `<dl class="facts">${factRow("medium", esc(conn.medium || "—"))}${factRow("protocol", esc(conn.protocol || "—"))}` +
        ((conn.target_instances || []).length ? factRow("target instances", conn.target_instances.map((x) => jump(x)).join(", ")) : "") + `</dl>`) +
      section("Messages", (conn.messages || []).map((m) => messageHtml(m, conn)).join("") || note("neutral", "No message list; see the protocol."), (conn.messages || []).length) +
      section(`Receiver behaviour`, receiverBehaviour(compByID.get(conn.target_component))) +
      section("Assets on this connection", assetsHtml(assetsOn(e.element_id)), assetsOn(e.element_id).length || null) +
      section("Diagnostic access", conn.diagnostic_access ? facts(conn.diagnostic_access, e.json_path + "/diagnostic_access") : "") +
      section("Physical access", conn.physical_access ? facts(conn.physical_access, e.json_path + "/physical_access") : "") +
      rawSection(e.json_path);
  }
  function messageEdgeHtml(e) {
    const m = at(e.json_path) || {}, conn = connByID.get(e.element_id) || {};
    return head({ kind: "message", label: "Message-level edge", color: edgeColor_(e), title: `${m.can_id || ""} ${m.name || ""}`.trim(),
        desc: `Carried on ${connJump(e.element_id)} · ${jump(e.source)} → ${jump(e.target)}`, stat: edgeStats(e, { messages: [m] }), path: e.json_path }) +
      findingsSection([e.id]) + protectionSection(e, conn) + section("Message", messageHtml(m, conn)) +
      section("Receiver behaviour", receiverBehaviour(compByID.get(e.target))) + rawSection(e.json_path);
  }
  function entryEdgeHtml(e) {
    const conn = connByID.get(e.element_id) || {};
    const connPtr = e.json_path.replace(/\/entry_points\/\d+$/, "");
    return head({ kind: "entry", label: "Entry-point edge", color: edgeColor_(e), title: e.label,
        desc: `From ${jump(e.source)} into ${jump(e.target)} · on <code>${esc(e.element_id)}</code>`, stat: edgeStats(e, conn), path: e.json_path }) +
      findingsSection([e.id]) + protectionSection(e, conn) +
      section("Transport", `<dl class="facts">${factRow("medium", esc(conn.medium || "—"))}${factRow("protocol", esc(conn.protocol || "—"))}</dl>`) +
      section("Diagnostic access", conn.diagnostic_access ? facts(conn.diagnostic_access, connPtr + "/diagnostic_access") : "") +
      rawSection(e.json_path);
  }
  function otherEdgeHtml(e) {
    const o = at(e.json_path);
    return head({ kind: e.kind === "physical" ? "physical" : "diagnostic", label: e.kind === "physical" ? "Physical access path" : "Diagnostic route",
        color: PCOL[e.kind], title: e.label, desc: `${jump(e.source)} → ${jump(e.target)} · on ${connJump(e.element_id)}`, path: e.json_path }) +
      findingsSection([e.id]) + protectionSection(e) +
      section("Details", o && typeof o === "object" ? facts(o, e.json_path) : "") + rawSection(e.json_path);
  }
  function mergedHtml(d) {
    const ms = d.members.map((id) => edgeById.get(id));
    return head({ kind: "merged", label: "Merged edges", color: PCOL[d.protection], title: `${ms.length} edges`,
        desc: `${esc(d.source)} → ${esc(d.target)}. A zone is folded; these edges cross its border (D19).`,
        stat: [[PLABEL[d.protection] || d.protection, "weakest"], [String(findingIdx(d.members).length), "findings"], [String(ms.length), "edges"]] }) +
      findingsSection(d.members) +
      section("Members", list(ms.map((e) => row({ id: e.id, tone: PCOL[e.protection ? e.protection.level : e.kind], name: esc(e.label || e.id),
        desc: esc(PLABEL[e.protection ? e.protection.level : e.kind]), path: e.id }))), ms.length);
  }
  function zoneHtml(id) {
    const z = zoneById.get(id);
    const members = G.nodes.filter((n) => n.kind === "component" && n.zone === id);
    const ids = members.flatMap((n) => [n.id, ...(membersOf.get(n.id) || [])]);
    return head({ kind: "zone", label: "Trust zone", title: z.label, desc: `<code>${esc(z.trust_zone)}</code>`,
        stat: [[String(members.length), "components"], [String(findingIdx(ids).length), "findings"], [collapsed.has(id) ? "folded" : "open", "view"]],
        actions: `<button type="button" class="pill-btn" data-zone="${esc(id)}">${collapsed.has(id) ? "Unfold zone" : "Fold zone"}</button>` }) +
      findingsSection(ids) +
      section("Components", list(members.map((n) => row({ id: n.id, tone: hasFlag(n.id) ? "bad" : "ink", name: esc(n.label),
        desc: n.name && n.name !== n.label ? esc(n.name) : "", path: n.id }))), members.length);
  }
  function drawerHtml(el) {
    const d = el.data();
    if (el.isEdge()) {
      if (d.members && !d.ref) return mergedHtml(d);
      const e = edgeById.get(d.ref);
      if (e.kind === "connection") return connectionHtml(e);
      if (e.kind === "message") return messageEdgeHtml(e);
      if (e.kind === "entry") return entryEdgeHtml(e);
      return otherEdgeHtml(e);
    }
    if (d.kind === "zone" || d.kind === "zonebox") return zoneHtml(d.id);
    const n = nodeById.get(d.id);
    if (n.kind === "component") return componentHtml(n);
    if (n.kind === "instance") return instanceHtml(n);
    return entryHtml(n);
  }
  function openDrawer(el) {
    pane.innerHTML = drawerHtml(el);
    pane.scrollTop = 0;
    document.body.classList.add("pane-open");
    cy.resize();
  }
  // Copy a JSON pointer; file:// pages may lack the async clipboard API.
  function copyText(text, btn) {
    const done = () => { btn.setAttribute("title", "Copied"); btn.setAttribute("aria-label", "Copied"); setTimeout(() => { btn.setAttribute("title", "Copy JSON pointer"); btn.setAttribute("aria-label", "Copy JSON pointer"); }, 1500); };
    if (navigator.clipboard && window.isSecureContext) { navigator.clipboard.writeText(text).then(done, () => {}); return; }
    const t = document.createElement("textarea");
    t.value = text; t.style.position = "fixed"; t.style.opacity = "0";
    document.body.appendChild(t); t.select();
    try { document.execCommand("copy"); done(); } catch (_) { /* nothing to do */ }
    t.remove();
  }
  function closeDrawer() { document.body.classList.remove("pane-open"); cy.resize(); }
  pane.addEventListener("click", (e) => {
    if (e.target.closest("[data-close]")) { reset(); return; }
    const c = e.target.closest("[data-copy]");
    if (c) { copyText(c.dataset.copy, c); return; }
    const t = e.target.closest("[data-toggle]");
    if (t) { toggleGroup(t.dataset.toggle); return; }
    const z = e.target.closest("[data-zone]");
    if (z) { toggleZone(z.dataset.zone); return; }
    const j = e.target.closest("[data-jump]");
    if (j) selectId(j.dataset.jump);
  });

  // ---------------------------------------------------------------- focus and reachability
  function clearHighlight() { cy.elements().removeClass("dim sel match"); setStatus(""); }
  // Keep `keep` plus what visually contains it (zones, group boxes) and the labels of kept edges.
  function dimExcept(keep) {
    let k = keep;
    const byId = (ids) => cy.nodes().filter((n) => ids.has(n.id()));
    for (let i = 0; i < 2; i++) k = k.union(byId(new Set(k.nodes().map((n) => n.data("container")).filter(Boolean))));
    const edgeIds = new Set(k.edges().map((e) => e.id()));
    k = k.union(cy.nodes("[kind='elabel']").filter((l) => edgeIds.has(l.data("edge"))));
    cy.elements().addClass("dim");
    k.removeClass("dim");
  }
  // Drawn elements standing for an entry point's reach (D17).
  function reachElements(n) {
    const nodes = new Set(n.reach.nodes.map(visNode).filter(Boolean)), edges = new Set(n.reach.edges);
    return cy.nodes().filter((x) => nodes.has(x.id())).union(cy.edges().filter((e) =>
      edges.has(e.data("ref")) || (e.data("members") || []).some((m) => edges.has(m))));
  }
  const groupMembers = (el) => cy.nodes("[kind='instance']").filter((i) => i.data("container") === el.id());
  function focus(el) {
    clearHighlight();
    el.addClass("sel");
    const d = el.data(), n = el.isNode() ? nodeById.get(d.id) : null;
    if (n && n.reach) {
      dimExcept(reachElements(n));
      const count = n.reach.nodes.filter((id) => ["component", "instance"].includes((nodeById.get(id) || {}).kind)).length;
      setStatus(`Reachable from ${n.label}: ${count} components and instances (topology, not feasibility)`);
    } else if (el.isNode() && d.kind !== "zone") {
      const m = groupMembers(el);
      dimExcept(el.closedNeighborhood().union(m).union(m.closedNeighborhood()));
      setStatus("Focus: " + String(d.label).split("\n")[0]);
    } else if (el.isEdge()) {
      dimExcept(el.union(el.connectedNodes()));
    }
  }
  function select(el) {
    if (!el || el.empty()) return;
    if (el.isNode() && el.data("kind") === "elabel") el = cy.getElementById(el.data("edge"));
    focus(el);
    openDrawer(el);
  }
  // Select a graph element by its graph ID, making it visible first:
  // switch on its layer, unfold its zone, expand its group.
  async function selectId(id) {
    let need = false;
    const n = nodeById.get(id), e = edgeById.get(id);
    const isEntry = (x) => { const k = (nodeById.get(x) || {}).kind; return k === "entry" || k === "external"; };
    if (((n && isEntry(id)) || (e && (isEntry(e.source) || isEntry(e.target)))) && !layers.entries) { layers.entries = true; need = true; }
    if (e && e.kind === "diagnostic" && !layers.diag) { layers.diag = true; need = true; }
    for (const end of n ? [id] : e ? [e.source, e.target] : zoneById.has(id) ? [] : []) {
      const z = zoneOf(end);
      if (z && collapsed.has(z)) { collapsed.delete(z); need = true; }
    }
    const inst = n && n.kind === "instance" ? n : e && nodeById.get(e.target) && nodeById.get(e.target).kind === "instance" ? nodeById.get(e.target) : null;
    if (inst && !expanded.has(inst.parent)) { expanded.add(inst.parent); need = true; }
    if (need) { syncLayerBoxes(); await rebuild(); }
    let el = cy.getElementById(id);
    if (el.empty()) el = cy.edges().filter((x) => x.data("ref") === id).first();
    if (el.empty()) return false;
    select(el);
    // Fit what stays highlighted (the reach set, or the neighbourhood).
    const kept = cy.elements().not(".dim").filter((x) => x.data("kind") !== "zone");
    cy.stop();
    cy.fit(kept.nonempty() ? kept : el, 50);
    if (cy.zoom() > 1.4) { cy.zoom(1.4); cy.center(el); }
    return true;
  }
  // Clearing a selection never moves the camera; "Fit" (or F) does that.
  function reset() { clearHighlight(); closeDrawer(); }

  async function toggleGroup(id) {
    if (expanded.has(id)) expanded.delete(id); else expanded.add(id);
    syncLayerBoxes();
    await rebuild();
    const n = cy.getElementById(id);
    if (n.nonempty() && document.body.classList.contains("pane-open")) { select(n); fitView(); }
  }
  async function toggleZone(id) {
    if (collapsed.has(id)) collapsed.delete(id); else collapsed.add(id);
    syncLayerBoxes();
    await rebuild();
    const z = cy.getElementById(id);
    if (z.nonempty() && document.body.classList.contains("pane-open")) { openDrawer(z); fitView(); }
  }

  cy.on("tap", "node, edge", (evt) => select(evt.target));
  cy.on("dbltap", "node[kind='component'][?instanceCount]", (evt) => toggleGroup(evt.target.id()));
  cy.on("dbltap", "node[kind='zone'], node[kind='zonebox']", (evt) => toggleZone(evt.target.id()));
  cy.on("tap", (evt) => { if (evt.target === cy) reset(); });

  // ---------------------------------------------------------------- layers
  const LAYERS = [
    ["zones", "Trust zones"], ["entries", "Entry points"], ["protection", "Protection colouring"],
    ["assets", "Assets overlay"], ["asil", "ASIL badges"], ["diag", "Diagnostic routes"], ["labels", "Edge labels"],
  ];
  // Style-only layers restyle in place; the rest change what ELK lays out.
  const STYLE_ONLY = new Set(["zones", "protection", "asil"]);
  const layersEl = document.getElementById("layers");
  layersEl.innerHTML = LAYERS.map(([k, t]) => `<label><input type="checkbox" data-layer="${k}"> ${t}</label>`).join("") +
    `<hr><label><input type="checkbox" id="expand-all"> Expand all multi-instance components</label>` +
    `<label><input type="checkbox" id="collapse-zones"> Fold all zones</label>`;
  function syncLayerBoxes() {
    layersEl.querySelectorAll("[data-layer]").forEach((b) => { b.checked = layers[b.dataset.layer]; });
    const groups = G.nodes.filter((n) => n.instance_count);
    document.getElementById("expand-all").checked = groups.length > 0 && groups.every((n) => expanded.has(n.id));
    document.getElementById("collapse-zones").checked = G.zones.length > 0 && G.zones.every((z) => collapsed.has(z.id));
  }
  async function setLayer(k, on) {
    layers[k] = on;
    syncLayerBoxes();
    if (STYLE_ONLY.has(k)) applyStyleLayers(); else await rebuild();
  }
  layersEl.addEventListener("change", (e) => {
    const k = e.target.dataset.layer;
    if (k) { setLayer(k, e.target.checked); return; }
    if (e.target.id === "expand-all") {
      for (const n of G.nodes) if (n.instance_count) { if (e.target.checked) expanded.add(n.id); else expanded.delete(n.id); }
      rebuild();
    }
    if (e.target.id === "collapse-zones") {
      for (const z of G.zones) { if (e.target.checked) collapsed.add(z.id); else collapsed.delete(z.id); }
      rebuild();
    }
  });
  syncLayerBoxes();
  document.querySelectorAll("[data-menu]").forEach((b) => b.addEventListener("click", (e) => {
    const m = b.parentElement, was = m.classList.contains("open");
    document.querySelectorAll(".menu.open").forEach((x) => x.classList.remove("open"));
    if (!was) m.classList.add("open");
    e.stopPropagation();
  }));
  document.addEventListener("click", (e) => { if (!e.target.closest(".menu")) document.querySelectorAll(".menu.open").forEach((x) => x.classList.remove("open")); });

  // ---------------------------------------------------------------- search
  const searchEl = document.getElementById("search");
  const haystacks = new Map(G.nodes.map((n) => {
    let s = `${n.id} ${n.label} ${n.name || ""}`;
    const c = n.kind === "component" ? compByID.get(n.id) : null;
    if (c) {
      s += ` ${c.type || ""} ${c.role || ""} ${c.hardware || ""} ${(c.interfaces || []).join(" ")}`;
      if (c.os) s += ` ${c.os.name || ""} ${c.os.version || ""} ${c.os.cpe || ""}`;
      for (const sw of c.hosted_software || []) s += ` ${sw.name} ${sw.version || ""} ${sw.cpe || ""}`;
    }
    return [n.id, s.toLowerCase()];
  }));
  // Graph node IDs matching q, in graph order.
  const searchIds = (q) => { q = q.trim().toLowerCase(); return q ? G.nodes.filter((n) => haystacks.get(n.id).includes(q)).map((n) => n.id) : []; };
  function runSearch() {
    const q = searchEl.value.trim();
    clearHighlight();
    if (!q) return [];
    const ids = searchIds(q);
    const shown = new Set(ids.map(visNode).filter(Boolean));
    const hits = cy.nodes().filter((n) => shown.has(n.id()));
    hits.addClass("match");
    dimExcept(hits);
    setStatus(`${ids.length} match${ids.length === 1 ? "" : "es"} for “${q}”${ids.length ? " — Enter to open the first" : ""}`);
    return ids;
  }
  searchEl.addEventListener("input", runSearch);
  searchEl.addEventListener("keydown", (e) => { if (e.key === "Enter") { const ids = runSearch(); if (ids.length) selectId(ids[0]); } });
  document.addEventListener("keydown", (e) => {
    if (e.key !== "Escape" || document.querySelector("dialog[open]")) return;
    document.querySelectorAll(".menu.open").forEach((m) => m.classList.remove("open"));
    if (document.activeElement === searchEl) { searchEl.value = ""; searchEl.blur(); }
    reset();
  });

  // ---------------------------------------------------------------- lint badge and findings panel
  const counts = { error: 0, warning: 0, info: 0 };
  FINDINGS.forEach((f) => counts[f.severity]++);
  const plural = (n, w) => `${n} ${w}${n === 1 ? "" : "s"}`;
  const badge = document.getElementById("lintbadge");
  badge.innerHTML = `<span class="sev-dot" style="background:${counts.error ? SEVCOL.error : counts.warning ? SEVCOL.warning : v("--good")}"></span>` +
    `<span>${plural(counts.error, "error")} · ${plural(counts.warning, "warning")} · ${counts.info} info</span>`;
  const sevOn = { error: true, warning: true, info: true };
  function renderFindings() {
    document.getElementById("filters").innerHTML = ["error", "warning", "info"].map((s) =>
      `<button class="filter ${sevOn[s] ? "" : "off"}" data-sev="${s}"><span class="sev-dot" style="background:${SEVCOL[s]}"></span> ${s === "info" ? counts[s] + " info" : plural(counts[s], s)}</button>`).join(" ");
    const order = { error: 0, warning: 1, info: 2 };
    const rows = FINDINGS.map((f, i) => [f, i]).filter(([f]) => sevOn[f.severity]).sort((a, b) => order[a[0].severity] - order[b[0].severity] || a[1] - b[1]);
    document.getElementById("findings-list").innerHTML = rows.map(([f, i]) =>
      `<div class="row${LINKS[i] ? "" : " nolink"}" data-idx="${i}" title="${LINKS[i] ? "Show " + esc(LINKS[i]) : "Not drawn: nothing this finding concerns is on the canvas"}">` +
      `<span class="chip solid" style="background:${SEVCOL[f.severity]};justify-self:start">${f.severity}</span>` +
      `<b class="mono">${esc(f.rule)}</b><span class="mono">${esc(f.element_id)}</span><span>${esc(f.message)}</span><span class="path">${esc(f.json_path)}</span></div>`).join("") ||
      `<div class="muted" style="padding:10px 14px">${FINDINGS.length ? "No findings at this severity." : "No findings."}</div>`;
  }
  renderFindings();
  function toggleFindings(open) {
    document.body.classList.toggle("findings-open", open);
    cy.resize();
  }
  let lastRow = Promise.resolve(false);
  badge.addEventListener("click", () => toggleFindings(!document.body.classList.contains("findings-open")));
  document.getElementById("findings-close").addEventListener("click", () => toggleFindings(false));
  document.getElementById("findings").addEventListener("click", (e) => {
    const f = e.target.closest("[data-sev]");
    if (f) { sevOn[f.dataset.sev] = !sevOn[f.dataset.sev]; renderFindings(); return; }
    const r = e.target.closest("[data-idx]");
    if (r && LINKS[+r.dataset.idx]) lastRow = selectId(LINKS[+r.dataset.idx]);
  });

  // ---------------------------------------------------------------- legend
  document.getElementById("fit").addEventListener("click", () => fitView());
  document.addEventListener("keydown", (e) => {
    const typing = e.target.closest && e.target.closest("input, textarea, select, [contenteditable]");
    if ((e.key === "f" || e.key === "F") && !typing && !e.ctrlKey && !e.metaKey && !e.altKey) fitView();
  });
  document.getElementById("legend-toggle").addEventListener("click", () => {
    const l = document.getElementById("legend");
    l.classList.toggle("min");
    document.getElementById("legend-toggle").textContent = l.classList.contains("min") ? "Legend ▸" : "Legend ▾";
  });

  // ---------------------------------------------------------------- review (tarav serve --review, D24)
  // Approve and Reject post back to the server, which re-checks the file,
  // records the decision and ends the review; the page then stays as a
  // read-only record of what was decided.
  const REVIEW = CONFIG && CONFIG.review;
  let decided = null;
  function showDecided(ok, title, lines) {
    decided = ok ? "approved" : "rejected";
    const d = document.getElementById("decided");
    d.className = ok ? "ok" : "no";
    d.innerHTML = `<div class="card"><h2>${esc(title)}</h2>${lines.map((l) => `<p>${l}</p>`).join("")}</div>`;
    d.hidden = false;
    document.getElementById("review").querySelectorAll("button").forEach((b) => { b.disabled = true; });
    closeReview();
  }
  async function decide(kind, fields) {
    const r = await fetch(kind, {
      method: "POST", cache: "no-store", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token: REVIEW.token, version: CONFIG.version, reviewer: fields.reviewer || "", comment: fields.comment || "" }),
    });
    let body = {};
    try { body = await r.json(); } catch (e) { /* non-JSON error body */ }
    if (!r.ok) throw new Error(body.error || `server answered ${r.status}`);
    if (kind === "approve") {
      showDecided(true, "Approved", [
        `${esc(body.stage)} approved by <b>${esc(body.reviewer)}</b>. The pipeline can start the next step; you can close this tab.`,
        `<span class="mono">sha256 ${esc(body.sha256)}</span>`]);
    } else {
      showDecided(false, "Rejected", [`${esc(body.stage)} was not approved: ${esc(body.reason)}. The pipeline stops here; you can close this tab.`]);
    }
    return body;
  }
  // One Review button opens a modal with an Approve / Reject toggle. A
  // blocked file can only be rejected; the modal says why.
  const TEXT = {
    approve: { submit: "Approve", comment: "Comment (optional)", placeholder: "",
      help: "Records your name against the file exactly as it is now. Any later edit needs a new review." },
    reject: { submit: "Reject", comment: "Reason", placeholder: "What needs to change",
      help: "The pipeline stops here. Nothing is recorded as approved." },
  };
  const dlg = document.getElementById("review-dialog");
  function reviewForm() { return dlg.querySelector("form"); }
  function setChoice(kind) {
    const f = reviewForm(), tx = TEXT[kind];
    f.decision.value = kind;
    f.dataset.kind = kind;
    f.querySelector(".help").textContent = tx.help;
    f.querySelector(".comment-label").textContent = tx.comment;
    f.comment.placeholder = tx.placeholder;
    const sub = f.querySelector("[type=submit]");
    sub.textContent = tx.submit;
    sub.className = "btn " + (kind === "approve" ? "primary" : "danger solid");
    f.querySelector(".err").textContent = "";
  }
  function openReview() {
    if (decided || dlg.open) return;
    dlg.showModal();
    const f = reviewForm();
    (f.reviewer.value ? f.comment : f.reviewer).focus();
  }
  function closeReview() { if (dlg.open) dlg.close(); }
  if (REVIEW) {
    const box = document.getElementById("review");
    const blocked = REVIEW.passed ? "" :
      `${plural(REVIEW.blocking, "blocking finding")} at or above ${REVIEW.fail_on}`;
    box.innerHTML =
      `<span class="stage">Stage <b>${esc(REVIEW.stage)}</b></span>` +
      `<button class="btn primary${blocked ? " blocked" : ""}" id="review-btn" aria-haspopup="dialog"` +
      `${blocked ? ` title="${esc(blocked)}: the file can only be rejected"` : ""}>` +
      `${blocked ? '<span class="sev-dot"></span>' : ""}Review…</button>`;
    box.hidden = false;
    const name = esc(REVIEW.reviewer || "");
    dlg.innerHTML =
      `<form method="dialog" data-kind="approve">` +
      `<div class="dh"><div><h2 id="review-title">Review ${esc(REVIEW.stage)}</h2>` +
      `<p class="sub">${esc(G.item.name || "")} · ` +
      `${plural(counts.error, "error")}, ${plural(counts.warning, "warning")}, ${counts.info} info</p></div>` +
      `<button type="button" class="x" id="review-cancel-x" aria-label="Close">✕</button></div>` +
      (blocked ? `<p class="blockednote">${esc(blocked)} under the policy. Fix the file to approve it; it reloads here when saved.</p>` : "") +
      `<fieldset class="seg"><legend>Decision</legend>` +
      `<label><input type="radio" name="decision" value="approve"${blocked ? " disabled" : " checked"}><span>Approve</span></label>` +
      `<label><input type="radio" name="decision" value="reject"${blocked ? " checked" : ""}><span>Reject</span></label></fieldset>` +
      `<p class="help"></p>` +
      `<label>Your name<input name="reviewer" required autocomplete="name" value="${name}"></label>` +
      `<label><span class="comment-label"></span><textarea name="comment" maxlength="2000"></textarea></label>` +
      `<div class="err" role="alert"></div>` +
      `<div class="actions"><button type="button" class="btn" id="review-cancel">Cancel</button><button type="submit" class="btn primary"></button></div>` +
      `</form>`;
    dlg.setAttribute("aria-labelledby", "review-title");
    const f = reviewForm();
    setChoice(blocked ? "reject" : "approve");
    document.getElementById("review-btn").addEventListener("click", openReview);
    document.getElementById("review-cancel").addEventListener("click", closeReview);
    document.getElementById("review-cancel-x").addEventListener("click", closeReview);
    // A click on the backdrop lands on the dialog element itself.
    dlg.addEventListener("click", (e) => { if (e.target === dlg) closeReview(); });
    f.addEventListener("change", (e) => { if (e.target.name === "decision") setChoice(e.target.value); });
    f.addEventListener("submit", (e) => {
      e.preventDefault();
      const kind = f.decision.value, err = f.querySelector(".err"), submit = f.querySelector("[type=submit]");
      const fields = { reviewer: f.reviewer.value.trim(), comment: f.comment.value.trim() };
      if (!fields.reviewer) { err.textContent = "Enter your name."; f.reviewer.focus(); return; }
      if (kind === "reject" && !fields.comment) { err.textContent = "Say what needs to change."; f.comment.focus(); return; }
      err.textContent = ""; submit.disabled = true;
      decide(kind, fields).then(closeReview).catch((x) => { err.textContent = x.message; submit.disabled = false; });
    });
  }

  // ---------------------------------------------------------------- live reload (tarav serve only)
  if (CONFIG && CONFIG.live) {
    const seen = CONFIG.version;
    setInterval(() => {
      if (decided) return; // the review server has gone; keep the decision on screen
      fetch("version", { cache: "no-store" }).then((r) => r.text()).then((t) => { if (t && t !== seen) location.reload(); }).catch(() => {});
    }, 1000);
  }

  // ---------------------------------------------------------------- self-check (browser tests)
  // Rendered route vs ELK route, endpoints on a node side, no diagonal
  // segments, and no segment crossing a node it does not connect.
  function routeCheck() {
    const box = (n) => { const p = n.position(), w = n.width(), h = n.height(); return { x1: p.x - w / 2, y1: p.y - h / 2, x2: p.x + w / 2, y2: p.y + h / 2 }; };
    const onSide = (p, b) => (Math.abs(p.x - b.x1) < 1 || Math.abs(p.x - b.x2) < 1) && p.y >= b.y1 - 1 && p.y <= b.y2 + 1 ||
      (Math.abs(p.y - b.y1) < 1 || Math.abs(p.y - b.y2) < 1) && p.x >= b.x1 - 1 && p.x <= b.x2 + 1;
    const hits = (a, c, b) => {
      const x1 = Math.min(a.x, c.x), x2 = Math.max(a.x, c.x), y1 = Math.min(a.y, c.y), y2 = Math.max(a.y, c.y);
      return x2 > b.x1 + 1 && x1 < b.x2 - 1 && y2 > b.y1 + 1 && y1 < b.y2 - 1;
    };
    const solid = cy.nodes("[kind='component'][!box], [kind='instance'], [kind='entry'], [kind='zonebox']");
    let maxErr = 0, loops = 0;
    const offSide = [], crossings = [], diagonal = [];
    cy.edges().forEach((e) => {
      // Self-loops are drawn by Cytoscape as loops, not as ELK segments.
      if (e.source().id() === e.target().id()) { loops++; return; }
      const want = e.data("pts");
      const got = [e.sourceEndpoint(), ...(e.data("bent") ? e.segmentPoints() : []), e.targetEndpoint()];
      if (got.length !== want.length) { maxErr = Infinity; return; }
      got.forEach((p, i) => { maxErr = Math.max(maxErr, Math.hypot(p.x - want[i].x, p.y - want[i].y)); });
      if (!onSide(want[0], box(e.source())) || !onSide(want[want.length - 1], box(e.target()))) offSide.push(e.id());
      for (let i = 1; i < want.length; i++) {
        if (Math.abs(want[i].x - want[i - 1].x) > 0.5 && Math.abs(want[i].y - want[i - 1].y) > 0.5) diagonal.push(e.id());
        solid.forEach((n) => { if (n.id() !== e.source().id() && n.id() !== e.target().id() && hits(want[i - 1], want[i], box(n))) crossings.push(e.id() + " x " + n.id()); });
      }
    });
    return { edges: cy.edges().length, loops, maxErr: +maxErr.toFixed(2), offSide, diagonal, crossings };
  }

  const ready = rebuild();
  // Hooks for the browser tests (D20). IDs are graph IDs unless noted.
  window.__tarav = {
    cy, ready, rebuild, select, selectId, toggleGroup, toggleZone, setLayer, routeCheck, reset, fitView,
    search: (q) => { searchEl.value = q; return runSearch(); },
    // Resolves when a wheel zoom animation has settled.
    zoomSettled: () => (wz.frame ? wz.done : Promise.resolve()),
    openFindings: () => toggleFindings(true),
    // Click the findings-panel row for finding i, as a user would.
    clickFinding: async (i) => {
      const r = document.querySelector(`#findings-list [data-idx="${i}"]`);
      if (!r) return false;
      r.click();
      return lastRow;
    },
    // Cytoscape IDs of elements not dimmed (edge labels excluded).
    undimmed: () => cy.elements().filter((x) => !x.hasClass("dim") && x.data("kind") !== "elabel").map((x) => x.id()).sort(),
    selected: () => cy.elements(".sel").map((x) => x.data("ref") || x.id()),
    drawerHeadings: () => [...pane.querySelectorAll("h3")].map((h) => h.textContent),
    drawerText: () => pane.innerText,
    drawerKind: () => (pane.querySelector(".kindlabel") || {}).textContent || "",
    layers, expanded: () => [...expanded], collapsed: () => [...collapsed], links: LINKS,
    // Review modal: open it, pick a decision and submit, as a user would.
    openReview, closeReview,
    review: async (kind, reviewer, comment) => {
      openReview();
      const f = reviewForm();
      const radio = f.querySelector(`input[name=decision][value="${kind}"]`);
      if (radio.disabled) return { error: kind + " is disabled" };
      radio.click();
      f.reviewer.value = reviewer || ""; f.comment.value = comment || "";
      f.requestSubmit();
      for (let i = 0; i < 100 && !decided && !f.querySelector(".err").textContent; i++) await new Promise((r) => setTimeout(r, 50));
      return decided ? { decided } : { error: f.querySelector(".err").textContent };
    },
    reviewState: () => {
      const f = dlg.querySelector("form");
      return {
        shown: !document.getElementById("review").hidden,
        open: dlg.open,
        choice: f ? f.decision.value : "",
        submit: f ? f.querySelector("[type=submit]").textContent : "",
        approveDisabled: !!(f && f.querySelector("input[value=approve]").disabled),
        decided, overlay: document.getElementById("decided").innerText,
      };
    },
    positions: () => cy.nodes().map((n) => [n.id(), Math.round(n.position("x")), Math.round(n.position("y"))]),
  };
})();
