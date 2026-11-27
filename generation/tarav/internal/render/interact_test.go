package render

import (
	"reflect"
	"sort"
	"strings"
	"testing"

	"tarav/internal/graph"
	"tarav/internal/model"
)

// Browser tests for the M3 interactions (SPEC D20). Each drives the page
// through window.__tarav and checks the result here.

func buildGraph(t *testing.T, rel string) (*model.Item, *graph.Graph) {
	t.Helper()
	it, err := model.Load(read(t, rel))
	if err != nil {
		t.Fatal(err)
	}
	return it, graph.Build(it)
}

func noErrs(t *testing.T, errs []string) {
	t.Helper()
	if len(errs) > 0 {
		t.Errorf("console/page errors: %q", errs)
	}
}

// Every node and edge opens a drawer with the plan §3 sections.
func TestBrowserDrawer(t *testing.T) {
	bin := chrome(t)
	const scenario = `async (t) => {
	  const out = [];
	  const ids = [...t.cy.nodes().map((n) => n.id()).filter((id) => !id.startsWith("lbl:") && !id.startsWith("zone:")),
	               ...t.cy.edges().map((e) => e.data("ref"))];
	  for (const id of ids) { await t.selectId(id); out.push({ id, kind: t.drawerKind(), headings: t.drawerHeadings() }); }
	  return out;
	}`
	want := map[string][]string{ // drawer kind -> headings that must be present (prefix match)
		"Component":             {"Security configuration", "Interfaces"},
		"Connection":            {"Protection", "Transport", "Messages", "Receiver behaviour"},
		"Message-level edge":    {"Protection", "Message", "Receiver behaviour"},
		"Entry-point edge":      {"Protection", "Transport"},
		"Remote entry point":    {"Reachable"},
		"Physical access point": {"Reachable"},
		"Physical access path":  {"Protection"},
		"Diagnostic route":      {"Protection", "Details"},
	}
	for _, rel := range []string{"bbw/item-definition.json", "ota-adas/item-definition.json"} {
		t.Run(rel, func(t *testing.T) {
			var got []struct {
				ID       string   `json:"id"`
				Kind     string   `json:"kind"`
				Headings []string `json:"headings"`
			}
			noErrs(t, run(t, bin, rel, "", scenario, &got))
			if len(got) == 0 {
				t.Fatal("nothing selected")
			}
			kinds := map[string]bool{}
			for _, g := range got {
				kinds[g.Kind] = true
				need, ok := want[g.Kind]
				if !ok {
					t.Errorf("%s: unexpected drawer kind %q", g.ID, g.Kind)
					continue
				}
				for _, h := range need {
					found := false
					for _, x := range g.Headings {
						found = found || strings.HasPrefix(x, h)
					}
					if !found {
						t.Errorf("%s (%s): no %q section in %q", g.ID, g.Kind, h, g.Headings)
					}
				}
			}
			for _, k := range []string{"Component", "Connection", "Remote entry point"} {
				if !kinds[k] {
					t.Errorf("no %s drawer exercised", k)
				}
			}
		})
	}
}

// D17: selecting an entry point leaves exactly its reach undimmed (plus the
// zones that contain reached components), with groups collapsed.
func TestBrowserReach(t *testing.T) {
	bin := chrome(t)
	const scenario = `async (t) => {
	  const out = {};
	  for (const n of t.cy.nodes("[kind='entry']")) { await t.selectId(n.id()); out[n.id()] = t.undimmed(); }
	  return out;
	}`
	for _, rel := range []string{"bbw/item-definition.json", "ota-adas/item-definition.json", "zone/zones-wrap.json"} {
		t.Run(rel, func(t *testing.T) {
			_, g := buildGraph(t, rel)
			var got map[string][]string
			noErrs(t, run(t, bin, rel, "", scenario, &got))
			nodes := map[string]graph.Node{}
			for _, n := range g.Nodes {
				nodes[n.ID] = n
			}
			drawnEdge := map[string]bool{}
			for _, e := range g.Edges {
				_, s := nodes[e.Source]
				_, d := nodes[e.Target]
				drawnEdge[e.ID] = s && d
			}
			entries := 0
			for _, n := range g.Nodes {
				if n.Reach == nil {
					continue
				}
				entries++
				want := map[string]bool{}
				for _, id := range n.Reach.Nodes {
					m := nodes[id]
					if m.Kind == graph.KindInstance {
						id = m.Parent // groups start collapsed
						m = nodes[id]
					}
					want[id] = true
					if m.Zone != "" {
						want[m.Zone] = true
					}
				}
				for _, id := range n.Reach.Edges {
					if drawnEdge[id] {
						want["e:"+id] = true
					}
				}
				var w []string
				for id := range want {
					w = append(w, id)
				}
				sort.Strings(w)
				if !reflect.DeepEqual(got[n.ID], w) {
					t.Errorf("%s undimmed\n  %q\nwant\n  %q", n.ID, got[n.ID], w)
				}
			}
			if entries == 0 || len(got) != entries {
				t.Errorf("checked %d entry points in the page, graph has %d", len(got), entries)
			}
		})
	}
}

// Every findings-panel row selects its linked element, also when zones
// start folded and groups collapsed (the row must unfold and expand).
func TestBrowserFindingsPanel(t *testing.T) {
	bin := chrome(t)
	const scenario = `async (t) => {
	  const fold = new URLSearchParams(location.hash.slice(1)).get("fold");
	  if (fold) for (const z of t.cy.nodes("[kind='zone']").map((n) => n.id())) await t.toggleZone(z);
	  t.openFindings();
	  const out = [];
	  for (let i = 0; i < t.links.length; i++) {
	    if (!t.links[i]) { out.push({ i, link: "", selected: [] }); continue; }
	    const ok = await t.clickFinding(i);
	    out.push({ i, link: t.links[i], ok, selected: t.selected() });
	    if (fold) for (const z of t.cy.nodes("[kind='zone']").map((n) => n.id())) await t.toggleZone(z);
	  }
	  return { rows: out, route: t.routeCheck() };
	}`
	for _, c := range []struct{ rel, hash string }{
		{"bbw/item-definition.json", ""},
		{"bbw/item-definition.json", "fold=1"},
		{"lint/L002-duplicate-ids.json", "fold=1"}, // links into instances
		{"lint/L017-missing-flags.json", ""},
		{"lint/L001-dangling-refs.json", ""}, // includes findings with no drawn element
	} {
		t.Run(c.rel+"#"+c.hash, func(t *testing.T) {
			var got struct {
				Rows []struct {
					I        int      `json:"i"`
					Link     string   `json:"link"`
					OK       bool     `json:"ok"`
					Selected []string `json:"selected"`
				} `json:"rows"`
				Route *route `json:"route"`
			}
			noErrs(t, run(t, bin, c.rel, c.hash, scenario, &got))
			if len(got.Rows) == 0 {
				t.Fatal("no findings rows")
			}
			for _, r := range got.Rows {
				if r.Link == "" {
					continue
				}
				if !r.OK || len(r.Selected) != 1 || r.Selected[0] != r.Link {
					t.Errorf("row %d (link %s): ok=%v selected %q", r.I, r.Link, r.OK, r.Selected)
				}
			}
			checkRoute(t, "after rows", got.Route)
		})
	}
}

func TestBrowserSearchAndLayers(t *testing.T) {
	bin := chrome(t)
	const scenario = `async (t) => {
	  const r = {};
	  r.cpe = t.search("cpe:2.3:a:bluez");
	  r.none = t.search("no-such-thing-xyz");
	  r.byID = t.search("emba-fl");
	  t.search("");
	  const count = (sel) => t.cy.elements(sel).length;
	  const probe = () => ({
	    entries: count("node[kind='entry']"), diag: count("edge[kind='diagnostic']"), labels: count("node[kind='elabel']"),
	    flatZones: count("node[kind='zone'].flat"), assetLabels: t.cy.nodes().filter((n) => String(n.style("label")).includes("◆")).length,
	    greyEdges: t.cy.edges().filter((e) => e.style("line-color") === "rgb(154,152,143)" && !e.data("dashed")).length,
	    asilCards: t.cy.nodes("[kind='component']").filter((n) => String(n.style("background-image")).includes("ASIL")).length,
	    route: t.routeCheck() });
	  r.base = probe();
	  r.off = {};
	  for (const k of ["entries", "diag", "labels", "zones", "protection", "asil"]) { await t.setLayer(k, false); r.off[k] = probe(); await t.setLayer(k, true); }
	  await t.setLayer("assets", true); r.assets = probe(); await t.setLayer("assets", false);
	  return r;
	}`
	type probe struct {
		Entries, Diag, Labels, FlatZones, AssetLabels, GreyEdges, AsilCards int
		Route                                                               *route
	}
	var got struct {
		CPE, None, ByID []string
		Base            probe
		Off             map[string]probe
		Assets          probe
	}
	noErrs(t, run(t, bin, "bbw/item-definition.json", "", scenario, &got))
	// COMP-VDCM hosts BlueZ (cpe:2.3:a:bluez:bluez:5.54).
	if !reflect.DeepEqual(got.CPE, []string{"COMP-VDCM"}) {
		t.Errorf("search by CPE = %q", got.CPE)
	}
	if len(got.None) != 0 || !reflect.DeepEqual(got.ByID, []string{"COMP-EMBA-FL"}) {
		t.Errorf("search none=%q byID=%q", got.None, got.ByID)
	}
	b := got.Base
	if b.Entries == 0 || b.Diag == 0 || b.Labels == 0 || b.FlatZones != 0 || b.AssetLabels != 0 || b.GreyEdges != 0 || b.AsilCards == 0 {
		t.Errorf("base state %+v", b)
	}
	checkRoute(t, "base", b.Route)
	for k, ok := range map[string]bool{
		"entries": got.Off["entries"].Entries == 0, "diag": got.Off["diag"].Diag == 0, "labels": got.Off["labels"].Labels == 0,
		"zones": got.Off["zones"].FlatZones > 0, "protection": got.Off["protection"].GreyEdges > 0, "asil": got.Off["asil"].AsilCards == 0,
	} {
		if !ok {
			t.Errorf("layer %s off had no effect: %+v", k, got.Off[k])
		}
		checkRoute(t, "layer "+k+" off", got.Off[k].Route)
	}
	if got.Assets.AssetLabels == 0 {
		t.Errorf("assets overlay on: no ◆ labels: %+v", got.Assets)
	}
	checkRoute(t, "assets on", got.Assets.Route)
}

// D19: folding each zone, then all zones, keeps routing clean, hides the
// zone's members, and merged edges carry the weakest member level.
func TestBrowserZoneCollapse(t *testing.T) {
	bin := chrome(t)
	const scenario = `async (t) => {
	  const zones = t.cy.nodes("[kind='zone']").map((n) => n.id()), out = { each: {} };
	  const snap = () => ({ route: t.routeCheck(), boxes: t.cy.nodes("[kind='zonebox']").map((n) => n.id()),
	    merged: t.cy.edges().filter((e) => e.data("members")).map((e) => ({ id: e.id(), members: e.data("members"), protection: e.data("protection") })) });
	  for (const z of zones) { await t.toggleZone(z); out.each[z] = snap(); await t.toggleZone(z); }
	  for (const z of zones) await t.toggleZone(z);
	  out.all = snap();
	  return out;
	}`
	strength := map[string]int{"none": 0, "unknown": 1, "crc": 2, "mac": 3, "mac_freshness": 4, "encrypted": 5}
	type snap struct {
		Route  *route
		Boxes  []string
		Merged []struct {
			ID         string
			Members    []string
			Protection string
		}
	}
	for _, rel := range []string{"bbw/item-definition.json", "ota-adas/item-definition.json", "zone/zones-wrap.json"} {
		t.Run(rel, func(t *testing.T) {
			_, g := buildGraph(t, rel)
			level := map[string]string{}
			for _, e := range g.Edges {
				if e.Protection != nil {
					level[e.ID] = string(e.Protection.Level)
				}
			}
			var got struct {
				Each map[string]snap
				All  snap
			}
			noErrs(t, run(t, bin, rel, "", scenario, &got))
			if len(got.Each) != len(g.Zones) {
				t.Fatalf("folded %d zones, graph has %d", len(got.Each), len(g.Zones))
			}
			check := func(name string, s snap) {
				checkRoute(t, name, s.Route)
				for _, m := range s.Merged {
					want := ""
					for _, id := range m.Members {
						if l, ok := level[id]; ok && (want == "" || strength[l] < strength[want]) {
							want = l
						}
					}
					if want != "" && m.Protection != want {
						t.Errorf("%s: merged %s = %s, weakest member is %s", name, m.ID, m.Protection, want)
					}
				}
			}
			for z, s := range got.Each {
				if !reflect.DeepEqual(s.Boxes, []string{z}) {
					t.Errorf("fold %s: boxes %q", z, s.Boxes)
				}
				check("fold "+z, s)
			}
			if len(got.All.Boxes) != len(g.Zones) {
				t.Errorf("fold all: %d boxes", len(got.All.Boxes))
			}
			check("fold all", got.All)
		})
	}
}

// One wheel notch zooms about 7% around the cursor, eased over a few
// frames; quick notches accumulate; a burst is capped; a small trackpad
// delta zooms a little; the point under the cursor stays put.
func TestBrowserWheelZoom(t *testing.T) {
	bin := chrome(t)
	const scenario = `async (t) => {
	  const el = document.getElementById("cy"), r = el.getBoundingClientRect();
	  const at = { clientX: r.left + r.width / 3, clientY: r.top + r.height / 3 };
	  const send = (o) => el.dispatchEvent(new WheelEvent("wheel", Object.assign({ bubbles: true, cancelable: true }, at, o)));
	  const wheel = async (...os) => { const z = t.cy.zoom(); for (const o of os) send(o); const mid = t.cy.zoom() / z; await t.zoomSettled(); return { mid, ratio: t.cy.zoom() / z }; };
	  // the model point under the cursor before and after
	  const model = () => { const p = t.cy.pan(), z = t.cy.zoom(); return { x: (r.width / 3 - p.x) / z, y: (r.height / 3 - p.y) / z }; };
	  const m0 = model();
	  const out = await wheel({ deltaY: 100 });
	  const m1 = model();
	  return { out, in: await wheel({ deltaY: -100 }), lines: await wheel({ deltaY: 3, deltaMode: 1 }),
	    two: await wheel({ deltaY: 100 }, { deltaY: 100 }), burst: await wheel({ deltaY: 5000 }),
	    pad: await wheel({ deltaY: 4 }), drift: Math.hypot(m1.x - m0.x, m1.y - m0.y) };
	}`
	type step struct{ Mid, Ratio float64 }
	var got struct {
		Out, In, Lines, Two, Burst, Pad step
		Drift                           float64
	}
	noErrs(t, run(t, bin, "bbw/item-definition.json", "", scenario, &got))
	near := func(name string, v, want float64) {
		if v < want-0.005 || v > want+0.005 {
			t.Errorf("%s zoom ratio %.4f, want ≈%.4f", name, v, want)
		}
	}
	near("one notch out", got.Out.Ratio, 0.93)
	near("one notch in", got.In.Ratio, 1/0.93)
	near("3 lines (≈100 px)", got.Lines.Ratio, 0.93)
	near("two quick notches", got.Two.Ratio, 0.93*0.93)
	near("burst capped at 200 px", got.Burst.Ratio, 0.93*0.93)
	if got.Pad.Ratio < 0.995 || got.Pad.Ratio >= 1 {
		t.Errorf("small trackpad delta zoom ratio %.4f, want just under 1", got.Pad.Ratio)
	}
	// Smooth: nothing jumps on the event itself; the view eases afterwards.
	if got.Out.Mid != 1 {
		t.Errorf("zoom changed synchronously on the wheel event (ratio %.4f); want an eased animation", got.Out.Mid)
	}
	if got.Drift > 0.5 {
		t.Errorf("point under the cursor moved %.2f model units", got.Drift)
	}
}

// Clearing a selection (empty-canvas click, the pane's close button, Esc)
// keeps the user's zoom and pan; only Fit re-fits the graph.
func TestBrowserResetKeepsViewport(t *testing.T) {
	bin := chrome(t)
	const scenario = `async (t) => {
	  const vp = () => ({ z: +t.cy.zoom().toFixed(4), x: Math.round(t.cy.pan().x), y: Math.round(t.cy.pan().y) });
	  t.cy.zoom({ level: t.cy.zoom() * 2.2, renderedPosition: { x: 200, y: 200 } });
	  t.cy.panBy({ x: -137, y: 61 });
	  const start = vp(), out = { start };
	  t.select(t.cy.getElementById("COMP-VDCM"));
	  out.afterSelect = vp();
	  t.cy.emit("tap");                         // empty canvas
	  out.afterCanvas = vp();
	  t.select(t.cy.getElementById("e:CONN-BRK-03"));
	  document.querySelector("#pane [data-close]").click();
	  out.afterClose = vp();
	  out.paneOpen = document.body.classList.contains("pane-open");
	  t.select(t.cy.getElementById("ep:INT-BLE-DIAG"));
	  document.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape", bubbles: true }));
	  out.afterEsc = vp();
	  document.getElementById("fit").click();
	  out.afterFit = vp();
	  t.cy.zoom({ level: t.cy.zoom() * 2, renderedPosition: { x: 100, y: 100 } });
	  document.dispatchEvent(new KeyboardEvent("keydown", { key: "f", bubbles: true }));
	  out.afterKey = vp();
	  return out;
	}`
	type vp struct {
		Z    float64
		X, Y int
	}
	var got struct {
		Start, AfterSelect, AfterCanvas, AfterClose, AfterEsc, AfterFit, AfterKey vp
		PaneOpen                                                                  bool
	}
	noErrs(t, run(t, bin, "bbw/item-definition.json", "", scenario, &got))
	for name, v := range map[string]vp{"select": got.AfterSelect, "empty-canvas click": got.AfterCanvas, "close button": got.AfterClose, "Esc": got.AfterEsc} {
		if v != got.Start {
			t.Errorf("after %s the viewport moved: %+v, want %+v", name, v, got.Start)
		}
	}
	if got.PaneOpen {
		t.Error("close button left the pane open")
	}
	if got.AfterFit == got.Start || got.AfterFit.Z >= got.Start.Z {
		t.Errorf("Fit did not zoom out to the whole graph: %+v (was %+v)", got.AfterFit, got.Start)
	}
	if got.AfterKey != got.AfterFit {
		t.Errorf("F key fit %+v, want the same view as the Fit button %+v", got.AfterKey, got.AfterFit)
	}
}
