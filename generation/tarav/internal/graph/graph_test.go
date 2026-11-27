package graph

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"tarav/internal/model"
)

const testdata = "../../testdata"

var update = flag.Bool("update", false, "rewrite testdata/golden/graph/")

// inputs are the samples plus the graph-specific fixtures.
var inputs = []string{
	"bbw/item-definition.json",
	"ota-adas/item-definition.json",
	"zone/zones-wrap.json",
	"valid/protection.json",
	"graph/edge-cases.json",
}

func load(t *testing.T, rel string) (*model.Item, []byte) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(testdata, rel))
	if err != nil {
		t.Fatal(err)
	}
	it, err := model.Load(raw)
	if err != nil {
		t.Fatal(err)
	}
	return it, raw
}

func encode(t *testing.T, g *Graph) []byte {
	t.Helper()
	b, err := json.MarshalIndent(g, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return append(b, '\n')
}

func TestGolden(t *testing.T) {
	for _, rel := range inputs {
		t.Run(rel, func(t *testing.T) {
			it, _ := load(t, rel)
			got := encode(t, Build(it))
			path := filepath.Join(testdata, "golden", "graph", rel)
			if *update {
				if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, got, 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("%v (run go test ./internal/graph -update)", err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("graph differs from %s; run with -update and review the diff", path)
			}
		})
	}
}

// Every node, edge and asset pointer must resolve in the input: the viewer
// shows the JSON at that pointer.
func TestPointersResolve(t *testing.T) {
	for _, rel := range inputs {
		it, raw := load(t, rel)
		var doc any
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatal(err)
		}
		g := Build(it)
		var ptrs []string
		for _, n := range g.Nodes {
			ptrs = append(ptrs, n.JSONPath)
		}
		for _, e := range g.Edges {
			ptrs = append(ptrs, e.JSONPath)
		}
		for _, a := range g.Assets {
			ptrs = append(ptrs, a.JSONPath)
		}
		for _, p := range ptrs {
			if !resolves(doc, p) {
				t.Errorf("%s: pointer %q does not resolve", rel, p)
			}
		}
	}
}

func resolves(doc any, ptr string) bool {
	if ptr == "" {
		return true
	}
	cur := doc
	for _, tok := range strings.Split(ptr, "/")[1:] {
		tok = strings.NewReplacer("~1", "/", "~0", "~").Replace(tok)
		switch v := cur.(type) {
		case map[string]any:
			n, ok := v[tok]
			if !ok {
				return false
			}
			cur = n
		case []any:
			i, err := strconv.Atoi(tok)
			if err != nil || i < 0 || i >= len(v) {
				return false
			}
			cur = v[i]
		default:
			return false
		}
	}
	return true
}

// Node and edge IDs are unique; every edge joins two nodes, except edges to
// references L001 reports (the viewer drops those).
func TestStructure(t *testing.T) {
	dangling := map[string]bool{"COMP-NOWHERE": true}
	for _, rel := range inputs {
		it, _ := load(t, rel)
		g := Build(it)
		ids := map[string]bool{}
		for _, z := range g.Zones {
			ids[z.ID] = true
		}
		for _, n := range g.Nodes {
			if ids[n.ID] {
				t.Errorf("%s: duplicate node %s", rel, n.ID)
			}
			ids[n.ID] = true
			if n.Kind == KindComponent && !ids[n.Zone] {
				t.Errorf("%s: %s in unknown zone %s", rel, n.ID, n.Zone)
			}
			if n.Kind == KindInstance && !ids[n.Parent] {
				t.Errorf("%s: %s has unknown parent %s", rel, n.ID, n.Parent)
			}
		}
		edges := map[string]bool{}
		for _, e := range g.Edges {
			if edges[e.ID] || ids[e.ID] {
				t.Errorf("%s: edge ID %s not unique", rel, e.ID)
			}
			edges[e.ID] = true
			for _, end := range append([]string{e.Source, e.Target}, e.TargetInstances...) {
				if !ids[end] && !dangling[end] {
					t.Errorf("%s: edge %s end %s is not a node", rel, e.ID, end)
				}
			}
			hasProt := e.Protection != nil
			if want := e.Kind == EdgeConnection || e.Kind == EdgeMessage || e.Kind == EdgeEntry; hasProt != want {
				t.Errorf("%s: edge %s (%s) protection set = %v", rel, e.ID, e.Kind, hasProt)
			}
		}
	}
}

func TestDeterministic(t *testing.T) {
	for _, rel := range inputs {
		it, _ := load(t, rel)
		a := encode(t, Build(it))
		for i := 0; i < 3; i++ {
			if b := encode(t, Build(it)); !bytes.Equal(a, b) {
				t.Fatalf("%s: output changed between builds", rel)
			}
		}
	}
}

func TestLabels(t *testing.T) {
	for in, want := range map[string]string{
		"Electro-Mechanical Brake Actuator (EMBA) x4": "EMBA",
		"Brake Pedal Sensor Unit (BPSU)":              "BPSU",
		"Group (G ×2)":                                "G",
		"No abbreviation":                             "No abbreviation",
	} {
		if got := ShortName(in); got != want {
			t.Errorf("ShortName(%q) = %q, want %q", in, got, want)
		}
	}
	for in, want := range map[string]string{"Raw CAN-FD Frames": "CAN-FD", "DHCP, DNS": "DHCP", "  ": "", "Plain HTTPS; x": "HTTPS"} {
		if got := firstWord(in); got != want {
			t.Errorf("firstWord(%q) = %q, want %q", in, got, want)
		}
	}
	for in, want := range map[string]string{"ASSET-BRK-04": "A04", "ASSETX": "ASSETX", "ASSET-": "ASSET-"} {
		if got := assetLabel(in); got != want {
			t.Errorf("assetLabel(%q) = %q, want %q", in, got, want)
		}
	}
}

// D17: pinned reach (components and instances only) per sample entry point.
func TestReachSamples(t *testing.T) {
	emba := "COMP-EBCM COMP-EMBA COMP-EMBA-FL COMP-EMBA-FR COMP-EMBA-RL COMP-EMBA-RR"
	want := map[string]map[string]string{
		"bbw/item-definition.json": {
			// BPSU sends on BRK-02, so its debug header reaches the whole chain;
			// RIC only sends and is never reached.
			"ep:INT-SWD-HEADER":              "COMP-BPSU COMP-VDCM " + emba,
			"ep:INT-BLE-DIAG":                "COMP-VDCM " + emba,
			"ep:INT-OBD2-CAN":                "COMP-VDCM " + emba,
			"ep:CONN-BRK-04#physical_access": emba,
		},
		"ota-adas/item-definition.json": {
			// ADAS only sends to the CGW and is never reached.
			"ep:INT-WIFI-AP":    "COMP-CLOUD COMP-TCU COMP-CGW COMP-EBCM",
			"ep:INT-OBD2-DEBUG": "COMP-CLOUD COMP-TCU COMP-CGW COMP-EBCM",
		},
	}
	for rel, entries := range want {
		it, _ := load(t, rel)
		g := Build(it)
		got := map[string]string{}
		for _, n := range g.Nodes {
			if n.Kind != KindEntry {
				continue
			}
			var comps []string
			for _, id := range n.Reach.Nodes {
				if k := kindOf(g, id); k == KindComponent || k == KindInstance {
					comps = append(comps, id)
				}
			}
			got[n.ID] = strings.Join(comps, " ")
		}
		for id, w := range entries {
			if got[id] != w {
				t.Errorf("%s %s reaches\n  %s\nwant\n  %s", rel, id, got[id], w)
			}
		}
		if len(got) != len(entries) {
			t.Errorf("%s: entry points %v", rel, got)
		}
	}
}

// Reach is closed: every reached edge starts at a reached node and ends at
// one; every non-entry node has no reach.
func TestReachClosed(t *testing.T) {
	for _, rel := range inputs {
		it, _ := load(t, rel)
		g := Build(it)
		edges := map[string]Edge{}
		for _, e := range g.Edges {
			edges[e.ID] = e
		}
		for _, n := range g.Nodes {
			if n.Kind != KindEntry {
				if n.Reach != nil {
					t.Errorf("%s: %s has reach", rel, n.ID)
				}
				continue
			}
			in := map[string]bool{}
			for _, id := range n.Reach.Nodes {
				in[id] = true
			}
			if !in[n.ID] {
				t.Errorf("%s: %s does not reach itself", rel, n.ID)
			}
			for _, id := range n.Reach.Edges {
				e := edges[id]
				if !in[e.Source] || !in[e.Target] {
					t.Errorf("%s: %s reaches edge %s but not both its ends", rel, n.ID, id)
				}
			}
		}
	}
}

func kindOf(g *Graph, id string) NodeKind {
	for _, n := range g.Nodes {
		if n.ID == id {
			return n.Kind
		}
	}
	return ""
}
