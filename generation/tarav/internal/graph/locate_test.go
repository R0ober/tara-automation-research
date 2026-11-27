package graph

import (
	"path/filepath"
	"testing"

	"tarav/internal/lint"
	"tarav/internal/model"
)

func TestLocate(t *testing.T) {
	bbw, _ := load(t, "bbw/item-definition.json")
	edge, _ := load(t, "graph/edge-cases.json")
	cases := []struct {
		it   *model.Item
		ptr  string
		want string
	}{
		// longest prefix
		{bbw, "/components/1/hosted_software/0/security_configuration/runs_as_root", "COMP-VDCM"},
		{bbw, "/components/4/instances/2/instance_id", "COMP-EMBA-RL"},
		{bbw, "/connections/1/messages/1/name", "CONN-BRK-02#msg:0x1A0"},
		{bbw, "/connections/1/messages/0", "CONN-BRK-02"}, // folded message -> its connection
		{bbw, "/connections/2", "CONN-BRK-03"},
		{bbw, "/connections/0/entry_points/1/interface_id", "CONN-BRK-01#ep:INT-OBD2-CAN"},
		{bbw, "/connections/0/diagnostic_access/downstream_routes/0/via_connection", "diag:CONN-BRK-01:0"},
		{bbw, "/components/0/physical_access/interface_id", "ep:INT-SWD-HEADER"}, // node wins the tie with its edge
		{bbw, "/connections/3/physical_access", "ep:CONN-BRK-04#physical_access"},
		// owner fallbacks
		{bbw, "/connections/0", "CONN-BRK-01#ep:INT-BLE-DIAG"}, // not drawn: first entry edge
		{bbw, "/connections/0/diagnostic_access/request_handler_component", "CONN-BRK-01#ep:INT-BLE-DIAG"},
		{bbw, "/assets/3/damage_scenarios/0", "COMP-EBCM"}, // asset -> parent component
		{edge, "/components/2/component_id", "COMP-A"},     // L002 duplicate, not drawn
		{edge, "/connections/2/physical_access", "ep:CONN-TAP#physical_access"},
		{edge, "/assets/0", "COMP-A"},
		{bbw, "/connections/0/entry_points/1", "CONN-BRK-01#ep:INT-OBD2-CAN"}, // edge wins the tie with its entry node
		// item level
		{bbw, "/item_definition/name", ""},
		{bbw, "", ""},
		{bbw, "/assets/99", ""},
	}
	for _, c := range cases {
		g := Build(c.it)
		if got := g.Locate(c.it, c.ptr); got != c.want {
			t.Errorf("Locate(%q) = %q, want %q", c.ptr, got, c.want)
		}
	}
}

// SPEC M3: every finding in every lint fixture and sample links to a drawn
// element, except findings on an asset whose parent and connections are all
// undefined (L001 fixture), which have nothing to be drawn on.
func TestEveryFindingLinks(t *testing.T) {
	files, _ := filepath.Glob(filepath.Join(testdata, "lint", "*.json"))
	for _, rel := range []string{"bbw/item-definition.json", "ota-adas/item-definition.json", "zone/zones-wrap.json"} {
		files = append(files, filepath.Join(testdata, rel))
	}
	for _, f := range files {
		it, err := model.LoadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		g := Build(it)
		ids := map[string]bool{}
		for _, n := range g.Nodes {
			ids[n.ID] = true
		}
		for _, e := range g.Edges {
			ids[e.ID] = g.Drawable(e) // a link to an undrawn edge could not be shown
		}
		for _, fd := range lint.Run(it) {
			id := g.Locate(it, fd.JSONPath)
			if id == "" && filepath.Base(f) == "L001-dangling-refs.json" && fd.ElementID == "ASSET-1" {
				continue
			}
			if !ids[id] {
				t.Errorf("%s: %s at %s links to %q", filepath.Base(f), fd.Rule, fd.JSONPath, id)
			}
		}
	}
}

func TestLocateAssetViaConnection(t *testing.T) {
	it, err := model.Load([]byte(`{"item_definition":{"item_id":"I","name":"n"},
		"components":[{"component_id":"A","name":"A","trust_zone":"Z","interfaces":[]},{"component_id":"B","name":"B","trust_zone":"Z","interfaces":[]}],
		"connections":[{"connection_id":"C","source_component":"A","target_component":"B"}],
		"assets":[{"asset_id":"S","name":"s","parent_component":"GONE","associated_connections":["NOPE","C"]},
		          {"asset_id":"T","name":"t","parent_component":"GONE"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	g := Build(it)
	if got := g.Locate(it, "/assets/0/parent_component"); got != "C" {
		t.Errorf("asset with undefined parent -> %q, want its connection C", got)
	}
	if got := g.Locate(it, "/assets/1"); got != "" {
		t.Errorf("asset with nothing drawn -> %q, want \"\"", got)
	}
}

// Findings on connections with an undefined end land on a drawn element.
func TestLocateDanglingConnection(t *testing.T) {
	it, g := mustLoad(t, "lint/L001-dangling-refs.json")
	for ptr, want := range map[string]string{
		"/connections/0/source_component":                                       "CONN-1#ep:INT-NOPE-EP", // own edge undrawn: entry edge
		"/connections/0/diagnostic_access/downstream_routes/0/target_component": "CONN-1#ep:INT-NOPE-EP",
		"/connections/1/target_component":                                       "COMP-GW", // nothing drawn: existing endpoint
		"/connections/1/messages/0/source_component":                            "COMP-GW",
	} {
		if got := g.Locate(it, ptr); got != want {
			t.Errorf("Locate(%s) = %q, want %q", ptr, got, want)
		}
	}
}

func mustLoad(t *testing.T, rel string) (*model.Item, *Graph) {
	t.Helper()
	it, err := model.LoadFile(filepath.Join(testdata, rel))
	if err != nil {
		t.Fatal(err)
	}
	return it, Build(it)
}
