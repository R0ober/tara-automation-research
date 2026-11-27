package model

import (
	"encoding/json"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func decl(src EntrySource, ptr string) Declaration { return Declaration{Source: src, Pointer: ptr} }

func TestEntryPointsSamples(t *testing.T) {
	emba := []string{"COMP-EMBA-FL", "COMP-EMBA-FR", "COMP-EMBA-RL", "COMP-EMBA-RR"}
	zoneAct := []string{"COMP-ACT-FL", "COMP-ACT-FR", "COMP-ACT-RL", "COMP-ACT-RR"}
	cases := []struct {
		file string
		want []EntryPoint
	}{
		{"bbw/item-definition.json", []EntryPoint{
			{ID: "INT-SWD-HEADER", InterfaceID: "INT-SWD-HEADER", Physical: true, Components: []string{"COMP-BPSU"},
				Declarations: []Declaration{decl(SourceComponentPhysical, "/components/0/physical_access")}},
			{ID: "INT-BLE-DIAG", InterfaceID: "INT-BLE-DIAG", Components: []string{"COMP-VDCM"}, Connections: []string{"CONN-BRK-01"},
				Declarations: []Declaration{decl(SourceDeclared, "/connections/0/entry_points/0")}},
			{ID: "INT-OBD2-CAN", InterfaceID: "INT-OBD2-CAN", Components: []string{"COMP-VDCM"}, Connections: []string{"CONN-BRK-01"},
				Declarations: []Declaration{decl(SourceDeclared, "/connections/0/entry_points/1")}},
			{ID: "CONN-BRK-04#physical_access", Physical: true, Components: []string{"COMP-EBCM", "COMP-EMBA"},
				Instances: emba, Connections: []string{"CONN-BRK-04"},
				Declarations: []Declaration{decl(SourceConnectionPhysical, "/connections/3/physical_access")}},
		}},
		// OTA-ADAS has no entry_points[] or physical_access: its attack
		// surface is the EXTERNAL_* connections.
		{"ota-adas/item-definition.json", []EntryPoint{
			{ID: "INT-WIFI-AP", InterfaceID: "INT-WIFI-AP", Components: []string{"COMP-TCU"}, Connections: []string{"CONN-02"},
				Declarations: []Declaration{decl(SourceExternalConnection, "/connections/1")}},
			{ID: "INT-OBD2-DEBUG", InterfaceID: "INT-OBD2-DEBUG", Components: []string{"COMP-TCU"}, Connections: []string{"CONN-06"},
				Declarations: []Declaration{decl(SourceExternalConnection, "/connections/5")}},
		}},
		{"zone/zones-wrap.json", []EntryPoint{
			{ID: "INT-LTE", InterfaceID: "INT-LTE", Components: []string{"COMP-TCU"}, Connections: []string{"CONN-Z-01"},
				Declarations: []Declaration{decl(SourceDeclared, "/connections/0/entry_points/0")}},
			{ID: "CONN-Z-05#physical_access", Physical: true, Components: []string{"COMP-ACTCTRL", "COMP-ACT"},
				Instances: zoneAct, Connections: []string{"CONN-Z-05"},
				Declarations: []Declaration{decl(SourceConnectionPhysical, "/connections/4/physical_access")}},
		}},
	}
	for _, c := range cases {
		t.Run(c.file, func(t *testing.T) {
			got := load(t, c.file).EntryPoints()
			if !reflect.DeepEqual(got, c.want) {
				g, _ := json.MarshalIndent(got, "", "  ")
				t.Errorf("got:\n%s", g)
			}
		})
	}
}

// Every declaration pointer must resolve in the input (findings will cite them).
func TestEntryPointPointersResolve(t *testing.T) {
	for _, rel := range []string{"bbw/item-definition.json", "ota-adas/item-definition.json", "zone/zones-wrap.json"} {
		it := load(t, rel)
		var doc any
		raw, _ := json.Marshal(it)
		_ = json.Unmarshal(raw, &doc)
		for _, ep := range it.EntryPoints() {
			for _, d := range ep.Declarations {
				if resolve(doc, d.Pointer) == nil {
					t.Errorf("%s: %s pointer %s does not resolve", rel, ep.ID, d.Pointer)
				}
			}
		}
	}
}

func resolve(doc any, ptr string) any {
	cur := doc
	for _, tok := range strings.Split(ptr, "/")[1:] {
		switch v := cur.(type) {
		case map[string]any:
			cur = v[tok]
		case []any:
			i, err := strconv.Atoi(tok)
			if err != nil || i < 0 || i >= len(v) {
				return nil
			}
			cur = v[i]
		default:
			return nil
		}
	}
	return cur
}

func TestEntryPointsNormalization(t *testing.T) {
	cases := []struct {
		name string
		doc  string
		want []EntryPoint
	}{
		{
			name: "same interface on two connections merges into one entry reaching both",
			doc: `"components":[{"component_id":"A","name":"A","trust_zone":"Z","interfaces":["OBD"]},
			                {"component_id":"B","name":"B","trust_zone":"Z","interfaces":["OBD"]}],
			      "connections":[
			        {"connection_id":"C1","source_component":"EXTERNAL_X","target_component":"A","entry_points":[{"interface_id":"OBD"}]},
			        {"connection_id":"C2","source_component":"EXTERNAL_X","target_component":"B","entry_points":[{"interface_id":"OBD"}]}]`,
			want: []EntryPoint{{ID: "OBD", InterfaceID: "OBD", Components: []string{"A", "B"}, Connections: []string{"C1", "C2"},
				Declarations: []Declaration{decl(SourceDeclared, "/connections/0/entry_points/0"), decl(SourceDeclared, "/connections/1/entry_points/0")}}},
		},
		{
			name: "duplicate declaration for the same component collapses; physical wins",
			doc: `"components":[{"component_id":"A","name":"A","trust_zone":"Z","interfaces":["SWD"],"physical_access":{"interface_id":"SWD"}}],
			      "connections":[{"connection_id":"C1","source_component":"EXTERNAL_X","target_component":"A","entry_points":[{"interface_id":"SWD"}]}]`,
			want: []EntryPoint{{ID: "SWD", InterfaceID: "SWD", Physical: true, Components: []string{"A"}, Connections: []string{"C1"},
				Declarations: []Declaration{decl(SourceComponentPhysical, "/components/0/physical_access"), decl(SourceDeclared, "/connections/0/entry_points/0")}}},
		},
		{
			name: "external connection without entry_points or interface_id is keyed by connection",
			doc: `"components":[{"component_id":"A","name":"A","trust_zone":"Z","interfaces":[]}],
			      "connections":[{"connection_id":"C1","source_component":"A","target_component":"EXTERNAL_BACKEND"}]`,
			want: []EntryPoint{{ID: "C1", Components: []string{"A"}, Connections: []string{"C1"},
				Declarations: []Declaration{decl(SourceExternalConnection, "/connections/0")}}},
		},
		{
			name: "declared entry_points take precedence over the implied external connection",
			doc: `"components":[{"component_id":"A","name":"A","trust_zone":"Z","interfaces":["BLE","X"]}],
			      "connections":[{"connection_id":"C1","source_component":"EXTERNAL_X","target_component":"A","interface_id":"X","entry_points":[{"interface_id":"BLE"}]}]`,
			want: []EntryPoint{{ID: "BLE", InterfaceID: "BLE", Components: []string{"A"}, Connections: []string{"C1"},
				Declarations: []Declaration{decl(SourceDeclared, "/connections/0/entry_points/0")}}},
		},
		{
			name: "external on both ends reaches nothing in the item",
			doc: `"components":[],
			      "connections":[{"connection_id":"C1","source_component":"EXTERNAL_A","target_component":"EXTERNAL_B"}]`,
			want: nil,
		},
		{
			name: "internal connection without taps is not an entry point",
			doc: `"components":[{"component_id":"A","name":"A","trust_zone":"Z","interfaces":[]},{"component_id":"B","name":"B","trust_zone":"Z","interfaces":[]}],
			      "connections":[{"connection_id":"C1","source_component":"A","target_component":"B"}]`,
			want: nil,
		},
		{
			name: "physical_access without interface_id on a component is skipped",
			doc: `"components":[{"component_id":"A","name":"A","trust_zone":"Z","interfaces":[],"physical_access":{"required_access":"x"}}],
			      "connections":[]`,
			want: nil,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			it, err := Load([]byte(`{"item_definition":{"item_id":"I","name":"n"},"assets":[],` + c.doc + `}`))
			if err != nil {
				t.Fatal(err)
			}
			if got := it.EntryPoints(); !reflect.DeepEqual(got, c.want) {
				g, _ := json.MarshalIndent(got, "", "  ")
				t.Errorf("got:\n%s", g)
			}
		})
	}
}
