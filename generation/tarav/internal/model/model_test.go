package model

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

const testdata = "../../testdata"

func load(t *testing.T, rel string) *Item {
	t.Helper()
	it, err := LoadFile(filepath.Join(testdata, rel))
	if err != nil {
		t.Fatal(err)
	}
	return it
}

func TestSamplesLoad(t *testing.T) {
	cases := []struct {
		file                 string
		comps, conns, assets int
		itemID               string
	}{
		{"bbw/item-definition.json", 5, 4, 4, "AUTO-BBW-01"},
		{"ota-adas/item-definition.json", 0, 6, 0, ""}, // 0 = don't check
		{"zone/zones-wrap.json", 8, 8, 1, "TEST-ZONES-01"},
		{"valid/minimal.json", 2, 1, 1, "ITEM-MIN"},
	}
	for _, c := range cases {
		t.Run(c.file, func(t *testing.T) {
			it := load(t, c.file)
			if it.ItemDefinition.ItemID == "" || len(it.Components) == 0 || len(it.Connections) == 0 || len(it.Assets) == 0 {
				t.Fatalf("empty core: %+v", it.ItemDefinition)
			}
			if c.itemID != "" && it.ItemDefinition.ItemID != c.itemID {
				t.Errorf("item_id = %q, want %q", it.ItemDefinition.ItemID, c.itemID)
			}
			if c.comps != 0 && len(it.Components) != c.comps {
				t.Errorf("components = %d, want %d", len(it.Components), c.comps)
			}
			if c.conns != 0 && len(it.Connections) != c.conns {
				t.Errorf("connections = %d, want %d", len(it.Connections), c.conns)
			}
			if c.assets != 0 && len(it.Assets) != c.assets {
				t.Errorf("assets = %d, want %d", len(it.Assets), c.assets)
			}
		})
	}
}

// Spot-check that nested fields the lint and viewer rely on are decoded.
func TestBBWFields(t *testing.T) {
	it := load(t, "bbw/item-definition.json")

	emba := it.Component("COMP-EMBA")
	if emba == nil || len(emba.Instances) != 4 || emba.Instances[0].InstanceID != "COMP-EMBA-FL" {
		t.Fatalf("EMBA instances: %+v", emba)
	}
	if v, ok := emba.HostedSoftware[0].SecurityConfiguration["command_authentication_mac"].(bool); !ok || v {
		t.Errorf("EMBA command_authentication_mac = %v, want false", emba.HostedSoftware[0].SecurityConfiguration["command_authentication_mac"])
	}

	bpsu := it.Component("COMP-BPSU")
	if bpsu.PhysicalAccess == nil || bpsu.PhysicalAccess.InterfaceID != "INT-SWD-HEADER" ||
		bpsu.PhysicalAccess.DebugAuthenticationRequired == nil || *bpsu.PhysicalAccess.DebugAuthenticationRequired {
		t.Errorf("BPSU physical_access: %+v", bpsu.PhysicalAccess)
	}

	ebcm := it.Component("COMP-EBCM")
	if ebcm.DiagnosticProgramming["rollback_protection_enabled"] != false {
		t.Errorf("EBCM rollback_protection_enabled = %v", ebcm.DiagnosticProgramming["rollback_protection_enabled"])
	}
	if len(ebcm.DiagnosticServices) != 1 || ebcm.DiagnosticServices[0].ExecutionConnection != "CONN-BRK-04" {
		t.Errorf("EBCM diagnostic_services: %+v", ebcm.DiagnosticServices)
	}

	c1 := it.Connection("CONN-BRK-01")
	if len(c1.EntryPoints) != 2 || c1.EntryPoints[0].Encrypted == nil || !*c1.EntryPoints[0].Encrypted {
		t.Errorf("CONN-BRK-01 entry points: %+v", c1.EntryPoints)
	}
	da := c1.DiagnosticAccess
	if da == nil || da.RequestHandlerComponent != "COMP-VDCM" || len(da.DownstreamRoutes) != 1 ||
		da.DownstreamRoutes[0].ViaConnection != "CONN-BRK-03" || da.BrakeOverrideService == nil ||
		!reflect.DeepEqual(da.BrakeOverrideService.EntryInterfaces, []string{"INT-BLE-DIAG", "INT-OBD2-CAN"}) {
		t.Errorf("CONN-BRK-01 diagnostic_access: %+v", da)
	}

	c2 := it.Connection("CONN-BRK-02")
	if !reflect.DeepEqual(c2.AdjacentComponents, []string{"COMP-RIC"}) || len(c2.Messages) != 2 ||
		c2.Messages[1].SourceComponent != "COMP-RIC" || c2.Encrypted == nil || *c2.Encrypted {
		t.Errorf("CONN-BRK-02: %+v", c2)
	}

	c4 := it.Connection("CONN-BRK-04")
	if len(c4.TargetInstances) != 4 || c4.PhysicalAccess == nil || c4.PhysicalAccess.Location != "Exterior wheel-well harness" {
		t.Errorf("CONN-BRK-04: %+v", c4)
	}
	if f := c4.Messages[0].PayloadFields[0]; f.TargetInstance != "COMP-EMBA-FL" {
		t.Errorf("payload field target_instance = %q", f.TargetInstance)
	}

	if ds := it.Assets[0].DamageScenarios; len(ds) != 1 || ds[0].ExpectedSFOPImpact == nil || ds[0].ExpectedSFOPImpact.Safety != "Severe" {
		t.Errorf("ASSET-BRK-01 damage scenarios: %+v", ds)
	}
}

// The model must not silently drop anything the samples contain: decoding
// into Item and encoding back yields the original document. A missing or
// misspelled json tag would make a field vanish here.
func TestRoundTripLosesNothing(t *testing.T) {
	for _, rel := range []string{"bbw/item-definition.json", "ota-adas/item-definition.json", "zone/zones-wrap.json", "valid/protection.json"} {
		t.Run(rel, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(testdata, rel))
			if err != nil {
				t.Fatal(err)
			}
			it, err := Load(raw)
			if err != nil {
				t.Fatal(err)
			}
			back, err := json.Marshal(it)
			if err != nil {
				t.Fatal(err)
			}
			var want, got any
			if err := json.Unmarshal(raw, &want); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(back, &got); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(want, got) {
				t.Errorf("round trip differs: %s", firstDiff("", want, got))
			}
		})
	}
}

// firstDiff names the first JSON pointer where a and b differ.
func firstDiff(path string, a, b any) string {
	switch av := a.(type) {
	case map[string]any:
		bv, ok := b.(map[string]any)
		if !ok {
			return path + ": type differs"
		}
		for k, v := range av {
			if _, ok := bv[k]; !ok {
				return path + "/" + k + ": dropped by the model"
			}
			if d := firstDiff(path+"/"+k, v, bv[k]); d != "" {
				return d
			}
		}
		for k := range bv {
			if _, ok := av[k]; !ok {
				return path + "/" + k + ": added by the model"
			}
		}
	case []any:
		bv, ok := b.([]any)
		if !ok || len(av) != len(bv) {
			return path + ": array differs"
		}
		for i := range av {
			if d := firstDiff(fmt.Sprintf("%s/%d", path, i), av[i], bv[i]); d != "" {
				return d
			}
		}
	default:
		if !reflect.DeepEqual(a, b) {
			return fmt.Sprintf("%s: %v != %v", path, a, b)
		}
	}
	return ""
}

func TestOTAFields(t *testing.T) {
	it := load(t, "ota-adas/item-definition.json")
	explicit := 0
	for _, c := range it.Connections {
		if c.InterfaceID != "" {
			explicit++
		}
	}
	if explicit != 4 {
		t.Errorf("connections with interface_id = %d, want 4", explicit)
	}
	rules := 0
	for _, c := range it.Components {
		rules += len(c.ForwardingRules)
		for _, r := range c.ForwardingRules {
			if !it.HasConnection(r.InputConnection) || !it.HasConnection(r.OutputConnection) {
				t.Errorf("forwarding rule on %s references unknown connection: %+v", c.ComponentID, r)
			}
		}
	}
	if rules == 0 {
		t.Error("no forwarding_rules decoded")
	}
}

// Absent optional booleans stay nil (unknown), distinct from false.
func TestOptionalBoolsStayNil(t *testing.T) {
	it, err := Load([]byte(`{"item_definition":{"item_id":"I","name":"n"},
		"components":[{"component_id":"A","name":"A","trust_zone":"Z","interfaces":["X"]}],
		"connections":[{"connection_id":"C","source_component":"A","target_component":"A"}],
		"assets":[], "some_future_field": {"x": 1}}`))
	if err != nil {
		t.Fatal(err)
	}
	if it.Connections[0].Encrypted != nil {
		t.Errorf("Encrypted = %v, want nil", *it.Connections[0].Encrypted)
	}
}

func TestLookups(t *testing.T) {
	it := load(t, "bbw/item-definition.json")
	cases := []struct {
		name string
		fn   func(string) bool
		id   string
		want bool
	}{
		{"component", it.HasComponent, "COMP-VDCM", true},
		{"component missing", it.HasComponent, "COMP-NOPE", false},
		{"component external sentinel", it.HasComponent, "EXTERNAL_ATTACKER_SURFACE", true},
		{"component any external", it.HasComponent, "EXTERNAL_BACKEND", true},
		{"component external prefix is case-sensitive", it.HasComponent, "external_attacker", false},
		{"component empty", it.HasComponent, "", false},
		{"instance", it.HasInstance, "COMP-EMBA-RR", true},
		{"instance missing", it.HasInstance, "COMP-EMBA-XX", false},
		{"instance is not a component", it.HasComponent, "COMP-EMBA-FL", false},
		{"component is not an instance", it.HasInstance, "COMP-EMBA", false},
		{"interface", it.HasInterface, "INT-SWD-HEADER", true},
		{"interface shared", it.HasInterface, "INT-CAN-CHASSIS", true},
		{"interface missing", it.HasInterface, "INT-NOPE", false},
		{"interface external not special", it.HasInterface, "EXTERNAL_ATTACKER_SURFACE", false},
		{"connection", it.HasConnection, "CONN-BRK-03", true},
		{"connection missing", it.HasConnection, "CONN-BRK-99", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.fn(c.id); got != c.want {
				t.Errorf("(%q) = %v, want %v", c.id, got, c.want)
			}
		})
	}
	if it.Component("EXTERNAL_ATTACKER_SURFACE") != nil || it.Connection("nope") != nil {
		t.Error("expected nil for sentinel component / unknown connection")
	}
}

func TestDuplicateIDsFirstWins(t *testing.T) {
	it, err := Load([]byte(`{"item_definition":{"item_id":"I","name":"n"},
		"components":[{"component_id":"A","name":"first","trust_zone":"Z","interfaces":[]},
		              {"component_id":"A","name":"second","trust_zone":"Z","interfaces":[]}],
		"connections":[], "assets":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	if got := it.Component("A").Name; got != "first" {
		t.Errorf("Component(A).Name = %q, want first", got)
	}
}

func TestLoadErrors(t *testing.T) {
	for name, in := range map[string]string{
		"not json":      `{`,
		"wrong type":    `{"components": "nope"}`,
		"trailing data": `{} {}`,
	} {
		if _, err := Load([]byte(in)); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	if _, err := LoadFile(filepath.Join(testdata, "missing.json")); err == nil {
		t.Error("missing file: expected error")
	}
}

func TestPointer(t *testing.T) {
	if got := Pointer("a/b", "c~d", 0); got != "/a~1b/c~0d/0" {
		t.Errorf("Pointer = %q", got)
	}
	if got := Pointer(); got != "" {
		t.Errorf("Pointer() = %q", got)
	}
}
