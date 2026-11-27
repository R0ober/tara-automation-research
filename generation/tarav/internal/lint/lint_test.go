package lint

import (
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"tarav/internal/model"
)

const testdata = "../../testdata"

func load(t *testing.T, rel string) *model.Item {
	t.Helper()
	it, err := model.LoadFile(filepath.Join(testdata, rel))
	if err != nil {
		t.Fatal(err)
	}
	return it
}

func loadJSON(t *testing.T, body string) *model.Item {
	t.Helper()
	it, err := model.Load([]byte(`{"item_definition":{"item_id":"I","name":"n"},` + body + `}`))
	if err != nil {
		t.Fatal(err)
	}
	return it
}

func TestComparePointers(t *testing.T) {
	sorted := []string{
		"", "/assets", "/assets/0", "/assets/0/asset_id", "/assets/2", "/assets/10",
		"/components/0", "/components/0/instances/9", "/components/0/instances/10", "/components/a", "/connections",
	}
	shuffled := append([]string(nil), sorted...)
	for i, j := 0, len(shuffled)-1; i < j; i, j = i+1, j-1 {
		shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
	}
	sort.Slice(shuffled, func(i, j int) bool { return ComparePointers(shuffled[i], shuffled[j]) < 0 })
	if !reflect.DeepEqual(shuffled, sorted) {
		t.Errorf("got  %q\nwant %q", shuffled, sorted)
	}
	if ComparePointers("/a/1", "/a/1") != 0 {
		t.Error("equal pointers must compare 0")
	}
	// "-1" is not an array index, so it compares as a string: "-1" < "2".
	if ComparePointers("/a/-1", "/a/2") != -1 {
		t.Error("negative tokens must compare as strings")
	}
}

func TestRegisterRejectsBadRules(t *testing.T) {
	check := func(*model.Item) []Finding { return nil }
	for name, r := range map[string]Rule{
		"no id":          {Severity: Error, Description: "d", Check: check},
		"no check":       {ID: "LX1", Severity: Error, Description: "d"},
		"no desc":        {ID: "LX2", Severity: Error, Check: check},
		"bad severity":   {ID: "LX3", Severity: "fatal", Description: "d", Check: check},
		"duplicate L002": {ID: "L002", Severity: Error, Description: "d", Check: check},
	} {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Error("expected panic")
				}
			}()
			Register(r)
		})
	}
}

func TestRunFillsRuleAndSorts(t *testing.T) {
	it := loadJSON(t, `
		"components":[{"component_id":"X","name":"a","trust_zone":"Z","interfaces":[]},
		              {"component_id":"Y","name":"b","trust_zone":"Z","interfaces":[]}],
		"connections":[{"connection_id":"Y","source_component":"X","target_component":"Y"}],
		"assets":[{"asset_id":"X","name":"a","parent_component":"X"}]`)
	// Findings from L002 (two duplicate IDs), L003 (asset X has no damage
	// scenario) and L017 (connection Y states no protection) interleave by
	// path, not by rule, and carry their rule's severity.
	got := Run(it)
	var keys []string
	for _, f := range got {
		wantSev := Error
		if f.Rule == "L017" {
			wantSev = Warning
		}
		if f.Severity != wantSev || f.Message == "" || f.ElementID == "" || f.JSONPath == "" {
			t.Errorf("incomplete finding %+v", f)
		}
		keys = append(keys, f.Rule+" "+f.JSONPath)
	}
	if want := []string{"L003 /assets/0", "L002 /assets/0/asset_id", "L017 /connections/0", "L002 /connections/0/connection_id"}; !reflect.DeepEqual(keys, want) {
		t.Errorf("findings = %q, want %q", keys, want)
	}
	if !HasErrors(got) || HasErrors(nil) || HasErrors([]Finding{{Severity: Warning}}) {
		t.Error("HasErrors wrong")
	}
}

func TestL002(t *testing.T) {
	cases := []struct {
		name string
		body string
		want []Finding // Rule/Severity omitted; checked via checkDuplicateIDs directly
	}{
		{
			name: "all unique, interfaces repeat and may equal other IDs",
			body: `"components":[{"component_id":"A","name":"A","trust_zone":"Z","interfaces":["BUS","B"]},
			                     {"component_id":"B","name":"B","trust_zone":"Z","interfaces":["BUS"]}],
			       "connections":[{"connection_id":"C","source_component":"A","target_component":"B","interface_id":"BUS"}],
			       "assets":[{"asset_id":"AS","name":"x","parent_component":"B","damage_scenarios":[{"damage_id":"D"}]}]`,
		},
		{
			name: "duplicate component",
			body: `"components":[{"component_id":"A","name":"1","trust_zone":"Z","interfaces":[]},
			                     {"component_id":"A","name":"2","trust_zone":"Z","interfaces":[]}],
			       "connections":[],"assets":[]`,
			want: []Finding{{Message: `component ID "A" is already used by a component at /components/0/component_id`,
				JSONPath: "/components/1/component_id", ElementID: "A"}},
		},
		{
			name: "instance clashes with a component, across namespaces",
			body: `"components":[{"component_id":"A","name":"1","trust_zone":"Z","interfaces":[]},
			                     {"component_id":"G","name":"2","trust_zone":"Z","interfaces":[],"instances":[{"instance_id":"A"}]}],
			       "connections":[],"assets":[]`,
			want: []Finding{{Message: `instance ID "A" is already used by a component at /components/0/component_id`,
				JSONPath: "/components/1/instances/0/instance_id", ElementID: "A"}},
		},
		{
			name: "three uses give two findings, both pointing at the first",
			body: `"components":[{"component_id":"A","name":"1","trust_zone":"Z","interfaces":[]}],
			       "connections":[{"connection_id":"A","source_component":"A","target_component":"A"}],
			       "assets":[{"asset_id":"S","name":"x","parent_component":"A","damage_scenarios":[{"damage_id":"A"}]}]`,
			want: []Finding{
				{Message: `connection ID "A" is already used by a component at /components/0/component_id`, JSONPath: "/connections/0/connection_id", ElementID: "A"},
				{Message: `damage scenario ID "A" is already used by a component at /components/0/component_id`, JSONPath: "/assets/0/damage_scenarios/0/damage_id", ElementID: "A"},
			},
		},
		{
			name: "duplicate damage scenarios across assets",
			body: `"components":[{"component_id":"A","name":"1","trust_zone":"Z","interfaces":[]}],"connections":[],
			       "assets":[{"asset_id":"S1","name":"x","parent_component":"A","damage_scenarios":[{"damage_id":"D"}]},
			                 {"asset_id":"S2","name":"y","parent_component":"A","damage_scenarios":[{"damage_id":"D"}]}]`,
			want: []Finding{{Message: `damage scenario ID "D" is already used by a damage scenario at /assets/0/damage_scenarios/0/damage_id`,
				JSONPath: "/assets/1/damage_scenarios/0/damage_id", ElementID: "D"}},
		},
		{
			name: "empty IDs are left to the schema",
			body: `"components":[{"component_id":"","name":"1","trust_zone":"Z","interfaces":[]},
			                     {"component_id":"","name":"2","trust_zone":"Z","interfaces":[]}],"connections":[],"assets":[]`,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := checkDuplicateIDs(loadJSON(t, c.body)); !reflect.DeepEqual(got, c.want) {
				t.Errorf("got  %+v\nwant %+v", got, c.want)
			}
		})
	}
}

func TestSamplesHaveNoL002(t *testing.T) {
	for _, rel := range []string{"bbw/item-definition.json", "ota-adas/item-definition.json", "zone/zones-wrap.json"} {
		if got := checkDuplicateIDs(load(t, rel)); len(got) != 0 {
			t.Errorf("%s: %+v", rel, got)
		}
	}
}

// The positive fixture plants one undefined ID (all named *-NOPE-*) at every
// reference site; each must be reported exactly once, at its own pointer.
func TestL001EverySite(t *testing.T) {
	got := checkDanglingRefs(load(t, "lint/L001-dangling-refs.json"))
	if len(got) != 21 {
		t.Errorf("got %d findings, want 21 (one per reference site)", len(got))
	}
	seen := map[string]bool{}
	for _, f := range got {
		if seen[f.JSONPath] {
			t.Errorf("duplicate finding at %s", f.JSONPath)
		}
		seen[f.JSONPath] = true
		if !strings.Contains(f.Message, "-NOPE-") || f.ElementID == "" {
			t.Errorf("unexpected finding %+v", f)
		}
	}
	if got := checkDanglingRefs(load(t, "lint/L001-all-defined.json")); len(got) != 0 {
		t.Errorf("negative fixture: %+v", got)
	}
}

func TestL001(t *testing.T) {
	comps := `"components":[{"component_id":"A","name":"A","trust_zone":"Z","interfaces":["BUS"],"instances":[{"instance_id":"A-1"}]},
	                     {"component_id":"B","name":"B","trust_zone":"Z","interfaces":["BUS"]}]`
	cases := []struct {
		name string
		body string
		want []Finding
	}{
		{
			name: "EXTERNAL_* sentinels are defined (D6)",
			body: comps + `,"connections":[{"connection_id":"C","source_component":"EXTERNAL_X","target_component":"A"}],
			       "assets":[{"asset_id":"S","name":"s","parent_component":"EXTERNAL_BACKEND"}]`,
		},
		{
			name: "absent interface_id is inferred, not checked (D10)",
			body: comps + `,"connections":[{"connection_id":"C","source_component":"A","target_component":"B"}],"assets":[]`,
		},
		{
			name: "empty references are left to the schema",
			body: comps + `,"connections":[{"connection_id":"C","source_component":"","target_component":"A","target_instances":[""]}],"assets":[]`,
		},
		{
			name: "an instance ID is not a component ID",
			body: comps + `,"connections":[{"connection_id":"C","source_component":"A-1","target_component":"B"}],"assets":[]`,
			want: []Finding{{Message: `connection C: source_component "A-1" is not a defined component`,
				JSONPath: "/connections/0/source_component", ElementID: "C"}},
		},
		{
			name: "a component ID is not an instance ID",
			body: comps + `,"connections":[{"connection_id":"C","source_component":"B","target_component":"A","target_instances":["A"]}],"assets":[]`,
			want: []Finding{{Message: `connection C: target_instances "A" is not a defined instance`,
				JSONPath: "/connections/0/target_instances/0", ElementID: "C"}},
		},
		{
			name: "an interface is defined if any component lists it",
			body: comps + `,"connections":[{"connection_id":"C","source_component":"EXTERNAL_X","target_component":"A","interface_id":"BUS",
			                 "entry_points":[{"interface_id":"BUS"}]}],"assets":[]`,
		},
		{
			name: "each dangling reference in a list is its own finding",
			body: comps + `,"connections":[{"connection_id":"C","source_component":"A","target_component":"B"}],
			       "assets":[{"asset_id":"S","name":"s","parent_component":"A","associated_connections":["X","C","Y"]}]`,
			want: []Finding{
				{Message: `asset S: associated_connections "X" is not a defined connection`, JSONPath: "/assets/0/associated_connections/0", ElementID: "S"},
				{Message: `asset S: associated_connections "Y" is not a defined connection`, JSONPath: "/assets/0/associated_connections/2", ElementID: "S"},
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := checkDanglingRefs(loadJSON(t, c.body)); !reflect.DeepEqual(got, c.want) {
				t.Errorf("got  %+v\nwant %+v", got, c.want)
			}
		})
	}
}

func TestSamplesHaveNoL001(t *testing.T) {
	for _, rel := range []string{"bbw/item-definition.json", "ota-adas/item-definition.json", "zone/zones-wrap.json"} {
		if got := checkDanglingRefs(load(t, rel)); len(got) != 0 {
			t.Errorf("%s: %+v", rel, got)
		}
	}
}

func TestL003(t *testing.T) {
	got := checkNoDamageScenario(load(t, "lint/L003-no-damage-scenario.json"))
	want := []Finding{
		{Message: "asset ASSET-MISSING has no damage_scenarios; every asset needs at least one damage scenario",
			JSONPath: "/assets/1", ElementID: "ASSET-MISSING"},
		{Message: "asset ASSET-EMPTY has an empty damage_scenarios list; every asset needs at least one damage scenario",
			JSONPath: "/assets/2/damage_scenarios", ElementID: "ASSET-EMPTY"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got  %+v\nwant %+v", got, want)
	}
	for _, rel := range []string{"lint/L003-all-covered.json", "bbw/item-definition.json", "ota-adas/item-definition.json", "zone/zones-wrap.json"} {
		if got := checkNoDamageScenario(load(t, rel)); len(got) != 0 {
			t.Errorf("%s: %+v", rel, got)
		}
	}
}

func TestL017(t *testing.T) {
	const hint = " (set them in `protection` or the receiver's security_configuration)"
	got := checkProtectionUnknown(load(t, "lint/L017-missing-flags.json"))
	want := []Finding{
		{Message: "connection edge CONN-UNKNOWN: protection is unknown; not stated: encrypted, mac, e2e_crc" + hint,
			JSONPath: "/connections/0", ElementID: "CONN-UNKNOWN"},
		{Message: "connection edge CONN-AT-LEAST-MAC: protection is at least mac; not stated: freshness" + hint,
			JSONPath: "/connections/1", ElementID: "CONN-AT-LEAST-MAC"},
		{Message: "entry edge CONN-ENTRY#ep:INT-OBD: protection is unknown; not stated: mac, e2e_crc" + hint,
			JSONPath: "/connections/2/entry_points/0", ElementID: "CONN-ENTRY"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got  %+v\nwant %+v", got, want)
	}
	if got := checkProtectionUnknown(load(t, "lint/L017-all-stated.json")); len(got) != 0 {
		t.Errorf("negative fixture: %+v", got)
	}
	// BBW: four edges lack flags; BLE (encrypted) and CONN-BRK-02 (crc,
	// MAC stated false) are complete.
	var ids []string
	for _, f := range checkProtectionUnknown(load(t, "bbw/item-definition.json")) {
		ids = append(ids, f.JSONPath)
	}
	if want := []string{"/connections/0/entry_points/1", "/connections/1/messages/1", "/connections/2", "/connections/3"}; !reflect.DeepEqual(ids, want) {
		t.Errorf("bbw L017 paths = %q, want %q", ids, want)
	}
}
