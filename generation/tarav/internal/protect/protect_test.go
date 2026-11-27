package protect

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
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
	it, err := model.Load([]byte(`{"item_definition":{"item_id":"I","name":"n"},"assets":[],` + body + `}`))
	if err != nil {
		t.Fatal(err)
	}
	return it
}

var (
	on    = Value{Set: true, On: true, Source: "s"}
	off   = Value{Set: true, On: false, Source: "s"}
	unset = Value{}
)

// Plan §6 rules, first match wins, with D12's strict unknown.
func TestDerive(t *testing.T) {
	cases := []struct {
		name              string
		enc, mac, fr, crc Value
		want              Level
		missing           []Flag
	}{
		{"encrypted wins over everything", on, off, off, off, Encrypted, nil},
		{"encrypted wins even with nothing else stated", on, unset, unset, unset, Encrypted, nil},
		{"mac + freshness", off, on, on, off, MACFreshness, nil},
		{"mac + freshness, encryption unknown", unset, on, on, unset, MACFreshness, []Flag{FlagEncrypted}},
		{"mac only, freshness off", off, on, off, unset, MAC, nil},
		{"mac, freshness unknown: at least mac", off, on, unset, unset, MAC, []Flag{FlagFreshness}},
		{"crc beats none", off, off, unset, on, CRC, nil},
		{"crc, mac unknown: at least crc", off, unset, unset, on, CRC, []Flag{FlagMAC}},
		{"freshness alone proves nothing", off, off, on, off, None, nil},
		{"all stated false: none", off, off, unset, off, None, nil},
		{"D12: mac false, crc unstated is unknown, not none", off, off, off, unset, Unknown, []Flag{FlagCRC}},
		{"nothing stated", unset, unset, unset, unset, Unknown, []Flag{FlagEncrypted, FlagMAC, FlagCRC}},
		{"encryption unstated blocks none", unset, off, off, off, Unknown, []Flag{FlagEncrypted}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := Derive(Flags{Encrypted: c.enc, MAC: c.mac, Freshness: c.fr, CRC: c.crc})
			if r.Level != c.want || !reflect.DeepEqual(r.Missing, c.missing) {
				t.Errorf("got %s missing %v, want %s missing %v", r.Level, r.Missing, c.want, c.missing)
			}
		})
	}
}

func TestRationale(t *testing.T) {
	r := Derive(Flags{Encrypted: Value{Set: true, Source: "connection"}, CRC: Value{Set: true, On: true, Source: "X.k, sender"}})
	if want := "encrypted false (connection); mac not stated; freshness not stated; e2e_crc true (X.k, sender)"; r.Rationale != want {
		t.Errorf("rationale = %q\nwant        %q", r.Rationale, want)
	}
}

func TestGather(t *testing.T) {
	comps := func(rxCfg, txCfg string) string {
		return `"components":[
		  {"component_id":"TX","name":"tx","trust_zone":"Z","interfaces":[],"security_configuration":` + txCfg + `},
		  {"component_id":"RX","name":"rx","trust_zone":"Z","interfaces":[],"security_configuration":` + rxCfg + `,
		   "hosted_software":[{"name":"app","security_configuration":{"e2e_crc_enabled":true,"secoc_mac_enabled":true}}]}]`
	}
	type flags struct{ enc, crc, mac, fr string } // "", "true", "false" with source suffix after '@'
	show := func(v Value) string {
		if !v.Set {
			return ""
		}
		return strconv.FormatBool(v.On) + "@" + v.Pointer
	}
	cases := []struct {
		name string
		doc  string
		get  func(*model.Item) Flags
		want flags
	}{
		{
			name: "receiver component beats its software, software beats sender; prefixed and non-bool keys ignored",
			doc: comps(`{"secoc_mac_enabled":false,"pedal_demand_e2e_crc_enabled":false,"secoc_freshness_counter_enabled":"yes"}`,
				`{"e2e_crc_enabled":false,"secoc_freshness_counter_enabled":true}`) +
				`,"connections":[{"connection_id":"C","source_component":"TX","target_component":"RX","encrypted":false}]`,
			get: func(it *model.Item) Flags { return ForConnection(it, 0) },
			want: flags{
				enc: "false@/connections/0/encrypted",
				crc: "true@/components/1/hosted_software/0/security_configuration/e2e_crc_enabled",
				mac: "false@/components/1/security_configuration/secoc_mac_enabled",
				fr:  "true@/components/0/security_configuration/secoc_freshness_counter_enabled",
			},
		},
		{
			name: "explicit connection protection beats the key table, flag by flag",
			doc: comps(`{}`, `{}`) +
				`,"connections":[{"connection_id":"C","source_component":"TX","target_component":"RX","protection":{"mac":false}}]`,
			get: func(it *model.Item) Flags { return ForConnection(it, 0) },
			want: flags{
				crc: "true@/components/1/hosted_software/0/security_configuration/e2e_crc_enabled",
				mac: "false@/connections/0/protection/mac",
			},
		},
		{
			name: "message protection beats connection protection; message endpoints pick the components",
			doc: comps(`{}`, `{"secoc_freshness_counter_enabled":false}`) +
				`,"connections":[{"connection_id":"C","source_component":"RX","target_component":"RX","encrypted":true,
				   "protection":{"mac":false,"e2e_crc":false},
				   "messages":[{"can_id":"0x1","name":"m","source_component":"RX","target_component":"TX","protection":{"mac":true}}]}]`,
			get: func(it *model.Item) Flags { return ForMessage(it, 0, 0) },
			want: flags{
				enc: "true@/connections/0/encrypted",
				crc: "false@/connections/0/protection/e2e_crc",
				mac: "true@/connections/0/messages/0/protection/mac",
				fr:  "false@/components/0/security_configuration/secoc_freshness_counter_enabled",
			},
		},
		{
			name: "entry point encryption overrides the connection's",
			doc: comps(`{}`, `{}`) +
				`,"connections":[{"connection_id":"C","source_component":"EXTERNAL_X","target_component":"TX","encrypted":false,
				   "entry_points":[{"interface_id":"I","encrypted":true},{"interface_id":"J"}]}]`,
			get:  func(it *model.Item) Flags { return ForEntry(it, 0, 0) },
			want: flags{enc: "true@/connections/0/entry_points/0/encrypted"},
		},
		{
			name: "entry point without encrypted falls back to the connection",
			doc: comps(`{}`, `{}`) +
				`,"connections":[{"connection_id":"C","source_component":"EXTERNAL_X","target_component":"TX","encrypted":false,
				   "entry_points":[{"interface_id":"I","encrypted":true},{"interface_id":"J"}]}]`,
			get:  func(it *model.Item) Flags { return ForEntry(it, 0, 1) },
			want: flags{enc: "false@/connections/0/encrypted"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := c.get(loadJSON(t, c.doc))
			got := flags{show(f.Encrypted), show(f.CRC), show(f.MAC), show(f.Freshness)}
			if got != c.want {
				t.Errorf("got  %+v\nwant %+v", got, c.want)
			}
		})
	}
}

// Expected level for every protection-carrying edge in the samples, as
// derived under D11–D13. A change here is a change in what reviewers see.
func TestSampleEdges(t *testing.T) {
	cases := map[string][]string{
		// CONN-BRK-01 (EXTERNAL_* with entry_points) is drawn as its entry
		// edges; 0x080 and 0x040 fold into their connections.
		"bbw/item-definition.json": {
			"CONN-BRK-01#ep:INT-BLE-DIAG entry encrypted",
			"CONN-BRK-01#ep:INT-OBD2-CAN entry unknown mac,e2e_crc",
			"CONN-BRK-02 connection crc",
			"CONN-BRK-02#msg:0x1A0 message unknown mac,e2e_crc",
			"CONN-BRK-03 connection unknown mac,e2e_crc",
			"CONN-BRK-04 connection unknown e2e_crc",
		},
		"ota-adas/item-definition.json": {
			"CONN-01 connection encrypted",
			"CONN-02 connection encrypted",
			"CONN-03 connection unknown mac,e2e_crc",
			"CONN-04 connection unknown e2e_crc",
			"CONN-05 connection unknown encrypted,mac,e2e_crc",
			"CONN-06 connection unknown mac,e2e_crc",
		},
		// 0x100 shares its connection's endpoints but states its own protection.
		"valid/protection.json": {
			"CONN-1 connection crc",
			"CONN-1#msg:0x100 message mac_freshness",
		},
	}
	for rel, want := range cases {
		t.Run(rel, func(t *testing.T) {
			var got []string
			for _, e := range Edges(load(t, rel)) {
				s := e.ID + " " + string(e.Kind) + " " + string(e.Result.Level)
				if len(e.Result.Missing) > 0 {
					var m []string
					for _, f := range e.Result.Missing {
						m = append(m, string(f))
					}
					s += " " + strings.Join(m, ",")
				}
				got = append(got, s)
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("got:\n  %s\nwant:\n  %s", strings.Join(got, "\n  "), strings.Join(want, "\n  "))
			}
		})
	}
}

func TestEdgeOrderAndSuppression(t *testing.T) {
	it := loadJSON(t, `"components":[{"component_id":"A","name":"A","trust_zone":"Z","interfaces":[]},
	                                 {"component_id":"B","name":"B","trust_zone":"Z","interfaces":[]}],
	  "connections":[
	    {"connection_id":"C1","source_component":"EXTERNAL_X","target_component":"A","entry_points":[{"interface_id":"I"},{"interface_id":"I"}]},
	    {"connection_id":"C2","source_component":"EXTERNAL_X","target_component":"A"},
	    {"connection_id":"C3","source_component":"A","target_component":"B","entry_points":[{"interface_id":"J"}],
	     "messages":[{"can_id":"0x1","name":"same endpoints, folded"},
	                 {"can_id":"0x2","name":"other source","source_component":"B"},
	                 {"can_id":"0x2","name":"dup id","target_component":"A"},
	                 {"can_id":"0x3","name":"same endpoints, own protection","protection":{}}]}]`)
	var got []string
	for _, e := range Edges(it) {
		got = append(got, e.ID+"@"+e.Pointer)
	}
	want := []string{
		"C1#ep:I@/connections/0/entry_points/0", "C1#ep:I~1@/connections/0/entry_points/1",
		"C2@/connections/1",
		"C3@/connections/2", "C3#msg:0x2@/connections/2/messages/1", "C3#msg:0x2~2@/connections/2/messages/2",
		"C3#msg:0x3@/connections/2/messages/3",
		"C3#ep:J@/connections/2/entry_points/0",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got  %q\nwant %q", got, want)
	}
}

// Every pointer a finding or the viewer may cite must resolve in the input.
func TestPointersResolve(t *testing.T) {
	for _, rel := range []string{"bbw/item-definition.json", "ota-adas/item-definition.json", "zone/zones-wrap.json", "valid/protection.json"} {
		raw, err := os.ReadFile(filepath.Join(testdata, rel))
		if err != nil {
			t.Fatal(err)
		}
		var doc any
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatal(err)
		}
		for _, e := range Edges(load(t, rel)) {
			ptrs := []string{e.Pointer}
			for _, v := range []Value{e.Flags.Encrypted, e.Flags.CRC, e.Flags.MAC, e.Flags.Freshness} {
				if v.Set {
					ptrs = append(ptrs, v.Pointer)
				}
			}
			for _, p := range ptrs {
				if _, ok := resolve(doc, p); !ok {
					t.Errorf("%s %s: pointer %s does not resolve", rel, e.ID, p)
				}
			}
		}
	}
}

func resolve(doc any, ptr string) (any, bool) {
	cur := doc
	for _, tok := range strings.Split(ptr, "/")[1:] {
		tok = strings.NewReplacer("~1", "/", "~0", "~").Replace(tok)
		switch v := cur.(type) {
		case map[string]any:
			n, ok := v[tok]
			if !ok {
				return nil, false
			}
			cur = n
		case []any:
			i, err := strconv.Atoi(tok)
			if err != nil || i < 0 || i >= len(v) {
				return nil, false
			}
			cur = v[i]
		default:
			return nil, false
		}
	}
	return cur, true
}
