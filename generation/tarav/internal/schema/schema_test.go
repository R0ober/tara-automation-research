package schema

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testdata = "../../testdata"

func read(t *testing.T, rel string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(testdata, rel))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestValidInputs(t *testing.T) {
	const v100 = "https://tarav.local/schema/item-definition/1.0.0"
	for rel, wantID := range map[string]string{
		"bbw/item-definition.json":      LatestID, // no $schema: latest
		"ota-adas/item-definition.json": LatestID,
		"zone/zones-wrap.json":          LatestID,
		"valid/minimal.json":            v100, // names 1.0.0 and keeps validating against it
	} {
		t.Run(rel, func(t *testing.T) {
			res, err := Validate(read(t, rel))
			if err != nil {
				t.Fatal(err)
			}
			if !res.OK() {
				t.Fatalf("expected valid, got %v", res.Errors)
			}
			if res.SchemaID != wantID {
				t.Errorf("SchemaID = %q, want %q", res.SchemaID, wantID)
			}
		})
	}
}

func TestSupported(t *testing.T) {
	got := strings.Join(Supported(), " ")
	if got != "https://tarav.local/schema/item-definition/1.0.0 "+LatestID {
		t.Errorf("Supported() = %s", got)
	}
}

// 1.1.0 adds a strict protection object on connections and messages (D11).
// 1.0.0 documents that carry one still validate: there it is an unknown,
// allowed field.
func TestProtectionObject(t *testing.T) {
	doc := func(version, prot string) []byte {
		return []byte(`{"$schema":"https://tarav.local/schema/item-definition/` + version + `",
			"item_definition":{"item_id":"I","name":"n"},
			"components":[{"component_id":"A","name":"A","trust_zone":"Z","interfaces":[]}],
			"connections":[{"connection_id":"C","source_component":"A","target_component":"A","protection":` + prot + `,
			                "messages":[{"can_id":"0x1","name":"m","protection":` + prot + `}]}],
			"assets":[]}`)
	}
	cases := []struct {
		version, prot string
		wantPointers  []string
	}{
		{"1.1.0", `{"e2e_crc":true,"mac":false,"freshness":true}`, nil},
		{"1.1.0", `{}`, nil},
		{"1.1.0", `{"MAC":true}`, []string{"/connections/0/messages/0/protection", "/connections/0/protection"}},
		{"1.1.0", `{"mac":"yes"}`, []string{"/connections/0/messages/0/protection/mac", "/connections/0/protection/mac"}},
		{"1.0.0", `{"MAC":true}`, nil},
	}
	for _, c := range cases {
		t.Run(c.version+" "+c.prot, func(t *testing.T) {
			res, err := Validate(doc(c.version, c.prot))
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, e := range res.Errors {
				got = append(got, e.Pointer)
			}
			if strings.Join(got, " ") != strings.Join(c.wantPointers, " ") {
				t.Errorf("errors = %v, want pointers %v", res.Errors, c.wantPointers)
			}
		})
	}
}

func TestNoticeWhenSchemaAbsent(t *testing.T) {
	res, err := Validate(read(t, "bbw/item-definition.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Notice, LatestID) {
		t.Errorf("Notice = %q, want mention of %s", res.Notice, LatestID)
	}
	res, _ = Validate(read(t, "valid/minimal.json"))
	if res.Notice != "" {
		t.Errorf("explicit $schema should give no notice, got %q", res.Notice)
	}
}

func TestInvalidFixtures(t *testing.T) {
	// want lists every expected error in output order as pointer plus a
	// substring of its message, so a wrong keyword at the right location
	// fails, and so does a wrong order.
	type want struct{ pointer, contains string }
	cases := []struct {
		file string
		want []want
	}{
		{"truncated-bbw.json", []want{{"", "not valid JSON"}}},
		{"missing-required.json", []want{{"", "missing property 'assets'"}}},
		{"wrong-type.json", []want{{"/components/0/interfaces", "got string, want array"}}},
		{"unknown-schema.json", []want{{"/$schema", "unknown schema"}}},
		{"bad-id.json", []want{{"/connections/0/connection_id", "'CONN 1' does not match pattern"}}},
		{"multiple-errors.json", []want{
			{"/assets/0/damage_scenarios/0", "missing property 'damage_id'"},
			{"/components/1", "missing property 'trust_zone'"},
		}},
		// Two keywords fail at one pointer: order is decided by the message
		// tie-break, which must be deterministic (SPEC §7).
		{"empty-id.json", []want{
			{"/connections/0/connection_id", "does not match pattern"},
			{"/connections/0/connection_id", "minLength"},
		}},
	}
	for _, c := range cases {
		t.Run(c.file, func(t *testing.T) {
			res, err := Validate(read(t, filepath.Join("schema", c.file)))
			if err != nil {
				t.Fatal(err)
			}
			if len(res.Errors) != len(c.want) {
				t.Fatalf("got %d errors %v, want %d", len(res.Errors), res.Errors, len(c.want))
			}
			for i, w := range c.want {
				e := res.Errors[i]
				if e.Pointer != w.pointer || !strings.Contains(e.Message, w.contains) {
					t.Errorf("error %d = %q, want pointer %q with message containing %q", i, e.String(), w.pointer, w.contains)
				}
			}
		})
	}
}

func TestPointerEscaping(t *testing.T) {
	cases := []struct {
		tokens []string
		want   string
	}{
		{nil, ""},
		{[]string{"a/b", "c~d", "0"}, "/a~1b/c~0d/0"},
		{[]string{"~1"}, "/~01"}, // "~" escaped before "/", so no double decode
		{[]string{""}, "/"},
	}
	for _, c := range cases {
		if got := pointer(c.tokens); got != c.want {
			t.Errorf("pointer(%q) = %q, want %q", c.tokens, got, c.want)
		}
	}
}

func TestNonObjectRoot(t *testing.T) {
	res, err := Validate([]byte(`[1,2]`))
	if err != nil {
		t.Fatal(err)
	}
	if res.OK() {
		t.Fatal("array root must be invalid")
	}
}

func TestNonStringSchemaField(t *testing.T) {
	res, err := Validate([]byte(`{"$schema": 1}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Errors) != 1 || res.Errors[0].Pointer != "/$schema" {
		t.Fatalf("got %v", res.Errors)
	}
}

func TestErrorString(t *testing.T) {
	if s := (Error{Pointer: "", Message: "x"}).String(); s != "/: x" {
		t.Errorf("root String() = %q", s)
	}
	if s := (Error{Pointer: "/a/0", Message: "x"}).String(); s != "/a/0: x" {
		t.Errorf("String() = %q", s)
	}
}
