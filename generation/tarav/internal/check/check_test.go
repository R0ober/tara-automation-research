package check

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"tarav/internal/policy"
)

func read(t *testing.T, rel string) []byte {
	t.Helper()
	b, err := os.ReadFile("../../testdata/" + rel)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestRun(t *testing.T) {
	strict, err := policy.Load("../../testdata/policy/strict.json")
	if err != nil {
		t.Fatal(err)
	}
	relaxed, err := policy.Load("../../testdata/policy/relaxed.json")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		file       string
		pol        *policy.Policy
		passed     bool
		blocking   int
		schemaErrs bool
	}{
		{"bbw/item-definition.json", nil, true, 0, false},
		{"ota-adas/item-definition.json", nil, true, 0, false},
		{"lint/L017-all-stated.json", strict, true, 0, false},
		{"lint/L017-missing-flags.json", strict, false, -1, false},
		{"lint/L002-duplicate-ids.json", nil, false, -1, false},
		{"lint/L003-no-damage-scenario.json", nil, false, -1, false},
		{"lint/L003-no-damage-scenario.json", relaxed, true, 0, false},
		{"schema/wrong-type.json", nil, false, 0, true},
	}
	for _, c := range cases {
		raw := read(t, c.file)
		r, err := Run(raw, c.pol)
		if err != nil {
			t.Fatal(err)
		}
		if r.Passed != c.passed || (c.blocking >= 0 && r.Blocking != c.blocking) || (len(r.SchemaErrors) > 0) != c.schemaErrs {
			t.Errorf("%s: passed=%v blocking=%d schema_errors=%d", c.file, r.Passed, r.Blocking, len(r.SchemaErrors))
		}
		if !c.passed && !c.schemaErrs && r.Blocking == 0 {
			t.Errorf("%s: failed without blocking findings", c.file)
		}
		sum := sha256.Sum256(raw)
		if r.SHA256 != hex.EncodeToString(sum[:]) {
			t.Errorf("%s: sha256 %s", c.file, r.SHA256)
		}
		if n := r.Counts.Error + r.Counts.Warning + r.Counts.Info; n != len(r.Findings) {
			t.Errorf("%s: counts %+v for %d findings", c.file, r.Counts, len(r.Findings))
		}
	}
}

// The JSON report is the pipeline contract: empty lists are [], not null.
func TestReportJSON(t *testing.T) {
	r, err := Run(read(t, "lint/L017-all-stated.json"), nil)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(r)
	var m map[string]any
	json.Unmarshal(b, &m)
	for _, k := range []string{"sha256", "passed", "schema", "schema_errors", "findings", "counts", "blocking", "fail_on"} {
		if _, ok := m[k]; !ok {
			t.Errorf("report JSON lacks %q: %s", k, b)
		}
	}
	if m["findings"] == nil || m["schema_errors"] == nil {
		t.Errorf("empty lists must encode as []: %s", b)
	}
	if _, ok := m["policy_sha256"]; ok {
		t.Error("default policy must omit policy_sha256")
	}
}
