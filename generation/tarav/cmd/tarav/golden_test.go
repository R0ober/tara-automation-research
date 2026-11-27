package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite testdata/golden from current lint output")

// goldenInputs are the files whose `lint --format json` output is pinned.
func goldenInputs(t *testing.T) []string {
	t.Helper()
	ins, err := filepath.Glob(td("lint/*.json"))
	if err != nil {
		t.Fatal(err)
	}
	return append(ins, td("bbw/item-definition.json"), td("ota-adas/item-definition.json"), td("zone/zones-wrap.json"))
}

// testdata/X/Y.json -> testdata/golden/X/Y.json
func goldenPath(t *testing.T, in string) string {
	rel, err := filepath.Rel(testdata, in)
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(testdata, "golden", rel)
}

func TestLintGolden(t *testing.T) {
	for _, in := range goldenInputs(t) {
		t.Run(filepath.Base(filepath.Dir(in))+"/"+filepath.Base(in), func(t *testing.T) {
			var out, errOut bytes.Buffer
			if code := run([]string{"lint", "--format", "json", in}, &out, &errOut); code == exitUsage {
				t.Fatalf("exit 2: %s", errOut.String())
			}
			gp := goldenPath(t, in)
			if *update {
				if err := os.MkdirAll(filepath.Dir(gp), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(gp, out.Bytes(), 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(gp)
			if err != nil {
				t.Fatalf("%v (run: go test ./cmd/tarav -update)", err)
			}
			if !bytes.Equal(out.Bytes(), want) {
				t.Errorf("lint output differs from %s (run: go test ./cmd/tarav -update)\ngot:\n%s", gp, out.String())
			}
		})
	}
}

// M1 checklist: every finding has all five fields and its json_path
// resolves to a value in the input.
func TestFindingsComplete(t *testing.T) {
	for _, in := range goldenInputs(t) {
		_, out, _ := runT("lint", "--format", "json", in)
		var fs []map[string]string
		if err := json.Unmarshal([]byte(out), &fs); err != nil {
			t.Fatalf("%s: %v", in, err)
		}
		raw, err := os.ReadFile(in)
		if err != nil {
			t.Fatal(err)
		}
		var doc any
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatal(err)
		}
		for _, f := range fs {
			for _, k := range []string{"rule", "severity", "message", "json_path", "element_id"} {
				if f[k] == "" {
					t.Errorf("%s: finding %v: empty %s", in, f, k)
				}
			}
			if v, ok := resolve(doc, f["json_path"]); !ok {
				t.Errorf("%s: json_path %s does not resolve", in, f["json_path"])
			} else if s, isStr := v.(string); isStr && f["rule"] == "L002" && s != f["element_id"] {
				t.Errorf("%s: %s points at %q, not the duplicated ID %q", in, f["json_path"], s, f["element_id"])
			}
		}
	}
}

// resolve follows an RFC 6901 pointer into decoded JSON.
func resolve(doc any, ptr string) (any, bool) {
	cur := doc
	for _, tok := range strings.Split(ptr, "/")[1:] {
		tok = strings.NewReplacer("~1", "/", "~0", "~").Replace(tok)
		switch v := cur.(type) {
		case map[string]any:
			x, ok := v[tok]
			if !ok {
				return nil, false
			}
			cur = x
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

// SPEC §7: byte-identical output across runs.
func TestLintDeterministic(t *testing.T) {
	for _, in := range goldenInputs(t) {
		_, a, _ := runT("lint", "--format", "json", in)
		for i := 0; i < 5; i++ {
			if _, b, _ := runT("lint", "--format", "json", in); a != b {
				t.Fatalf("%s: output changed between runs", in)
			}
		}
	}
}
