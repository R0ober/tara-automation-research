package render

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
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

var samples = []string{"bbw/item-definition.json", "ota-adas/item-definition.json", "zone/zones-wrap.json"}

func TestRenderSamples(t *testing.T) {
	for _, rel := range samples {
		t.Run(rel, func(t *testing.T) {
			raw := read(t, rel)
			a, err := Render(raw, Options{})
			if err != nil {
				t.Fatal(err)
			}
			if !a.Schema.OK() || a.HTML == nil {
				t.Fatalf("no page: %v", a.Schema.Errors)
			}
			b, _ := Render(raw, Options{})
			if !bytes.Equal(a.HTML, b.HTML) {
				t.Error("output is not byte-identical across runs")
			}
			page := string(a.HTML)
			for _, ph := range []string{"{{TITLE}}", "{{CSS}}", "{{JS}}", "{{VENDOR}}", "{{GRAPH}}", "{{FINDINGS}}", "{{ITEM}}", "{{CONFIG}}", "{{VERSION}}", "{{LINKS}}"} {
				if strings.Contains(page[:strings.Index(page, "<!-- vendor/")], ph) {
					t.Errorf("placeholder %s left in page", ph)
				}
			}
			for name, want := range map[string]any{"tarav-graph": map[string]any{}, "tarav-findings": []any{}, "tarav-links": []any{}, "tarav-item": map[string]any{}, "tarav-config": map[string]any{}} {
				if err := json.Unmarshal([]byte(scriptBody(t, page, name)), &want); err != nil {
					t.Errorf("%s is not valid JSON: %v", name, err)
				}
			}
		})
	}
}

// The page must not load anything over the network (SPEC D4): no external
// src/href, no stylesheets or imports, and a CSP that forbids it anyway.
func TestNetworkFree(t *testing.T) {
	res, err := Render(read(t, "bbw/item-definition.json"), Options{})
	if err != nil {
		t.Fatal(err)
	}
	page := string(res.HTML)
	if !strings.Contains(page, `content="default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data: blob:; connect-src 'self'"`) {
		t.Error("CSP meta missing or changed")
	}
	for _, re := range []string{`(?i)<script[^>]+src=`, `(?i)<link\b`, `(?i)<(img|iframe)[^>]+src=["']?https?:`, `(?i)@import`, `(?i)url\(\s*["']?https?:`} {
		if m := regexp.MustCompile(re).FindString(page); m != "" {
			t.Errorf("network load %q matches %s", m, re)
		}
	}
}

// Input text can't break out of the embedded JSON blocks or the title.
func TestEscaping(t *testing.T) {
	raw := []byte(`{"item_definition":{"item_id":"I","name":"</script><script>alert(1)</script> & <b>"},
		"components":[{"component_id":"A","name":"</script>","trust_zone":"Z","interfaces":[]}],"connections":[],"assets":[]}`)
	res, err := Render(raw, Options{})
	if err != nil || res.HTML == nil {
		t.Fatalf("render: %v %v", err, res.Schema.Errors)
	}
	page := string(res.HTML)
	if strings.Contains(page, "<script>alert(1)") {
		t.Error("item text broke out of its script block")
	}
	if !strings.Contains(page, "<title>&lt;/script&gt;&lt;script&gt;alert(1)&lt;/script&gt; &amp; &lt;b&gt; · tarav</title>") {
		t.Error("title not escaped")
	}
	var item map[string]any
	if err := json.Unmarshal([]byte(scriptBody(t, page, "tarav-item")), &item); err != nil {
		t.Fatal(err)
	}
	if item["item_definition"].(map[string]any)["name"] != "</script><script>alert(1)</script> & <b>" {
		t.Error("escaped item JSON does not decode back to the input")
	}
}

// D15: schema errors give no page; findings still give a page.
func TestSchemaErrorsNoPage(t *testing.T) {
	res, err := Render(read(t, "schema/wrong-type.json"), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Schema.OK() || res.HTML != nil {
		t.Errorf("want schema errors and no page, got ok=%v page=%d bytes", res.Schema.OK(), len(res.HTML))
	}
	res, err = Render(read(t, "lint/L002-duplicate-ids.json"), Options{})
	if err != nil || res.HTML == nil || len(res.Findings) == 0 {
		t.Errorf("page with findings: err=%v page=%d findings=%d", err, len(res.HTML), len(res.Findings))
	}
}

func TestLiveConfigAndHash(t *testing.T) {
	raw := read(t, "valid/minimal.json")
	a, _ := Render(raw, Options{Live: true})
	var cfg struct {
		Live    bool   `json:"live"`
		Version string `json:"version"`
	}
	if err := json.Unmarshal([]byte(scriptBody(t, string(a.HTML), "tarav-config")), &cfg); err != nil {
		t.Fatal(err)
	}
	if !cfg.Live || cfg.Version != a.Hash || len(a.Hash) != 16 {
		t.Errorf("config = %+v, hash %q", cfg, a.Hash)
	}
	b, _ := Render(append(raw, ' '), Options{})
	if a.Hash == b.Hash {
		t.Error("hash must change with the input bytes")
	}
}

func scriptBody(t *testing.T, page, id string) string {
	t.Helper()
	start := `<script type="application/json" id="` + id + `">`
	i := strings.Index(page, start)
	if i < 0 {
		t.Fatalf("no %s block", id)
	}
	rest := page[i+len(start):]
	return rest[:strings.Index(rest, "</script>")]
}

// D18: links are parallel to findings and name graph elements.
func TestLinksParallel(t *testing.T) {
	res, err := Render(read(t, "bbw/item-definition.json"), Options{})
	if err != nil {
		t.Fatal(err)
	}
	page := string(res.HTML)
	var links []string
	if err := json.Unmarshal([]byte(scriptBody(t, page, "tarav-links")), &links); err != nil {
		t.Fatal(err)
	}
	if len(links) != len(res.Findings) || len(links) == 0 {
		t.Fatalf("%d links for %d findings", len(links), len(res.Findings))
	}
	for i, l := range links {
		if l == "" {
			t.Errorf("finding %d (%s %s) has no link", i, res.Findings[i].Rule, res.Findings[i].JSONPath)
		}
	}
}
