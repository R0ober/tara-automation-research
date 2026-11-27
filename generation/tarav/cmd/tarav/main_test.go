package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testdata = "../../testdata"

func td(rel string) string { return filepath.Join(testdata, rel) }

func runT(args ...string) (code int, stdout, stderr string) {
	var o, e bytes.Buffer
	code = run(args, &o, &e)
	return code, o.String(), e.String()
}

// SPEC D5 / M1 checklist: 0 on valid samples, 1 on schema errors, 2 on
// usage and I/O errors.
func TestExitCodes(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want int
	}{
		{"no args", nil, exitUsage},
		{"unknown command", []string{"frobnicate"}, exitUsage},
		{"help", []string{"--help"}, exitOK},
		{"validate no file", []string{"validate"}, exitUsage},
		{"validate missing file", []string{"validate", td("does-not-exist.json")}, exitUsage},
		{"validate bad flag", []string{"validate", "--nope", td("valid/minimal.json")}, exitUsage},
		{"validate bbw", []string{"validate", td("bbw/item-definition.json")}, exitOK},
		{"validate ota-adas", []string{"validate", td("ota-adas/item-definition.json")}, exitOK},
		{"validate minimal", []string{"validate", td("valid/minimal.json")}, exitOK},
		{"validate several, one bad", []string{"validate", td("valid/minimal.json"), td("schema/bad-id.json")}, exitFindings},
		{"lint bbw", []string{"lint", td("bbw/item-definition.json")}, exitOK},
		{"lint flag after file", []string{"lint", td("bbw/item-definition.json"), "--format", "json"}, exitOK},
		{"lint bad format", []string{"lint", "--format", "sarif", td("bbw/item-definition.json")}, exitUsage},
		{"lint schema error", []string{"lint", td("schema/wrong-type.json")}, exitFindings},
		{"lint missing file", []string{"lint", td("nope.json")}, exitUsage},
		{"lint no file", []string{"lint", "--format", "json"}, exitUsage},
		{"lint json needs one file", []string{"lint", "--format", "json", td("valid/minimal.json"), td("valid/minimal.json")}, exitUsage},
		{"lint text takes several files", []string{"lint", td("valid/minimal.json"), td("valid/minimal.json")}, exitOK},
		{"lint error finding", []string{"lint", td("lint/L002-duplicate-ids.json")}, exitFindings},
		{"lint no error finding", []string{"lint", td("lint/L002-unique-ids.json")}, exitOK},
		{"lint dangling refs", []string{"lint", td("lint/L001-dangling-refs.json")}, exitFindings},
		{"lint all refs defined", []string{"lint", td("lint/L001-all-defined.json")}, exitOK},
		{"lint asset without damage scenario", []string{"lint", td("lint/L003-no-damage-scenario.json")}, exitFindings},
		{"lint all assets covered", []string{"lint", td("lint/L003-all-covered.json")}, exitOK},
		{"lint warnings only exit 0", []string{"lint", td("lint/L017-missing-flags.json")}, exitOK},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got, o, e := runT(c.args...); got != c.want {
				t.Errorf("exit = %d, want %d\nstdout: %s\nstderr: %s", got, c.want, o, e)
			}
		})
	}
}

// Every schema fixture exits 1 and prints a JSON-pointer message.
func TestValidateFixtures(t *testing.T) {
	cases := map[string]string{
		"truncated-bbw.json":    ": /: not valid JSON",
		"missing-required.json": ": /: missing property",
		"wrong-type.json":       ": /components/0/interfaces: ",
		"unknown-schema.json":   ": /$schema: unknown schema",
		"bad-id.json":           ": /connections/0/connection_id: ",
		"multiple-errors.json":  ": /assets/0/damage_scenarios/0: ",
		"empty-id.json":         ": /connections/0/connection_id: ",
	}
	for f, want := range cases {
		t.Run(f, func(t *testing.T) {
			code, out, _ := runT("validate", td("schema/"+f))
			if code != exitFindings {
				t.Fatalf("exit = %d, want 1", code)
			}
			if !strings.Contains(out, f+want) {
				t.Errorf("stdout %q does not contain %q", out, f+want)
			}
		})
	}
}

// D1: no "$schema" -> validated against latest with a one-line stderr notice.
func TestSchemaNotice(t *testing.T) {
	_, out, errOut := runT("validate", td("bbw/item-definition.json"))
	if !strings.Contains(errOut, "note: no \"$schema\"") || strings.Count(errOut, "\n") != 1 {
		t.Errorf("stderr = %q, want one notice line", errOut)
	}
	if !strings.HasSuffix(out, ": valid\n") {
		t.Errorf("stdout = %q", out)
	}
	_, _, errOut = runT("validate", td("valid/minimal.json"))
	if errOut != "" {
		t.Errorf("explicit $schema: stderr = %q, want empty", errOut)
	}
}

func TestLintJSONOutput(t *testing.T) {
	_, out, _ := runT("lint", "--format", "json", td("lint/L017-all-stated.json"))
	if out != "[]\n" {
		t.Errorf("stdout = %q, want []", out)
	}
}

func TestParseInterspersed(t *testing.T) {
	fs := newFlagSet("x", &bytes.Buffer{})
	f := fs.String("format", "text", "")
	files, err := parse(fs, []string{"a.json", "--format", "json", "b.json", "--", "--c.json"})
	if err != nil {
		t.Fatal(err)
	}
	if *f != "json" || strings.Join(files, ",") != "a.json,b.json,--c.json" {
		t.Errorf("format=%q files=%q", *f, files)
	}
}

func TestLintTextFormat(t *testing.T) {
	_, out, _ := runT("lint", td("lint/L002-duplicate-ids.json"))
	want := td("lint/L002-duplicate-ids.json") + ":/components/2/component_id: error L002 [COMP-A] component ID \"COMP-A\" is already used by a component at /components/0/component_id\n"
	if !strings.Contains(out, want) {
		t.Errorf("stdout:\n%s\nmissing line:\n%s", out, want)
	}
}

// In json mode stdout stays parseable: schema errors go to stderr.
func TestLintJSONSchemaErrorsOnStderr(t *testing.T) {
	code, out, errOut := runT("lint", "--format", "json", td("schema/wrong-type.json"))
	if code != exitFindings || out != "" || !strings.Contains(errOut, "/components/0/interfaces") {
		t.Errorf("code=%d stdout=%q stderr=%q", code, out, errOut)
	}
}

// D15: schema errors -> exit 1, no page; findings -> page written, exit per D5.
func TestRender(t *testing.T) {
	dir := t.TempDir()
	out := func(n string) string { return filepath.Join(dir, n) }
	cases := []struct {
		name       string
		args       []string
		want       int
		wantFile   string // "" = no file expected
		wantNoFile string
	}{
		{"sample", []string{"render", td("bbw/item-definition.json"), "-o", out("bbw.html")}, exitOK, out("bbw.html"), ""},
		{"flag first", []string{"render", "-o", out("ota.html"), td("ota-adas/item-definition.json")}, exitOK, out("ota.html"), ""},
		{"warnings only", []string{"render", td("lint/L017-missing-flags.json"), "-o", out("w.html")}, exitOK, out("w.html"), ""},
		{"error findings still write", []string{"render", td("lint/L002-duplicate-ids.json"), "-o", out("dup.html")}, exitFindings, out("dup.html"), ""},
		{"schema error writes nothing", []string{"render", td("schema/wrong-type.json"), "-o", out("bad.html")}, exitFindings, "", out("bad.html")},
		{"no -o", []string{"render", td("bbw/item-definition.json")}, exitUsage, "", ""},
		{"two inputs", []string{"render", td("bbw/item-definition.json"), td("valid/minimal.json"), "-o", out("x.html")}, exitUsage, "", out("x.html")},
		{"missing input", []string{"render", td("nope.json"), "-o", out("y.html")}, exitUsage, "", out("y.html")},
		{"unwritable output", []string{"render", td("valid/minimal.json"), "-o", filepath.Join(dir, "no", "such", "dir.html")}, exitUsage, "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, _, errOut := runT(c.args...)
			if code != c.want {
				t.Errorf("exit = %d, want %d\nstderr: %s", code, c.want, errOut)
			}
			if c.wantFile != "" {
				if b, err := os.ReadFile(c.wantFile); err != nil || !bytes.HasPrefix(b, []byte("<!doctype html>")) {
					t.Errorf("page not written: %v", err)
				}
			}
			if c.wantNoFile != "" {
				if _, err := os.Stat(c.wantNoFile); !os.IsNotExist(err) {
					t.Errorf("%s should not exist", c.wantNoFile)
				}
			}
		})
	}
}

func TestRenderStdout(t *testing.T) {
	code, out, errOut := runT("render", td("valid/minimal.json"), "-o", "-")
	if code != exitOK || !strings.HasPrefix(out, "<!doctype html>") || !strings.Contains(errOut, "wrote stdout (0 errors, 1 warning, 0 info)") {
		t.Errorf("code=%d stderr=%q stdout starts %q", code, errOut, out[:min(len(out), 40)])
	}
}

func TestServeUsage(t *testing.T) {
	for name, args := range map[string][]string{
		"no file":   {"serve"},
		"two files": {"serve", td("valid/minimal.json"), td("valid/minimal.json")},
		"missing":   {"serve", td("nope.json")},
		"bad addr":  {"serve", td("valid/minimal.json"), "--addr", "not-an-address"},
		"bad flag":  {"serve", "--nope", td("valid/minimal.json")},
	} {
		t.Run(name, func(t *testing.T) {
			if code, _, errOut := runT(args...); code != exitUsage {
				t.Errorf("exit = %d, want 2\nstderr: %s", code, errOut)
			}
		})
	}
}
