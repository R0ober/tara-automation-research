package policy

import (
	"strings"
	"testing"

	"tarav/internal/lint"
)

func TestParseErrors(t *testing.T) {
	cases := map[string]string{
		`{"fail_on":"warn"}`:          `fail_on "warn"`,
		`{"failon":"error"}`:          `unknown field "failon"`,
		`{"rules":{"L999":"error"}}`:  `unknown rule "L999"`,
		`{"rules":{"L017":"silent"}}`: `rules.L017: level "silent"`,
		`{"fail_on":"error"} {}`:      `trailing data`,
		`[]`:                          `cannot unmarshal`,
		`{"rules":{"L001":"never"}}`:  `level "never"`,
		`{"fail_on":"off"}`:           `fail_on "off"`,
	}
	for in, want := range cases {
		_, err := Parse([]byte(in))
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("Parse(%s) = %v, want error containing %q", in, err, want)
		}
	}
}

func TestParseDefaultsAndHash(t *testing.T) {
	p, err := Parse([]byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if p.FailOn != "error" || len(p.SHA256) != 64 {
		t.Errorf("got %+v", p)
	}
	if Default().SHA256 != "" {
		t.Error("default policy must have no hash")
	}
	if _, err := Load("../../testdata/policy/strict.json"); err != nil {
		t.Error(err)
	}
	if _, err := Load("../../testdata/policy/nope.json"); err == nil {
		t.Error("missing file: want error")
	}
}

func fs(sevs ...lint.Severity) []lint.Finding {
	var out []lint.Finding
	for i, s := range sevs {
		out = append(out, lint.Finding{Rule: []string{"L001", "L003", "L017"}[i%3], Severity: s})
	}
	return out
}

func TestApply(t *testing.T) {
	p, err := Parse([]byte(`{"rules":{"L003":"info","L017":"off"}}`))
	if err != nil {
		t.Fatal(err)
	}
	in := fs(lint.Error, lint.Error, lint.Warning)
	got := p.Apply(in)
	if len(got) != 2 || got[0].Severity != lint.Error || got[1].Rule != "L003" || got[1].Severity != lint.Info {
		t.Errorf("Apply = %+v", got)
	}
	if in[1].Severity != lint.Error {
		t.Error("Apply modified its input")
	}
}

func TestBlocking(t *testing.T) {
	f := fs(lint.Error, lint.Warning, lint.Info)
	for failOn, want := range map[string]int{"error": 1, "warning": 2, "info": 3, "never": 0} {
		if got := (&Policy{FailOn: failOn}).Blocking(f); got != want {
			t.Errorf("fail_on %s: Blocking = %d, want %d", failOn, got, want)
		}
	}
}
