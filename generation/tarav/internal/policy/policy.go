// Package policy decides which lint findings block a pipeline (SPEC D22).
// A policy file re-grades or turns off rules and sets the severity at
// which the check fails. Without one, the D5 default applies: fail on any
// error-severity finding.
package policy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"tarav/internal/lint"
)

// Never as fail_on means findings never fail the check (schema errors still do).
const Never = "never"

// Off as a rule level drops that rule's findings.
const Off = "off"

// Policy is the parsed policy file.
type Policy struct {
	// FailOn is the lowest severity that fails the check: error, warning,
	// info or never.
	FailOn string `json:"fail_on"`
	// Rules maps a rule ID to the severity its findings get, or "off".
	Rules map[string]string `json:"rules,omitempty"`
	// SHA256 is the hex digest of the policy file, empty for the default.
	SHA256 string `json:"-"`
}

// Default is the D5 rule: fail on error-severity findings.
func Default() *Policy { return &Policy{FailOn: string(lint.Error)} }

// Load reads and checks a policy file. Unknown fields, unknown rule IDs
// and unknown levels are errors, so a typo cannot silently relax the gate.
func Load(path string) (*Policy, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	p, err := Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return p, nil
}

// Parse is Load without the file read.
func Parse(raw []byte) (*Policy, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	p := &Policy{}
	if err := dec.Decode(p); err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	if dec.More() {
		return nil, fmt.Errorf("policy: trailing data after the JSON object")
	}
	if p.FailOn == "" {
		p.FailOn = string(lint.Error)
	}
	if rank(p.FailOn) < 0 && p.FailOn != Never {
		return nil, fmt.Errorf("policy: fail_on %q: want error, warning, info or never", p.FailOn)
	}
	known := map[string]bool{}
	for _, r := range lint.Rules() {
		known[r.ID] = true
	}
	ids := make([]string, 0, len(p.Rules))
	for id := range p.Rules {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if !known[id] {
			return nil, fmt.Errorf("policy: rules: unknown rule %q (known: %s)", id, strings.Join(ruleIDs(), ", "))
		}
		if lvl := p.Rules[id]; rank(lvl) < 0 && lvl != Off {
			return nil, fmt.Errorf("policy: rules.%s: level %q: want error, warning, info or off", id, lvl)
		}
	}
	sum := sha256.Sum256(raw)
	p.SHA256 = hex.EncodeToString(sum[:])
	return p, nil
}

func ruleIDs() []string {
	var ids []string
	for _, r := range lint.Rules() {
		ids = append(ids, r.ID)
	}
	return ids
}

// rank orders severities from most to least severe; -1 for anything else.
func rank(s string) int {
	switch lint.Severity(s) {
	case lint.Error:
		return 0
	case lint.Warning:
		return 1
	case lint.Info:
		return 2
	}
	return -1
}

// Apply returns the findings with rule levels from the policy: re-graded
// findings keep their position (the sort order does not depend on
// severity), and "off" rules are dropped. The input is not modified.
func (p *Policy) Apply(fs []lint.Finding) []lint.Finding {
	out := make([]lint.Finding, 0, len(fs))
	for _, f := range fs {
		if lvl, ok := p.Rules[f.Rule]; ok {
			if lvl == Off {
				continue
			}
			f.Severity = lint.Severity(lvl)
		}
		out = append(out, f)
	}
	return out
}

// Blocking counts the findings at or above FailOn.
func (p *Policy) Blocking(fs []lint.Finding) int {
	if p.FailOn == Never {
		return 0
	}
	limit, n := rank(p.FailOn), 0
	for _, f := range fs {
		if r := rank(string(f.Severity)); r >= 0 && r <= limit {
			n++
		}
	}
	return n
}
