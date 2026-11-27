// Package check runs the pipeline checks on one input: schema validation,
// lint and the policy (SPEC D21). The same result drives `tarav check`,
// `tarav approve` and the review page, so all three agree on pass or fail.
package check

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"tarav/internal/lint"
	"tarav/internal/model"
	"tarav/internal/policy"
	"tarav/internal/schema"
)

// Counts tallies findings by severity.
type Counts struct {
	Error   int `json:"error"`
	Warning int `json:"warning"`
	Info    int `json:"info"`
}

// Report is the machine-readable check result. Its JSON form is the
// contract with pipeline callers.
type Report struct {
	File string `json:"file,omitempty"`
	// SHA256 is the hex digest of the exact bytes checked; approvals bind to it.
	SHA256 string `json:"sha256"`
	Passed bool   `json:"passed"`
	// Schema is the schema ID the input was checked against.
	Schema       string         `json:"schema"`
	SchemaErrors []schema.Error `json:"schema_errors"`
	Findings     []lint.Finding `json:"findings"`
	Counts       Counts         `json:"counts"`
	// Blocking is the number of findings at or above the policy's fail_on.
	Blocking int    `json:"blocking"`
	FailOn   string `json:"fail_on"`
	// PolicySHA256 identifies the policy file used; empty for the default.
	PolicySHA256 string `json:"policy_sha256,omitempty"`

	// Notice is the schema notice for stderr (e.g. no "$schema").
	Notice string `json:"-"`
	// Item is the loaded model when the schema passed.
	Item *model.Item `json:"-"`
}

// Hash is the approval hash of raw: hex SHA-256 of the bytes as stored.
func Hash(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// Run checks raw under p (nil means policy.Default). A non-nil error is an
// internal failure, not a problem with the input.
func Run(raw []byte, p *policy.Policy) (*Report, error) {
	if p == nil {
		p = policy.Default()
	}
	r := &Report{
		SHA256:       Hash(raw),
		SchemaErrors: []schema.Error{},
		Findings:     []lint.Finding{},
		FailOn:       p.FailOn,
		PolicySHA256: p.SHA256,
	}
	res, err := schema.Validate(raw)
	if err != nil {
		return nil, err
	}
	r.Notice, r.Schema = res.Notice, res.SchemaID
	if !res.OK() {
		r.SchemaErrors = res.Errors
		return r, nil
	}
	it, err := model.Load(raw)
	if err != nil {
		return nil, fmt.Errorf("load: %w", err)
	}
	r.Item = it
	r.Findings = p.Apply(lint.Run(it))
	for _, f := range r.Findings {
		switch f.Severity {
		case lint.Error:
			r.Counts.Error++
		case lint.Warning:
			r.Counts.Warning++
		case lint.Info:
			r.Counts.Info++
		}
	}
	r.Blocking = p.Blocking(r.Findings)
	r.Passed = r.Blocking == 0
	return r, nil
}
