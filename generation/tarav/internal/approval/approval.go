// Package approval records human approvals of a file at a pipeline stage
// and checks them at the gate (SPEC D23, D25). A record binds a reviewer
// and a stage to the SHA-256 of the exact bytes they approved, so any
// later edit invalidates it. Records are an audit trail, not a signature:
// anyone who can write the file can forge one.
package approval

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Record is one approval. The JSON form is the contract with pipeline callers.
type Record struct {
	Approved     bool      `json:"approved"`
	Stage        string    `json:"stage"`
	File         string    `json:"file"`
	SHA256       string    `json:"sha256"`
	Reviewer     string    `json:"reviewer"`
	ApprovedAt   time.Time `json:"approved_at"`
	Comment      string    `json:"comment,omitempty"`
	Tarav        string    `json:"tarav_version"`
	PolicySHA256 string    `json:"policy_sha256,omitempty"`
	Findings     Counts    `json:"findings"`
}

// Counts is the finding tally at approval time.
type Counts struct {
	Error   int `json:"error"`
	Warning int `json:"warning"`
	Info    int `json:"info"`
}

// Denial is what gate and a rejected review report instead of a Record.
type Denial struct {
	Approved bool   `json:"approved"` // always false
	Stage    string `json:"stage"`
	File     string `json:"file"`
	SHA256   string `json:"sha256,omitempty"`
	Reason   string `json:"reason"`
	Reviewer string `json:"reviewer,omitempty"`
}

// Log is the approvals file: every approval ever recorded, oldest first.
type Log struct {
	Approvals []Record `json:"approvals"`
}

var stageRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)

// ValidStage reports whether s is a usable stage name: lower-case letters,
// digits and dashes, e.g. "item-definition" or "attack-path-analysis".
func ValidStage(s string) error {
	if !stageRE.MatchString(s) {
		return fmt.Errorf("stage %q: want lower-case letters, digits and dashes (e.g. item-definition)", s)
	}
	return nil
}

// ValidReviewer rejects empty or multi-line reviewer names.
func ValidReviewer(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", errors.New("reviewer name is empty")
	}
	if strings.ContainsAny(s, "\r\n") || len(s) > 200 {
		return "", errors.New("reviewer name must be one line of at most 200 bytes")
	}
	return s, nil
}

// DefaultPath is the approvals file next to the input: FILE.approvals.json.
func DefaultPath(file string) string { return file + ".approvals.json" }

// Read loads the approvals log; a missing file is an empty log.
func Read(path string) (*Log, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return &Log{Approvals: []Record{}}, nil
	}
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	l := &Log{}
	if err := dec.Decode(l); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if l.Approvals == nil {
		l.Approvals = []Record{}
	}
	return l, nil
}

// Append adds rec to the log at path, writing through a temporary file and
// a rename so a crash never leaves a half-written log.
func Append(path string, rec Record) error {
	l, err := Read(path)
	if err != nil {
		return err
	}
	l.Approvals = append(l.Approvals, rec)
	b, err := json.MarshalIndent(l, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".approvals-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // no-op after a successful rename
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// Find returns the newest record for stage whose hash is sha, or nil and a
// reason why the gate stays closed.
func (l *Log) Find(stage, sha string) (*Record, string) {
	var staleAt *Record
	for i := len(l.Approvals) - 1; i >= 0; i-- {
		r := &l.Approvals[i]
		if r.Stage != stage || !r.Approved {
			continue
		}
		if r.SHA256 == sha {
			return r, ""
		}
		if staleAt == nil {
			staleAt = r
		}
	}
	if staleAt != nil {
		return nil, fmt.Sprintf("file changed since %s approved it at %s; review it again",
			staleAt.Reviewer, staleAt.ApprovedAt.Format(time.RFC3339))
	}
	return nil, "no approval recorded for this stage"
}
