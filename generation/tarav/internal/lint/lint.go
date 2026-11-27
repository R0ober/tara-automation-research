// Package lint runs registered rules over an item definition and returns
// findings in a deterministic order.
package lint

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"

	"tarav/internal/model"
)

// Severity of a finding. Error-severity findings fail the run (SPEC D5).
type Severity string

const (
	Error   Severity = "error"
	Warning Severity = "warning"
	Info    Severity = "info"
)

// Finding is one lint result. The shape is fixed by plan §7; all five
// fields are always populated.
type Finding struct {
	Rule      string   `json:"rule"`
	Severity  Severity `json:"severity"`
	Message   string   `json:"message"`
	JSONPath  string   `json:"json_path"` // RFC 6901 pointer to the offending value
	ElementID string   `json:"element_id"`
}

// Rule is a registered check. Check returns findings without Rule and
// Severity set; Run fills those in from the rule.
type Rule struct {
	ID          string
	Severity    Severity
	Description string
	Check       func(*model.Item) []Finding
}

var (
	mu       sync.RWMutex
	registry = map[string]Rule{}
)

// Register adds a rule. It panics on an incomplete rule or a duplicate ID,
// both programming errors caught at init.
func Register(r Rule) {
	if r.ID == "" || r.Check == nil || r.Description == "" {
		panic(fmt.Sprintf("lint: incomplete rule %+v", r))
	}
	switch r.Severity {
	case Error, Warning, Info:
	default:
		panic(fmt.Sprintf("lint: rule %s has invalid severity %q", r.ID, r.Severity))
	}
	mu.Lock()
	defer mu.Unlock()
	if _, dup := registry[r.ID]; dup {
		panic("lint: duplicate rule " + r.ID)
	}
	registry[r.ID] = r
}

// Rules returns the registered rules sorted by ID.
func Rules() []Rule {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]Rule, 0, len(registry))
	for _, r := range registry {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Run applies every registered rule and returns the findings sorted by
// (json_path, rule, message). Paths compare token by token, numerically
// for array indices, so /components/2 sorts before /components/10.
func Run(it *model.Item) []Finding {
	var all []Finding
	for _, r := range Rules() {
		for _, f := range r.Check(it) {
			f.Rule, f.Severity = r.ID, r.Severity
			all = append(all, f)
		}
	}
	sort.SliceStable(all, func(i, j int) bool { return less(all[i], all[j]) })
	return all
}

// HasErrors reports whether any finding is error-severity.
func HasErrors(fs []Finding) bool {
	for _, f := range fs {
		if f.Severity == Error {
			return true
		}
	}
	return false
}

func less(a, b Finding) bool {
	if c := ComparePointers(a.JSONPath, b.JSONPath); c != 0 {
		return c < 0
	}
	if a.Rule != b.Rule {
		return a.Rule < b.Rule
	}
	return a.Message < b.Message
}

// ComparePointers orders two JSON pointers token by token; tokens that are
// both non-negative integers compare numerically, others as strings, and a
// prefix sorts first.
func ComparePointers(a, b string) int {
	ta, tb := strings.Split(a, "/"), strings.Split(b, "/")
	for i := 0; i < len(ta) && i < len(tb); i++ {
		if ta[i] == tb[i] {
			continue
		}
		na, ea := strconv.Atoi(ta[i])
		nb, eb := strconv.Atoi(tb[i])
		if ea == nil && eb == nil && na >= 0 && nb >= 0 {
			if na < nb {
				return -1
			}
			return 1
		}
		if ta[i] < tb[i] {
			return -1
		}
		return 1
	}
	switch {
	case len(ta) < len(tb):
		return -1
	case len(ta) > len(tb):
		return 1
	}
	return 0
}
