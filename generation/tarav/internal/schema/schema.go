// Package schema validates item-definition JSON against the bundled,
// versioned JSON Schemas (SPEC D1).
package schema

import (
	"bytes"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"golang.org/x/text/language"
	"golang.org/x/text/message"

	schemafiles "tarav/schema"
)

// LatestID is the $id of the newest bundled schema; inputs without a
// top-level "$schema" are validated against it.
const LatestID = "https://tarav.local/schema/item-definition/1.1.0"

// bundled maps every supported $id to its schema source. Older versions stay
// accepted so inputs that name them keep validating.
var bundled = map[string][]byte{
	"https://tarav.local/schema/item-definition/1.0.0": schemafiles.ItemDefinitionV1_0,
	LatestID: schemafiles.ItemDefinitionV1_1,
}

// Supported returns the bundled schema IDs, oldest first.
func Supported() []string {
	ids := make([]string, 0, len(bundled))
	for id := range bundled {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// Error is one schema violation, located by an RFC 6901 JSON Pointer into
// the input document ("" is the document root).
type Error struct {
	Pointer string `json:"json_path"`
	Message string `json:"message"`
}

func (e Error) String() string {
	p := e.Pointer
	if p == "" {
		p = "/"
	}
	return p + ": " + e.Message
}

// Result is the outcome of validating one document.
type Result struct {
	// SchemaID is the schema the document was checked against ("" if the
	// document could not be parsed or named an unknown schema).
	SchemaID string
	// Notice is a non-fatal remark for stderr, e.g. a missing "$schema".
	Notice string
	Errors []Error
}

// OK reports whether the document is valid.
func (r Result) OK() bool { return len(r.Errors) == 0 }

var (
	compileOnce sync.Once
	compiled    map[string]*jsonschema.Schema
	compileErr  error
)

func compileAll() (map[string]*jsonschema.Schema, error) {
	compileOnce.Do(func() {
		c := jsonschema.NewCompiler()
		ids := make([]string, 0, len(bundled))
		for id, src := range bundled {
			doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(src))
			if err != nil {
				compileErr = fmt.Errorf("bundled schema %s: %w", id, err)
				return
			}
			if err := c.AddResource(id, doc); err != nil {
				compileErr = fmt.Errorf("bundled schema %s: %w", id, err)
				return
			}
			ids = append(ids, id)
		}
		compiled = make(map[string]*jsonschema.Schema, len(ids))
		for _, id := range ids {
			s, err := c.Compile(id)
			if err != nil {
				compileErr = fmt.Errorf("compile schema %s: %w", id, err)
				return
			}
			compiled[id] = s
		}
	})
	return compiled, compileErr
}

// Validate checks data against the schema it names in "$schema", or the
// latest bundled schema if it names none. It never returns a Go error for
// bad input; problems with the input are reported in Result.Errors. A
// non-nil error means the bundled schemas themselves are broken.
func Validate(data []byte) (Result, error) {
	schemas, err := compileAll()
	if err != nil {
		return Result{}, err
	}

	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		return Result{Errors: []Error{{Pointer: "", Message: "not valid JSON: " + err.Error()}}}, nil
	}

	var res Result
	id := LatestID
	if obj, ok := doc.(map[string]any); ok {
		if raw, present := obj["$schema"]; present {
			s, isStr := raw.(string)
			if !isStr {
				return Result{Errors: []Error{{Pointer: "/$schema", Message: "must be a string naming a tarav item-definition schema"}}}, nil
			}
			if _, known := schemas[s]; !known {
				return Result{Errors: []Error{{Pointer: "/$schema", Message: fmt.Sprintf("unknown schema %q (supported: %s)", s, strings.Join(Supported(), ", "))}}}, nil
			}
			id = s
		} else {
			res.Notice = fmt.Sprintf("no \"$schema\" in input; validating against %s", LatestID)
		}
	}
	res.SchemaID = id

	verr := schemas[id].Validate(doc)
	if verr == nil {
		return res, nil
	}
	ve, ok := verr.(*jsonschema.ValidationError)
	if !ok {
		return res, fmt.Errorf("validate: %w", verr)
	}
	res.Errors = flatten(ve)
	return res, nil
}

// english renders library messages; the zero printer is not usable.
var english = message.NewPrinter(language.English)

// flatten turns the library's error tree into sorted leaf errors, one per
// failing keyword at its instance location. Each leaf is a distinct
// (schema keyword, instance location) pair, so no de-duplication is needed.
func flatten(ve *jsonschema.ValidationError) []Error {
	var errs []Error
	var walk func(*jsonschema.ValidationError)
	walk = func(e *jsonschema.ValidationError) {
		if len(e.Causes) > 0 {
			for _, c := range e.Causes {
				walk(c)
			}
			return
		}
		if e.ErrorKind == nil {
			return
		}
		errs = append(errs, Error{Pointer: pointer(e.InstanceLocation), Message: e.ErrorKind.LocalizedString(english)})
	}
	walk(ve)
	if len(errs) == 0 {
		errs = []Error{{Pointer: "", Message: ve.Error()}}
	}
	sort.Slice(errs, func(i, j int) bool {
		if errs[i].Pointer != errs[j].Pointer {
			return errs[i].Pointer < errs[j].Pointer
		}
		return errs[i].Message < errs[j].Message
	})
	return errs
}

// pointer encodes path tokens as an RFC 6901 JSON Pointer.
func pointer(tokens []string) string {
	var b strings.Builder
	for _, t := range tokens {
		b.WriteByte('/')
		b.WriteString(strings.NewReplacer("~", "~0", "/", "~1").Replace(t))
	}
	return b.String()
}
