// Package render assembles the self-contained viewer page: validate, lint,
// build the graph, and inline everything into one offline HTML file.
package render

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html"
	"strings"

	"tarav/internal/check"
	"tarav/internal/graph"
	"tarav/internal/lint"
	"tarav/internal/model"
	"tarav/internal/policy"
	"tarav/internal/schema"
	"tarav/web"
)

// Version is shown in the page's top bar.
const Version = "M4"

// Options tune the page. Live makes the page poll "version" next to itself
// and reload when the input changes (tarav serve). Policy re-grades the
// findings (nil is the D5 default). Review adds the approve and reject
// controls (tarav serve --review, SPEC D24).
type Options struct {
	Live   bool
	Policy *policy.Policy
	Review *PageReview
}

// PageReview is what the review controls need to know.
type PageReview struct {
	Stage    string `json:"stage"`
	Token    string `json:"token"`
	Reviewer string `json:"reviewer"`
	Passed   bool   `json:"passed"`
	Blocking int    `json:"blocking"`
	FailOn   string `json:"fail_on"`
}

// Result is the outcome of rendering one input. HTML is nil when the input
// has schema errors (D15); Findings are the lint results otherwise.
type Result struct {
	Schema   schema.Result
	Findings []lint.Finding
	// Report is the full check result (policy applied).
	Report *check.Report
	HTML   []byte
	// Hash identifies the input content; serve uses it as the page version.
	Hash string
}

// Render validates, lints and renders raw. A non-nil error is an internal
// failure (bundled assets or schemas broken), not a problem with the input.
func Render(raw []byte, opts Options) (Result, error) {
	res := Result{Hash: versionOf(raw, nil)}
	rep, err := check.Run(raw, opts.Policy)
	if err != nil {
		return res, err
	}
	res.Report = rep
	res.Schema = schema.Result{SchemaID: rep.Schema, Errors: rep.SchemaErrors, Notice: rep.Notice}
	if !res.Schema.OK() {
		return res, nil
	}
	res.Findings = rep.Findings
	if opts.Review != nil {
		r := *opts.Review
		r.Passed, r.Blocking, r.FailOn = rep.Passed, rep.Blocking, rep.FailOn
		opts.Review = &r
	}
	res.HTML, err = page(raw, rep.Item, res.Findings, opts, res.Hash)
	return res, err
}

func page(raw []byte, it *model.Item, findings []lint.Finding, opts Options, hash string) ([]byte, error) {
	tmpl, err := web.FS.ReadFile("viewer.html")
	if err != nil {
		return nil, err
	}
	css, err := asset("viewer.css", "</style")
	if err != nil {
		return nil, err
	}
	js, err := asset("viewer.js", "</script")
	if err != nil {
		return nil, err
	}
	var vendor strings.Builder
	for _, name := range web.Vendor {
		src, err := asset(name, "</script")
		if err != nil {
			return nil, err
		}
		fmt.Fprintf(&vendor, "<!-- %s -->\n<script>\n%s\n</script>\n", name, src)
	}
	g := graph.Build(it)
	graphJSON, err := scriptJSON(g)
	if err != nil {
		return nil, err
	}
	findingsJSON, err := scriptJSON(findings)
	if err != nil {
		return nil, err
	}
	// links[i] is the graph element findings[i] is shown on (D18); the
	// finding shape itself stays as plan §7 defines it.
	links := make([]string, len(findings))
	for i, f := range findings {
		links[i] = g.Locate(it, f.JSONPath)
	}
	linksJSON, err := scriptJSON(links)
	if err != nil {
		return nil, err
	}
	// The raw item is embedded as written (compacted), not re-encoded from
	// the model, so the page shows exactly what was reviewed.
	var item bytes.Buffer
	if err := json.Compact(&item, raw); err != nil {
		return nil, fmt.Errorf("compact item: %w", err)
	}
	var itemSafe bytes.Buffer
	json.HTMLEscape(&itemSafe, item.Bytes())
	cfg := map[string]any{"live": opts.Live, "version": hash}
	if opts.Review != nil {
		cfg["review"] = opts.Review
	}
	config, err := scriptJSON(cfg)
	if err != nil {
		return nil, err
	}
	title := it.ItemDefinition.Name
	if title == "" {
		title = it.ItemDefinition.ItemID
	}
	// One pass: inserted content is never rescanned for placeholders.
	out := strings.NewReplacer(
		"{{TITLE}}", html.EscapeString(title+" · tarav"),
		"{{VERSION}}", Version,
		"{{CSS}}", css,
		"{{JS}}", js,
		"{{VENDOR}}", vendor.String(),
		"{{GRAPH}}", graphJSON,
		"{{FINDINGS}}", findingsJSON,
		"{{LINKS}}", linksJSON,
		"{{ITEM}}", itemSafe.String(),
		"{{CONFIG}}", config,
	).Replace(string(tmpl))
	return []byte(out), nil
}

// asset reads an embedded file that is inlined inside a tag; it must not
// contain that tag's closing sequence.
func asset(name, closing string) (string, error) {
	b, err := web.FS.ReadFile(name)
	if err != nil {
		return "", err
	}
	if bytes.Contains(bytes.ToLower(b), []byte(closing)) {
		return "", fmt.Errorf("render: %s contains %q and cannot be inlined", name, closing)
	}
	return string(b), nil
}

// scriptJSON encodes v for a <script type="application/json"> block.
// encoding/json escapes <, > and & as < etc., so the content cannot
// close the script element.
func scriptJSON(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
