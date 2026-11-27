package render

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"os"
	"strings"

	"tarav/internal/policy"
)

// ServeOptions configure Handler. Policy re-grades findings on the page;
// Review, when set, turns the page into a review with approve and reject
// controls (SPEC D24).
type ServeOptions struct {
	Policy *policy.Policy
	Review *Review
}

// Handler serves the viewer for the item at path (SPEC D16). Each page load
// re-reads and re-renders the file; GET version returns a hash of its
// current content, which the page polls to reload itself after an edit.
// Schema and read errors are shown as a page that keeps polling, so fixing
// the file brings the viewer back.
func Handler(path string, opts ServeOptions) http.Handler {
	mux := http.NewServeMux()
	var page *PageReview
	if rv := opts.Review; rv != nil {
		page = &PageReview{Stage: rv.Stage, Token: rv.Token, Reviewer: rv.Reviewer}
		mux.HandleFunc("/approve", rv.approve(path, opts.Policy))
		mux.HandleFunc("/reject", rv.reject(path))
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		noStore(w)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		raw, err := os.ReadFile(path)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, errorPage(path, versionOf(nil, err), []string{err.Error()}))
			return
		}
		res, err := Render(raw, Options{Live: true, Policy: opts.Policy, Review: page})
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, errorPage(path, res.Hash, []string{err.Error()}))
			return
		}
		if !res.Schema.OK() {
			msgs := make([]string, len(res.Schema.Errors))
			for i, e := range res.Schema.Errors {
				msgs[i] = e.String()
			}
			w.WriteHeader(http.StatusUnprocessableEntity)
			fmt.Fprint(w, errorPage(path, res.Hash, msgs))
			return
		}
		w.Write(res.HTML)
	})
	mux.HandleFunc("/version", func(w http.ResponseWriter, r *http.Request) {
		noStore(w)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		raw, err := os.ReadFile(path)
		fmt.Fprint(w, versionOf(raw, err))
	})
	if opts.Review != nil {
		return localOnly(mux)
	}
	return mux
}

// versionOf matches Result.Hash for readable files; unreadable files get a
// distinct version so the page reloads once the file is back.
func versionOf(raw []byte, err error) string {
	if err != nil {
		return "unreadable"
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:8])
}

func noStore(w http.ResponseWriter) { w.Header().Set("Cache-Control", "no-store") }

func errorPage(path, version string, msgs []string) string {
	var li strings.Builder
	for _, m := range msgs {
		fmt.Fprintf(&li, "<li>%s</li>", html.EscapeString(m))
	}
	return `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'">
<title>tarav: errors in ` + html.EscapeString(path) + `</title>
<style>body{font:14px/1.5 system-ui,sans-serif;margin:40px;color:#1c1c1a;background:#fafaf9}h1{font-size:16px;color:#c0392b}
li{font-family:ui-monospace,Menlo,monospace;font-size:12px;margin:4px 0}p{color:#6b6b66}</style></head><body>
<h1>` + html.EscapeString(path) + ` cannot be rendered</h1><ul>` + li.String() + `</ul>
<p>Fix the file and save; this page reloads by itself.</p>
<script>
const seen = ` + jsString(version) + `;
setInterval(() => fetch("version", { cache: "no-store" }).then((r) => r.text()).then((t) => { if (t && t !== seen) location.reload(); }).catch(() => {}), 1000);
</script></body></html>`
}

// jsString quotes s as a JS string literal safe inside <script>.
func jsString(s string) string {
	b, _ := json.Marshal(s) // only fails for unsupported types, never for a string
	return string(b)
}
