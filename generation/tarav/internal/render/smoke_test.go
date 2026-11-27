package render

import (
	"bytes"
	"context"
	"encoding/json"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// driverHead is injected first in <head> so it sees every console message
// and error. After load it waits for the layout, runs the scenario (an
// async function of the window.__tarav hooks), and writes {errs, result}
// into the DOM for --dump-dom.
const driverHead = `<script>
(function () {
  const errs = [];
  const oe = console.error, ow = console.warn;
  console.error = function () { errs.push("console.error: " + [...arguments].join(" ")); oe.apply(console, arguments); };
  console.warn = function () { errs.push("console.warn: " + [...arguments].join(" ")); ow.apply(console, arguments); };
  window.addEventListener("error", (e) => errs.push("pageerror: " + e.message));
  window.addEventListener("unhandledrejection", (e) => errs.push("rejection: " + e.reason));
  window.addEventListener("load", async () => {
    const out = { errs };
    try {
      const t = window.__tarav;
      await t.ready;
      out.result = await (SCENARIO)(t);
    } catch (e) { errs.push("driver: " + e.stack); }
    const pre = document.createElement("pre");
    pre.id = "tarav-smoke";
    pre.textContent = JSON.stringify(out);
    document.body.appendChild(pre);
  });
})();
</script>`

// smokeScenario is the M2 smoke check: route, positions, and optionally
// route again with a group expanded (hash "expand=ID").
const smokeScenario = `async (t) => {
  const q = new URLSearchParams(location.hash.slice(1)), r = { route: t.routeCheck(), pos: t.positions() };
  if (q.get("expand")) { await t.toggleGroup(q.get("expand")); r.expanded = t.routeCheck(); }
  return r;
}`

type route struct {
	Edges     int      `json:"edges"`
	MaxErr    float64  `json:"maxErr"`
	OffSide   []string `json:"offSide"`
	Diagonal  []string `json:"diagonal"`
	Crossings []string `json:"crossings"`
}

type smoke struct {
	Route    *route   `json:"route"`
	Expanded *route   `json:"expanded"`
	Pos      [][3]any `json:"pos"`
}

func chrome(t *testing.T) string {
	if testing.Short() {
		t.Skip("browser smoke test skipped in -short mode")
	}
	if p := os.Getenv("TARAV_CHROME"); p != "" {
		return p
	}
	for _, name := range []string{"google-chrome", "google-chrome-stable", "chromium", "chromium-browser"} {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	t.Skip("no Chrome/Chromium found (set TARAV_CHROME to run the browser smoke test)")
	return ""
}

var smokeRE = regexp.MustCompile(`(?s)<pre id="tarav-smoke">(.*?)</pre>`)

// run renders rel, injects the driver with scenario, opens the page
// headless with networking blocked (a proxy that refuses connections) and
// decodes the scenario's result into out. It returns the page's console
// and script errors.
func run(t *testing.T, bin, rel, hash, scenario string, out any) []string {
	t.Helper()
	res, err := Render(read(t, rel), Options{})
	if err != nil || res.HTML == nil {
		t.Fatalf("render %s: %v %v", rel, err, res.Schema.Errors)
	}
	dir := t.TempDir()
	page := filepath.Join(dir, "page.html")
	drv := strings.Replace(driverHead, "SCENARIO", scenario, 1)
	html5 := strings.Replace(string(res.HTML), "<head>", "<head>"+drv, 1)
	if err := os.WriteFile(page, []byte(html5), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "--headless=new", "--disable-gpu", "--no-first-run", "--no-default-browser-check",
		"--user-data-dir="+filepath.Join(dir, "profile"), "--proxy-server=127.0.0.1:9", "--window-size=1400,900",
		"--virtual-time-budget=60000", "--enable-logging=stderr", "--v=0", "--dump-dom", (&url.URL{Scheme: "file", Path: page, Fragment: hash}).String())
	var logs bytes.Buffer
	cmd.Stderr = &logs
	dom, err := cmd.Output()
	if err != nil {
		t.Fatalf("chrome: %v", err)
	}
	m := smokeRE.FindSubmatch(dom)
	if m == nil {
		var console []string
		for _, l := range strings.Split(logs.String(), "\n") {
			if strings.Contains(l, "CONSOLE") || strings.Contains(l, "Uncaught") {
				console = append(console, l)
			}
		}
		t.Fatalf("%s: driver produced no result (page did not load?)\n%s", rel, strings.Join(console, "\n"))
	}
	var env struct {
		Errs   []string        `json:"errs"`
		Result json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal([]byte(html.UnescapeString(string(m[1]))), &env); err != nil {
		t.Fatalf("%s: bad driver result: %v", rel, err)
	}
	if out != nil && len(env.Result) > 0 {
		if err := json.Unmarshal(env.Result, out); err != nil {
			t.Fatalf("%s: bad scenario result: %v\n%s", rel, err, env.Result)
		}
	}
	return env.Errs
}

func load(t *testing.T, bin, rel, hash string) (smoke, []string) {
	t.Helper()
	var s smoke
	errs := run(t, bin, rel, hash, smokeScenario, &s)
	return s, errs
}

func checkRoute(t *testing.T, what string, r *route) {
	t.Helper()
	switch {
	case r == nil:
		t.Errorf("%s: no route check", what)
	case r.Edges == 0:
		t.Errorf("%s: no edges drawn", what)
	case r.MaxErr > 0.5 || len(r.OffSide)+len(r.Diagonal)+len(r.Crossings) > 0:
		t.Errorf("%s: routing %+v", what, *r)
	}
}

// SPEC M2 criteria: zero console errors, routeCheck clean, identical layout
// on reload, for the three samples (BBW also with EMBA expanded).
func TestBrowserSmoke(t *testing.T) {
	bin := chrome(t)
	cases := []struct{ rel, hash string }{
		{"bbw/item-definition.json", "expand=COMP-EMBA"},
		{"ota-adas/item-definition.json", ""},
		{"zone/zones-wrap.json", "expand=COMP-ACT"},
	}
	for _, c := range cases {
		t.Run(c.rel, func(t *testing.T) {
			a, errs := load(t, bin, c.rel, c.hash)
			if len(errs) > 0 {
				t.Errorf("console/page errors: %q", errs)
			}
			checkRoute(t, "initial", a.Route)
			if c.hash != "" {
				checkRoute(t, "expanded", a.Expanded)
			}
			b, _ := load(t, bin, c.rel, "")
			if len(a.Pos) == 0 || !reflect.DeepEqual(a.Pos, b.Pos) {
				t.Errorf("layout differs between loads:\n%v\n%v", a.Pos, b.Pos)
			}
		})
	}
}

// SPEC M2: serve reloads the page after the input changes. The file is
// edited from inside the server on the page's second version poll, so the
// test does not depend on wall-clock timing; Chrome must then load the page
// again and end on the new item.
func TestBrowserLiveReload(t *testing.T) {
	bin := chrome(t)
	dir := t.TempDir()
	item := filepath.Join(dir, "item.json")
	if err := os.WriteFile(item, read(t, "valid/minimal.json"), 0o644); err != nil {
		t.Fatal(err)
	}
	var polls, pages atomic.Int32
	h := Handler(item, ServeOptions{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/version":
			if polls.Add(1) == 2 {
				if err := os.WriteFile(item, read(t, "bbw/item-definition.json"), 0o644); err != nil {
					t.Error(err)
				}
			}
		case "/":
			pages.Add(1)
		}
		h.ServeHTTP(w, r)
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, "--headless=new", "--disable-gpu", "--no-first-run", "--no-default-browser-check",
		"--user-data-dir="+filepath.Join(dir, "profile"), "--virtual-time-budget=10000", "--dump-dom", srv.URL+"/").Output()
	if err != nil {
		t.Fatalf("chrome: %v", err)
	}
	if pages.Load() < 2 {
		t.Errorf("page loaded %d times after %d polls; want a reload after the edit", pages.Load(), polls.Load())
	}
	if !strings.Contains(string(out), "<title>Electronic Brake-by-Wire") {
		t.Errorf("final page is not the edited item: %.200s", out)
	}
}
