package render

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tarav/internal/approval"
	"tarav/internal/check"
	"tarav/internal/policy"
)

type reviewEnv struct {
	t      *testing.T
	item   string
	log    string
	rv     *Review
	srv    *httptest.Server
	policy *policy.Policy
}

func newReviewEnv(t *testing.T, rel string, pol *policy.Policy) *reviewEnv {
	t.Helper()
	dir := t.TempDir()
	e := &reviewEnv{t: t, item: filepath.Join(dir, "item.json"), log: filepath.Join(dir, "approvals.json"), policy: pol}
	e.write(rel)
	rv, err := NewReview("item-definition", "Ada", e.log)
	if err != nil {
		t.Fatal(err)
	}
	rv.Now = func() time.Time { return time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC) }
	e.rv = rv
	e.srv = httptest.NewServer(Handler(e.item, ServeOptions{Policy: pol, Review: rv}))
	t.Cleanup(e.srv.Close)
	return e
}

func (e *reviewEnv) write(rel string) {
	if err := os.WriteFile(e.item, read(e.t, rel), 0o644); err != nil {
		e.t.Fatal(err)
	}
}

func (e *reviewEnv) version() string {
	_, v, _ := get(e.t, e.srv, "/version")
	return v
}

// post sends a decision; body fields default to a valid request.
func (e *reviewEnv) post(path string, mod func(*http.Request), fields map[string]string) (int, map[string]any) {
	e.t.Helper()
	d := map[string]string{"token": e.rv.Token, "version": e.version(), "reviewer": "Ada", "comment": ""}
	for k, v := range fields {
		d[k] = v
	}
	b, _ := json.Marshal(d)
	req, _ := http.NewRequest(http.MethodPost, e.srv.URL+path, strings.NewReader(string(b)))
	req.Header.Set("Content-Type", "application/json")
	if mod != nil {
		mod(req)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var m map[string]any
	json.Unmarshal(raw, &m)
	return resp.StatusCode, m
}

func (e *reviewEnv) outcome() *Outcome {
	select {
	case o := <-e.rv.Done:
		return &o
	default:
		return nil
	}
}

func TestReviewApprove(t *testing.T) {
	e := newReviewEnv(t, "lint/L017-all-stated.json", nil)

	_, body, _ := get(t, e.srv, "/")
	cfg := scriptBody(t, body, "tarav-config")
	if !strings.Contains(cfg, `"review":{"stage":"item-definition","token":"`+e.rv.Token+`","reviewer":"Ada","passed":true,"blocking":0,"fail_on":"error"}`) {
		t.Errorf("page config: %s", cfg)
	}

	// Requests the server must refuse, none of which decide the review.
	refused := []struct {
		name   string
		mod    func(*http.Request)
		fields map[string]string
		want   int
	}{
		{"wrong token", nil, map[string]string{"token": "x"}, http.StatusForbidden},
		{"form content type", func(r *http.Request) { r.Header.Set("Content-Type", "application/x-www-form-urlencoded") }, nil, http.StatusUnsupportedMediaType},
		{"cross origin", func(r *http.Request) { r.Header.Set("Origin", "http://evil.example") }, nil, http.StatusForbidden},
		{"stale version", nil, map[string]string{"version": "0000000000000000"}, http.StatusConflict},
		{"no reviewer", nil, map[string]string{"reviewer": "  "}, http.StatusBadRequest},
		{"long comment", nil, map[string]string{"comment": strings.Repeat("x", 2001)}, http.StatusBadRequest},
		{"unknown field", nil, map[string]string{"approved": "yes"}, http.StatusBadRequest},
	}
	for _, c := range refused {
		if code, m := e.post("/approve", c.mod, c.fields); code != c.want {
			t.Errorf("%s: %d %v, want %d", c.name, code, m, c.want)
		}
	}
	if code, _, _ := get(t, e.srv, "/approve"); code != http.StatusMethodNotAllowed {
		t.Errorf("GET /approve = %d", code)
	}
	if o := e.outcome(); o != nil {
		t.Fatalf("refused requests decided the review: %+v", o)
	}
	if _, err := os.Stat(e.log); err == nil {
		t.Fatal("refused requests wrote the approvals log")
	}

	code, m := e.post("/approve", nil, map[string]string{"reviewer": " Ada Lovelace ", "comment": "looks right"})
	if code != http.StatusOK || m["reviewer"] != "Ada Lovelace" || m["approved"] != true {
		t.Fatalf("approve: %d %v", code, m)
	}
	o := e.outcome()
	if o == nil || o.Record == nil || o.Denial != nil {
		t.Fatalf("outcome: %+v", o)
	}
	raw, _ := os.ReadFile(e.item)
	want := approval.Record{
		Approved: true, Stage: "item-definition", File: e.item, SHA256: check.Hash(raw), Reviewer: "Ada Lovelace",
		ApprovedAt: time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC), Comment: "looks right", Tarav: Version,
	}
	if *o.Record != want {
		t.Errorf("record:\n got %+v\nwant %+v", *o.Record, want)
	}
	l, err := approval.Read(e.log)
	if err != nil || len(l.Approvals) != 1 || l.Approvals[0] != want {
		t.Errorf("log: %v %+v", err, l)
	}

	// Decided: both endpoints refuse from now on.
	for _, p := range []string{"/approve", "/reject"} {
		if code, _ := e.post(p, nil, nil); code != http.StatusGone {
			t.Errorf("%s after decision = %d, want 410", p, code)
		}
	}
}

// A file that fails the policy cannot be approved, but editing it during
// the review fixes that.
func TestReviewBlockedThenFixed(t *testing.T) {
	strict, err := policy.Load("../../testdata/policy/strict.json")
	if err != nil {
		t.Fatal(err)
	}
	e := newReviewEnv(t, "lint/L017-missing-flags.json", strict)
	_, body, _ := get(t, e.srv, "/")
	if cfg := scriptBody(t, body, "tarav-config"); !strings.Contains(cfg, `"passed":false`) || !strings.Contains(cfg, `"fail_on":"warning"`) {
		t.Errorf("blocked page config: %s", cfg)
	}
	if code, m := e.post("/approve", nil, nil); code != http.StatusUnprocessableEntity {
		t.Errorf("approve failing file: %d %v", code, m)
	}
	e.write("schema/wrong-type.json")
	if code, _ := e.post("/approve", nil, nil); code != http.StatusUnprocessableEntity {
		t.Errorf("approve schema-invalid file: %d", code)
	}
	e.write("lint/L017-all-stated.json")
	code, m := e.post("/approve", nil, nil)
	if code != http.StatusOK || m["policy_sha256"] != strict.SHA256 {
		t.Errorf("approve fixed file: %d %v", code, m)
	}
}

func TestReviewReject(t *testing.T) {
	e := newReviewEnv(t, "valid/minimal.json", nil)
	code, m := e.post("/reject", nil, map[string]string{"comment": "  zones are wrong ", "version": "anything"})
	if code != http.StatusOK || m["approved"] != false || m["reason"] != "zones are wrong" || m["reviewer"] != "Ada" {
		t.Fatalf("reject: %d %v", code, m)
	}
	o := e.outcome()
	if o == nil || o.Denial == nil || o.Record != nil || len(o.Denial.SHA256) != 64 {
		t.Fatalf("outcome: %+v", o)
	}
	if _, err := os.Stat(e.log); err == nil {
		t.Error("reject wrote the approvals log")
	}

	e2 := newReviewEnv(t, "valid/minimal.json", nil)
	if _, m := e2.post("/reject", nil, nil); m["reason"] != "rejected by the reviewer" {
		t.Errorf("default reason: %v", m)
	}
}

// DNS rebinding: a review page must not be served to a foreign host name.
func TestReviewLocalOnly(t *testing.T) {
	e := newReviewEnv(t, "valid/minimal.json", nil)
	for host, want := range map[string]int{
		"evil.example:8000": http.StatusMisdirectedRequest,
		"evil.example":      http.StatusMisdirectedRequest,
		"localhost:8000":    http.StatusOK,
		"127.0.0.1:8000":    http.StatusOK,
		"[::1]:8000":        http.StatusOK,
		"10.1.2.3":          http.StatusOK,
	} {
		req, _ := http.NewRequest(http.MethodGet, e.srv.URL+"/version", nil)
		req.Host = host
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != want {
			t.Errorf("Host %s: %d, want %d", host, resp.StatusCode, want)
		}
	}
	// Plain serve has no review endpoints.
	plain := httptest.NewServer(Handler(e.item, ServeOptions{}))
	defer plain.Close()
	if code, _, _ := get(t, plain, "/approve"); code != http.StatusNotFound {
		t.Errorf("plain serve /approve = %d", code)
	}
	if _, body, _ := get(t, plain, "/"); strings.Contains(scriptBody(t, body, "tarav-config"), "review") {
		t.Error("plain serve page has review config")
	}
}
