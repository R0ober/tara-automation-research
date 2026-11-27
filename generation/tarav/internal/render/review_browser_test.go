package render

import (
	"bytes"
	"context"
	"encoding/json"
	"html"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"tarav/internal/policy"
)

// reviewInBrowser serves item under review, injects the driver with
// scenario into the page, loads it in headless Chrome and returns the
// scenario result, the page errors and the review outcome (nil if none).
func reviewInBrowser(t *testing.T, bin, rel string, pol *policy.Policy, scenario string, out any) ([]string, *Outcome) {
	t.Helper()
	dir := t.TempDir()
	item := filepath.Join(dir, "item.json")
	if err := os.WriteFile(item, read(t, rel), 0o644); err != nil {
		t.Fatal(err)
	}
	rv, err := NewReview("item-definition", "Ada", filepath.Join(dir, "approvals.json"))
	if err != nil {
		t.Fatal(err)
	}
	h := Handler(item, ServeOptions{Policy: pol, Review: rv})
	drv := strings.Replace(driverHead, "SCENARIO", scenario, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			h.ServeHTTP(w, r)
			return
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		for k, v := range rec.Header() {
			w.Header()[k] = v
		}
		w.WriteHeader(rec.Code)
		w.Write(bytes.Replace(rec.Body.Bytes(), []byte("<head>"), []byte("<head>"+drv), 1))
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	dom, err := exec.CommandContext(ctx, bin, "--headless=new", "--disable-gpu", "--no-first-run", "--no-default-browser-check",
		"--user-data-dir="+filepath.Join(dir, "profile"), "--window-size=1400,900",
		"--virtual-time-budget=30000", "--dump-dom", srv.URL+"/").Output()
	if err != nil {
		t.Fatalf("chrome: %v", err)
	}
	m := smokeRE.FindSubmatch(dom)
	if m == nil {
		t.Fatalf("%s: driver produced no result", rel)
	}
	var env struct {
		Errs   []string        `json:"errs"`
		Result json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal([]byte(html.UnescapeString(string(m[1]))), &env); err != nil {
		t.Fatalf("bad driver result: %v", err)
	}
	if err := json.Unmarshal(env.Result, out); err != nil {
		t.Fatalf("bad scenario result: %v\n%s", err, env.Result)
	}
	select {
	case o := <-rv.Done:
		return env.Errs, &o
	default:
		return env.Errs, nil
	}
}

type reviewState struct {
	Shown           bool   `json:"shown"`
	Open            bool   `json:"open"`
	Choice          string `json:"choice"`
	Submit          string `json:"submit"`
	ApproveDisabled bool   `json:"approveDisabled"`
	Decided         string `json:"decided"`
	Overlay         string `json:"overlay"`
}

// Approve through the real modal: one Review button opens it; Cancel, the
// close button and the backdrop close it; the toggle switches the submit
// button; submitting records the approval and the page shows it.
func TestBrowserReviewApprove(t *testing.T) {
	bin := chrome(t)
	var got struct {
		Before   reviewState `json:"before"`
		Steps    []string    `json:"steps"`
		Toggle   []string    `json:"toggle"`
		NoReason string      `json:"noReason"`
		Prefill  string      `json:"prefill"`
		After    reviewState `json:"after"`
	}
	errs, o := reviewInBrowser(t, bin, "bbw/item-definition.json", nil, `async (t) => {
  const r = { before: t.reviewState(), steps: [], toggle: [] };
  const dlg = document.getElementById("review-dialog"), btn = document.getElementById("review-btn");
  const st = () => r.steps.push(dlg.open ? "open" : "closed");
  st();
  btn.click(); st(); document.getElementById("review-cancel").click(); st();
  btn.click(); st(); document.getElementById("review-cancel-x").click(); st();
  btn.click(); st(); dlg.click(); st();
  btn.click(); st();
  const f = dlg.querySelector("form");
  r.prefill = f.reviewer.value;
  f.querySelector("input[value=reject]").click(); r.toggle.push(t.reviewState().submit);
  f.requestSubmit(); r.noReason = f.querySelector(".err").textContent;
  f.querySelector("input[value=approve]").click(); r.toggle.push(t.reviewState().submit);
  f.reviewer.value = "Ada Lovelace";
  f.comment.value = "zones and protection reviewed";
  f.requestSubmit();
  for (let i = 0; i < 100 && !t.reviewState().decided; i++) await new Promise((res) => setTimeout(res, 50));
  r.after = t.reviewState();
  return r;
}`, &got)
	if len(errs) > 0 {
		t.Errorf("page errors: %v", errs)
	}
	if b := got.Before; !b.Shown || b.Open || b.ApproveDisabled || b.Choice != "approve" || b.Submit != "Approve" || got.Prefill != "Ada" {
		t.Errorf("before reviewing: %+v prefill=%q", b, got.Prefill)
	}
	if want := []string{"closed", "open", "closed", "open", "closed", "open", "closed", "open"}; !reflect.DeepEqual(got.Steps, want) {
		t.Errorf("modal open/closed after each step = %v, want %v", got.Steps, want)
	}
	if !reflect.DeepEqual(got.Toggle, []string{"Reject", "Approve"}) || got.NoReason == "" {
		t.Errorf("toggle: submit labels %v; reject without reason: %q", got.Toggle, got.NoReason)
	}
	if a := got.After; a.Decided != "approved" || a.Open || !strings.Contains(a.Overlay, "approved by Ada Lovelace") {
		t.Errorf("after approving: %+v", a)
	}
	if o == nil || o.Record == nil || o.Record.Reviewer != "Ada Lovelace" || o.Record.Comment != "zones and protection reviewed" {
		t.Errorf("server outcome: %+v", o)
	}
}

// A file that fails the policy opens the modal on Reject with Approve
// disabled and says why; rejecting still works.
func TestBrowserReviewBlocked(t *testing.T) {
	bin := chrome(t)
	strict, err := policy.Load("../../testdata/policy/strict.json")
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Before  reviewState     `json:"before"`
		Note    string          `json:"note"`
		Approve json.RawMessage `json:"approve"`
		Reject  json.RawMessage `json:"reject"`
		After   reviewState     `json:"after"`
	}
	errs, o := reviewInBrowser(t, bin, "bbw/item-definition.json", strict, `async (t) => {
  const r = { before: t.reviewState(), note: (document.querySelector("#review-dialog .blockednote") || {}).textContent || "" };
  r.approve = await t.review("approve", "Ada", "");
  r.reject = await t.review("reject", "Ada", "missing protection flags");
  r.after = t.reviewState();
  return r;
}`, &got)
	if len(errs) > 0 {
		t.Errorf("page errors: %v", errs)
	}
	if b := got.Before; !b.ApproveDisabled || b.Choice != "reject" || b.Submit != "Reject" || !strings.Contains(got.Note, "at or above warning") {
		t.Errorf("blocked modal: %+v note=%q", b, got.Note)
	}
	if !strings.Contains(string(got.Approve), "disabled") {
		t.Errorf("approving a blocked file: %s", got.Approve)
	}
	if got.After.Decided != "rejected" || !strings.Contains(got.After.Overlay, "missing protection flags") {
		t.Errorf("after rejecting: %+v %s", got.After, got.Reject)
	}
	if o == nil || o.Denial == nil || o.Denial.Reason != "missing protection flags" {
		t.Errorf("server outcome: %+v", o)
	}
}
