package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"tarav/internal/approval"
	"tarav/internal/check"
)

func copyTo(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(td(rel))
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "item.json")
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCheckExitCodes(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want int
	}{
		{"bbw", []string{"check", td("bbw/item-definition.json")}, exitOK},
		{"bbw json", []string{"check", td("bbw/item-definition.json"), "--format", "json"}, exitOK},
		{"error finding", []string{"check", td("lint/L002-duplicate-ids.json")}, exitFindings},
		{"schema error", []string{"check", "--format", "json", td("schema/wrong-type.json")}, exitFindings},
		{"warnings pass by default", []string{"check", td("lint/L017-missing-flags.json")}, exitOK},
		{"strict policy fails warnings", []string{"check", "--policy", td("policy/strict.json"), td("lint/L017-missing-flags.json")}, exitFindings},
		{"relaxed policy passes L003", []string{"check", "--policy", td("policy/relaxed.json"), td("lint/L003-no-damage-scenario.json")}, exitOK},
		{"missing policy", []string{"check", "--policy", td("policy/nope.json"), td("bbw/item-definition.json")}, exitUsage},
		{"bad policy", []string{"check", "--policy", td("bbw/item-definition.json"), td("bbw/item-definition.json")}, exitUsage},
		{"missing file", []string{"check", td("nope.json")}, exitUsage},
		{"two files", []string{"check", td("bbw/item-definition.json"), td("bbw/item-definition.json")}, exitUsage},
		{"bad format", []string{"check", "--format", "sarif", td("bbw/item-definition.json")}, exitUsage},
		{"approve no reviewer", []string{"approve", td("bbw/item-definition.json")}, exitUsage},
		{"approve bad stage", []string{"approve", "--reviewer", "a", "--stage", "Bad Stage", td("bbw/item-definition.json")}, exitUsage},
		{"approve no file", []string{"approve", "--reviewer", "a"}, exitUsage},
		{"gate bad stage", []string{"gate", "--stage", "x/y", td("bbw/item-definition.json")}, exitUsage},
		{"gate missing file", []string{"gate", td("nope.json")}, exitUsage},
		{"serve stage without review", []string{"serve", "--stage", "x", td("bbw/item-definition.json")}, exitUsage},
		{"serve review bad stage", []string{"serve", "--review", "--stage", "X", td("bbw/item-definition.json")}, exitUsage},
		{"serve bad policy", []string{"serve", "--policy", td("policy/nope.json"), td("bbw/item-definition.json")}, exitUsage},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got, o, e := runT(c.args...); got != c.want {
				t.Errorf("exit = %d, want %d\nstdout: %s\nstderr: %s", got, c.want, o, e)
			}
		})
	}
}

func TestCheckJSONReport(t *testing.T) {
	code, out, _ := runT("check", "--format", "json", "--policy", td("policy/strict.json"), td("lint/L017-missing-flags.json"))
	var r check.Report
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatalf("stdout is not one JSON report: %v\n%s", err, out)
	}
	if code != exitFindings || r.Passed || r.Blocking == 0 || r.FailOn != "warning" || r.PolicySHA256 == "" ||
		r.File != td("lint/L017-missing-flags.json") || len(r.SHA256) != 64 || len(r.Findings) != r.Counts.Warning {
		t.Errorf("exit %d, report %+v", code, r)
	}

	_, out, _ = runT("check", "--format", "json", td("schema/wrong-type.json"))
	if err := json.Unmarshal([]byte(out), &r); err != nil || len(r.SchemaErrors) == 0 || r.Passed {
		t.Errorf("schema error report: %v %s", err, out)
	}
}

func TestCheckText(t *testing.T) {
	_, out, _ := runT("check", td("lint/L002-duplicate-ids.json"))
	if !strings.Contains(out, "error L002") || !strings.Contains(out, "FAILED (") {
		t.Errorf("text report:\n%s", out)
	}
	_, out, _ = runT("check", td("schema/wrong-type.json"))
	if !strings.Contains(out, "FAILED (") || !strings.Contains(out, " schema error") {
		t.Errorf("schema text report:\n%s", out)
	}
	_, out, _ = runT("check", td("lint/L017-all-stated.json"))
	if !strings.HasSuffix(out, ": passed; 0 errors, 0 warnings, 0 info\n") {
		t.Errorf("passing text report:\n%s", out)
	}
}

// The CLI path of the pipeline: approve, then gate; an edit closes the gate.
func TestApproveThenGate(t *testing.T) {
	now = func() time.Time { return time.Date(2026, 11, 26, 9, 30, 0, 0, time.FixedZone("x", 3600)) }
	defer func() { now = time.Now }()
	item := copyTo(t, "lint/L017-missing-flags.json")
	log := approval.DefaultPath(item)

	code, out, _ := runT("gate", item)
	var d approval.Denial
	if code != exitNotApproved || json.Unmarshal([]byte(out), &d) != nil || d.Approved || !strings.Contains(d.Reason, "no approval") {
		t.Fatalf("gate before approval: %d %s", code, out)
	}

	// A file that fails the policy is not approved and nothing is written.
	if code, out, errOut := runT("approve", "--reviewer", "Ada", "--policy", td("policy/strict.json"), item); code != exitFindings || out != "" || !strings.Contains(errOut, "nothing recorded") {
		t.Fatalf("approve failing: %d %q %s", code, out, errOut)
	}
	if _, err := os.Stat(log); err == nil {
		t.Fatal("failed approve wrote the log")
	}

	code, out, _ = runT("approve", "--reviewer", "Ada", "--comment", "ok", item)
	var rec approval.Record
	if code != exitOK || json.Unmarshal([]byte(out), &rec) != nil {
		t.Fatalf("approve: %d %s", code, out)
	}
	raw, _ := os.ReadFile(item)
	if !rec.Approved || rec.Stage != "item-definition" || rec.SHA256 != check.Hash(raw) || rec.Reviewer != "Ada" ||
		rec.ApprovedAt.Format(time.RFC3339) != "2026-11-26T08:30:00Z" || rec.Findings.Warning == 0 || rec.Comment != "ok" {
		t.Errorf("record %+v", rec)
	}

	if code, out, _ = runT("gate", item); code != exitOK || !strings.Contains(out, `"reviewer": "Ada"`) {
		t.Errorf("gate after approval: %d %s", code, out)
	}
	if code, _, _ = runT("gate", "--stage", "attack-path-analysis", item); code != exitNotApproved {
		t.Errorf("other stage: %d", code)
	}

	// Any edit, even whitespace, closes the gate.
	os.WriteFile(item, append(raw, '\n'), 0o644)
	code, out, _ = runT("gate", item)
	if code != exitNotApproved || !strings.Contains(out, "file changed since Ada approved it") {
		t.Errorf("gate after edit: %d %s", code, out)
	}

	// A custom log path, and a corrupt log is an I/O error, not a closed gate.
	alt := filepath.Join(filepath.Dir(item), "alt.json")
	if code, _, _ = runT("approve", "--reviewer", "Bo", "--approvals", alt, item); code != exitOK {
		t.Errorf("approve --approvals: %d", code)
	}
	if code, _, _ = runT("gate", "--approvals", alt, item); code != exitOK {
		t.Errorf("gate --approvals: %d", code)
	}
	os.WriteFile(log, []byte("{"), 0o644)
	if code, _, _ = runT("gate", item); code != exitUsage {
		t.Errorf("corrupt log: %d, want %d", code, exitUsage)
	}
	if code, _, _ = runT("approve", "--reviewer", "Cy", item); code != exitUsage {
		t.Errorf("approve onto corrupt log: %d, want %d", code, exitUsage)
	}
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

var tokenRE = regexp.MustCompile(`"token":"([0-9a-f]{32})"`)

// startReview runs `tarav serve --review` and returns its base URL, the
// page's token and version, and a channel with the exit code.
func startReview(t *testing.T, item string, extra ...string) (base, token, version string, stdout, stderr *syncBuf, exit chan int) {
	t.Helper()
	stdout, stderr, exit = &syncBuf{}, &syncBuf{}, make(chan int, 1)
	args := append([]string{"serve", "--review", "--addr", "127.0.0.1:0", "--reviewer", "Ada"}, extra...)
	go func() { exit <- run(append(args, item), stdout, stderr) }()
	urlRE := regexp.MustCompile(`(http://\S+/)`)
	for i := 0; i < 200 && base == ""; i++ {
		if m := urlRE.FindStringSubmatch(stderr.String()); m != nil {
			base = m[1]
		}
		time.Sleep(10 * time.Millisecond)
	}
	if base == "" {
		t.Fatalf("serve did not start: %s", stderr.String())
	}
	if stdout.String() != "" {
		t.Fatalf("review mode printed to stdout before deciding: %q", stdout.String())
	}
	resp, err := http.Get(base)
	if err != nil {
		t.Fatal(err)
	}
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	m := tokenRE.FindSubmatch(page)
	if m == nil {
		t.Fatal("no review token in the page")
	}
	resp, err = http.Get(base + "version")
	if err != nil {
		t.Fatal(err)
	}
	v, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return base, string(m[1]), string(v), stdout, stderr, exit
}

func decide(t *testing.T, url string, body map[string]string) int {
	t.Helper()
	b, _ := json.Marshal(body)
	resp, err := http.Post(url, "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func waitExit(t *testing.T, exit chan int) int {
	t.Helper()
	select {
	case c := <-exit:
		return c
	case <-time.After(5 * time.Second):
		t.Fatal("serve --review did not exit after the decision")
		return -1
	}
}

// The browser path of the pipeline: serve --review blocks until Approve,
// prints the record on stdout and exits 0; the gate then opens.
func TestServeReviewApprove(t *testing.T) {
	item := copyTo(t, "valid/minimal.json")
	base, token, version, stdout, stderr, exit := startReview(t, item, "--stage", "item-definition")
	if c := decide(t, base+"approve", map[string]string{"token": token, "version": version, "reviewer": "Ada"}); c != http.StatusOK {
		t.Fatalf("approve: %d", c)
	}
	if c := waitExit(t, exit); c != exitOK {
		t.Fatalf("exit %d\n%s", c, stderr.String())
	}
	var rec approval.Record
	if err := json.Unmarshal([]byte(stdout.String()), &rec); err != nil || !rec.Approved || rec.Reviewer != "Ada" {
		t.Fatalf("stdout must be exactly the record: %v %q", err, stdout.String())
	}
	if code, _, _ := runT("gate", item); code != exitOK {
		t.Errorf("gate after review approval: %d", code)
	}
}

func TestServeReviewReject(t *testing.T) {
	item := copyTo(t, "valid/minimal.json")
	base, token, _, stdout, _, exit := startReview(t, item)
	if c := decide(t, base+"reject", map[string]string{"token": token, "comment": "wrong zones"}); c != http.StatusOK {
		t.Fatalf("reject: %d", c)
	}
	if c := waitExit(t, exit); c != exitNotApproved {
		t.Fatalf("exit %d, want %d", c, exitNotApproved)
	}
	var d approval.Denial
	if err := json.Unmarshal([]byte(stdout.String()), &d); err != nil || d.Approved || d.Reason != "wrong zones" {
		t.Errorf("stdout: %v %q", err, stdout.String())
	}
	if code, _, _ := runT("gate", item); code != exitNotApproved {
		t.Errorf("gate after rejection: %d", code)
	}
}
