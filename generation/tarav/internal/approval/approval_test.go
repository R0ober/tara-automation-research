package approval

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestValid(t *testing.T) {
	for _, s := range []string{"item-definition", "attack-path-analysis", "s2"} {
		if err := ValidStage(s); err != nil {
			t.Errorf("%q: %v", s, err)
		}
	}
	for _, s := range []string{"", "Item", "-x", "a b", "a/b", strings.Repeat("a", 65)} {
		if ValidStage(s) == nil {
			t.Errorf("%q: want error", s)
		}
	}
	if n, err := ValidReviewer("  Ada  "); err != nil || n != "Ada" {
		t.Errorf("got %q %v", n, err)
	}
	for _, s := range []string{"", "  ", "a\nb", strings.Repeat("x", 201)} {
		if _, err := ValidReviewer(s); err == nil {
			t.Errorf("%q: want error", s)
		}
	}
}

func rec(stage, sha, who string, at int) Record {
	return Record{Approved: true, Stage: stage, SHA256: sha, Reviewer: who, ApprovedAt: time.Unix(int64(at), 0).UTC()}
}

func TestAppendFind(t *testing.T) {
	path := filepath.Join(t.TempDir(), "item.json.approvals.json")
	l, err := Read(path)
	if err != nil || len(l.Approvals) != 0 {
		t.Fatalf("missing log: %v %+v", err, l)
	}
	if r, why := l.Find("item-definition", "aa"); r != nil || !strings.Contains(why, "no approval") {
		t.Errorf("empty log: %v %q", r, why)
	}
	for _, r := range []Record{rec("item-definition", "aa", "Ada", 1), rec("item-definition", "bb", "Bo", 2), rec("attack-path-analysis", "cc", "Cy", 3)} {
		if err := Append(path, r); err != nil {
			t.Fatal(err)
		}
	}
	if l, err = Read(path); err != nil || len(l.Approvals) != 3 {
		t.Fatalf("read back: %v %d", err, len(l.Approvals))
	}
	if r, _ := l.Find("item-definition", "aa"); r == nil || r.Reviewer != "Ada" {
		t.Errorf("older approval of the same bytes still counts: %+v", r)
	}
	if r, why := l.Find("item-definition", "zz"); r != nil || !strings.Contains(why, "changed since Bo approved") {
		t.Errorf("stale: %v %q", r, why)
	}
	if r, _ := l.Find("attack-path-analysis", "aa"); r != nil {
		t.Error("an approval for one stage must not open another")
	}
	ents, _ := os.ReadDir(filepath.Dir(path))
	if len(ents) != 1 {
		t.Errorf("temporary files left behind: %v", ents)
	}
}

func TestReadRejectsUnknownFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a.json")
	os.WriteFile(path, []byte(`{"approvals":[],"extra":1}`), 0o644)
	if _, err := Read(path); err == nil {
		t.Error("want error")
	}
	os.WriteFile(path, []byte(`{}`), 0o644)
	if l, err := Read(path); err != nil || l.Approvals == nil {
		t.Errorf("empty object: %v %+v", err, l)
	}
}

func TestNotApprovedRecordIgnored(t *testing.T) {
	l := &Log{Approvals: []Record{{Stage: "s", SHA256: "aa"}}}
	if r, _ := l.Find("s", "aa"); r != nil {
		t.Error("a record with approved=false must not open the gate")
	}
}
