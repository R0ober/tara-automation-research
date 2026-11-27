package render

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func get(t *testing.T, srv *httptest.Server, path string) (int, string, http.Header) {
	t.Helper()
	resp, err := http.Get(srv.URL + path)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, string(b), resp.Header
}

func TestServe(t *testing.T) {
	dir := t.TempDir()
	item := filepath.Join(dir, "item.json")
	write := func(rel string) {
		if err := os.WriteFile(item, read(t, rel), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("valid/minimal.json")
	srv := httptest.NewServer(Handler(item, ServeOptions{}))
	defer srv.Close()

	code, body, hdr := get(t, srv, "/")
	if code != 200 || !strings.HasPrefix(body, "<!doctype html>") || hdr.Get("Cache-Control") != "no-store" {
		t.Fatalf("page: %d %q cache=%q", code, body[:min(len(body), 60)], hdr.Get("Cache-Control"))
	}
	if !strings.Contains(body, `"live":true`) {
		t.Error("served page is not in live mode")
	}
	_, v1, _ := get(t, srv, "/version")
	if !strings.Contains(body, `"version":"`+v1+`"`) {
		t.Errorf("page version does not match /version %q", v1)
	}

	// Editing the file changes the version; the page polls it and reloads.
	write("bbw/item-definition.json")
	if _, v2, _ := get(t, srv, "/version"); v2 == v1 || len(v2) != 16 {
		t.Errorf("version after edit = %q (before %q)", v2, v1)
	}

	// Schema errors: an error page that keeps polling.
	write("schema/wrong-type.json")
	code, body, _ = get(t, srv, "/")
	if code != http.StatusUnprocessableEntity || !strings.Contains(body, "/components/0/interfaces") || !strings.Contains(body, `fetch("version"`) {
		t.Errorf("schema error page: %d\n%s", code, body)
	}

	// Unreadable file: error page, distinct version.
	os.Remove(item)
	code, body, _ = get(t, srv, "/")
	if code != http.StatusInternalServerError || !strings.Contains(body, "no such file") {
		t.Errorf("missing file page: %d\n%s", code, body)
	}
	if _, v, _ := get(t, srv, "/version"); v != "unreadable" {
		t.Errorf("version for missing file = %q", v)
	}

	if code, _, _ := get(t, srv, "/other"); code != http.StatusNotFound {
		t.Errorf("/other = %d, want 404", code)
	}
}

func TestErrorPageEscapes(t *testing.T) {
	p := errorPage("<x>.json", `"</script>`, []string{"<b>bad</b>"})
	if strings.Contains(p, "<b>bad") || strings.Contains(p, "<x>") || strings.Contains(p, `"</script>`) {
		t.Errorf("unescaped input in error page:\n%s", p)
	}
}
