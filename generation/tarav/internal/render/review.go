package render

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"io"
	"mime"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"tarav/internal/approval"
	"tarav/internal/check"
	"tarav/internal/policy"
)

// Review is the state of one `tarav serve --review` run (SPEC D24). The
// first approve or reject decides it; the outcome is sent once on Done,
// which the caller uses as the pipeline's gate signal.
type Review struct {
	Stage     string
	Reviewer  string // pre-filled reviewer name; the page may change it
	Approvals string // approvals log path
	Token     string // per-run secret the page must send back
	Done      chan Outcome
	// Now is the clock for approved_at; nil means time.Now.
	Now func() time.Time

	mu      sync.Mutex
	decided bool
}

// Outcome is exactly one of Record (approved) or Denial (rejected).
type Outcome struct {
	Record *approval.Record
	Denial *approval.Denial
}

// NewReview prepares a review with a fresh random token.
func NewReview(stage, reviewer, approvals string) (*Review, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return &Review{
		Stage: stage, Reviewer: reviewer, Approvals: approvals,
		Token: hex.EncodeToString(b), Done: make(chan Outcome, 1),
	}, nil
}

type decision struct {
	Token    string `json:"token"`
	Version  string `json:"version"`
	Reviewer string `json:"reviewer"`
	Comment  string `json:"comment"`
}

// readDecision enforces the request rules shared by approve and reject:
// POST, a JSON body (so a cross-site form cannot send it without a CORS
// preflight, which this server never grants) and the run's token.
func (rv *Review) readDecision(w http.ResponseWriter, r *http.Request) (*decision, bool) {
	noStore(w)
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		replyErr(w, http.StatusMethodNotAllowed, "use POST")
		return nil, false
	}
	if mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type")); mt != "application/json" {
		replyErr(w, http.StatusUnsupportedMediaType, "want application/json")
		return nil, false
	}
	if o := r.Header.Get("Origin"); o != "" && o != "http://"+r.Host {
		replyErr(w, http.StatusForbidden, "cross-origin request")
		return nil, false
	}
	var d decision
	dec := json.NewDecoder(io.LimitReader(r.Body, 64<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&d); err != nil {
		replyErr(w, http.StatusBadRequest, "bad request body: "+err.Error())
		return nil, false
	}
	if subtle.ConstantTimeCompare([]byte(d.Token), []byte(rv.Token)) != 1 {
		replyErr(w, http.StatusForbidden, "wrong review token; reload the page")
		return nil, false
	}
	if len(d.Comment) > 2000 {
		replyErr(w, http.StatusBadRequest, "comment is longer than 2000 bytes")
		return nil, false
	}
	return &d, true
}

// approve re-checks the file as it is now and, if it still passes and is
// the version the reviewer was looking at, appends the record and ends
// the review. The hash is taken from the bytes that were checked.
func (rv *Review) approve(path string, pol *policy.Policy) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		d, ok := rv.readDecision(w, r)
		if !ok {
			return
		}
		name, err := approval.ValidReviewer(d.Reviewer)
		if err != nil {
			replyErr(w, http.StatusBadRequest, err.Error())
			return
		}
		rv.mu.Lock()
		defer rv.mu.Unlock()
		if rv.decided {
			replyErr(w, http.StatusGone, "this review is already decided")
			return
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			replyErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		if versionOf(raw, nil) != d.Version {
			replyErr(w, http.StatusConflict, "the file changed since this page loaded; review the new version")
			return
		}
		rep, err := check.Run(raw, pol)
		if err != nil {
			replyErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		if !rep.Passed || len(rep.SchemaErrors) > 0 {
			replyErr(w, http.StatusUnprocessableEntity, "the file does not pass the checks; it cannot be approved")
			return
		}
		now := time.Now
		if rv.Now != nil {
			now = rv.Now
		}
		rec := approval.Record{
			Approved: true, Stage: rv.Stage, File: path, SHA256: rep.SHA256,
			Reviewer: name, ApprovedAt: now().UTC().Truncate(time.Second), Comment: d.Comment,
			Tarav: Version, PolicySHA256: rep.PolicySHA256,
			Findings: approval.Counts{Error: rep.Counts.Error, Warning: rep.Counts.Warning, Info: rep.Counts.Info},
		}
		if err := approval.Append(rv.Approvals, rec); err != nil {
			replyErr(w, http.StatusInternalServerError, "could not record the approval: "+err.Error())
			return
		}
		rv.decided = true
		reply(w, http.StatusOK, rec)
		rv.send(Outcome{Record: &rec})
	}
}

// reject ends the review without an approval; nothing is written.
func (rv *Review) reject(path string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		d, ok := rv.readDecision(w, r)
		if !ok {
			return
		}
		rv.mu.Lock()
		defer rv.mu.Unlock()
		if rv.decided {
			replyErr(w, http.StatusGone, "this review is already decided")
			return
		}
		reason := strings.TrimSpace(d.Comment)
		if reason == "" {
			reason = "rejected by the reviewer"
		}
		den := approval.Denial{Stage: rv.Stage, File: path, Reason: reason, Reviewer: strings.TrimSpace(d.Reviewer)}
		if raw, err := os.ReadFile(path); err == nil {
			den.SHA256 = check.Hash(raw)
		}
		rv.decided = true
		reply(w, http.StatusOK, den)
		rv.send(Outcome{Denial: &den})
	}
}

// send delivers the outcome without ever blocking a handler; decided
// guarantees there is only one, and Done has room for it.
func (rv *Review) send(o Outcome) {
	select {
	case rv.Done <- o:
	default:
	}
}

func reply(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func replyErr(w http.ResponseWriter, code int, msg string) {
	reply(w, code, map[string]string{"error": msg})
}

// localOnly refuses requests whose Host is a DNS name other than
// localhost. A review page holds a token that can approve; this stops a
// DNS-rebinding page on some other site from loading it.
func localOnly(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if hh, _, err := net.SplitHostPort(host); err == nil {
			host = hh
		}
		host = strings.Trim(host, "[]")
		if net.ParseIP(host) == nil && !strings.EqualFold(host, "localhost") {
			http.Error(w, "tarav review: open this page by IP address or localhost", http.StatusMisdirectedRequest)
			return
		}
		h.ServeHTTP(w, r)
	})
}
