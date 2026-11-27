// Command tarav validates and lints TARA item-definition JSON.
//
//	tarav validate FILE...
//	tarav lint [--format text|json] FILE...
//	tarav render FILE -o OUT.html
//	tarav serve FILE [--addr HOST:PORT] [--open] [--review ...]
//	tarav check FILE [--policy P] [--format text|json]
//	tarav approve FILE --reviewer NAME [--stage S] [--policy P] [--approvals A]
//	tarav gate FILE [--stage S] [--approvals A]
//
// Exit codes (SPEC D5, D21): 0 clean or approved, 1 schema errors or
// blocking findings, 2 usage or I/O errors, 3 not approved (gate, review).
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"time"

	"tarav/internal/approval"
	"tarav/internal/check"
	"tarav/internal/lint"
	"tarav/internal/model"
	"tarav/internal/policy"
	"tarav/internal/render"
	"tarav/internal/schema"
)

const (
	exitOK          = 0
	exitFindings    = 1
	exitUsage       = 2
	exitNotApproved = 3
)

const defaultStage = "item-definition"

const usage = `usage:
  tarav validate FILE...                    check FILE against the item-definition schema
  tarav lint [--format text|json] FILE...   validate, then run lint rules
  tarav render FILE -o OUT.html             validate, lint, write the offline viewer page ("-o -" for stdout)
  tarav serve FILE [--addr HOST:PORT] [--open]
                                            serve the viewer locally; reloads when FILE changes

pipeline (JSON on stdout, messages on stderr):
  tarav check FILE [--policy P] [--format text|json]
                                            validate and lint under a policy; exit 0 passed, 1 failed
  tarav serve FILE --review [--stage S] [--reviewer NAME] [--policy P] [--approvals A]
                                            review page with Approve and Reject; exits 0 with the
                                            approval record, or 3 when rejected or interrupted
  tarav approve FILE --reviewer NAME [--stage S] [--comment C] [--policy P] [--approvals A]
                                            record an approval without the page (file must pass check)
  tarav gate FILE [--stage S] [--approvals A]
                                            exit 0 if this exact file content is approved for S, else 3

  --stage defaults to item-definition; --approvals defaults to FILE.approvals.json

exit codes: 0 clean or approved, 1 schema errors or blocking findings, 2 usage or I/O error,
            3 not approved
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return exitUsage
	}
	switch args[0] {
	case "validate":
		return runValidate(args[1:], stdout, stderr)
	case "lint":
		return runLint(args[1:], stdout, stderr)
	case "render":
		return runRender(args[1:], stdout, stderr)
	case "serve":
		return runServe(args[1:], stdout, stderr)
	case "check":
		return runCheck(args[1:], stdout, stderr)
	case "approve":
		return runApprove(args[1:], stdout, stderr)
	case "gate":
		return runGate(args[1:], stdout, stderr)
	case "-h", "-help", "--help", "help":
		fmt.Fprint(stdout, usage)
		return exitOK
	default:
		fmt.Fprintf(stderr, "tarav: unknown command %q\n\n%s", args[0], usage)
		return exitUsage
	}
}

func parse(fs *flag.FlagSet, args []string) ([]string, error) {
	var files []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		rest := fs.Args()
		if len(rest) == 0 {
			return files, nil
		}
		if rest[0] == "--" {
			return append(files, rest[1:]...), nil
		}
		files = append(files, rest[0])
		args = rest[1:]
	}
}

func newFlagSet(name string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, usage) }
	return fs
}

// validateFile validates one file, printing schema errors to errOut. ok is false
// on schema errors; err is non-nil only for I/O or internal failures (exit 2).
func validateFile(path string, errOut, stderr io.Writer) (data []byte, ok bool, err error) {
	data, err = os.ReadFile(path)
	if err != nil {
		return nil, false, err
	}
	res, err := schema.Validate(data)
	if err != nil {
		return nil, false, err
	}
	if res.Notice != "" {
		fmt.Fprintf(stderr, "%s: note: %s\n", path, res.Notice)
	}
	for _, e := range res.Errors {
		fmt.Fprintf(errOut, "%s: %s\n", path, e)
	}
	return data, res.OK(), nil
}

func runValidate(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("validate", stderr)
	files, err := parse(fs, args)
	if errors.Is(err, flag.ErrHelp) {
		return exitOK
	}
	if err != nil {
		return exitUsage
	}
	if len(files) == 0 {
		fmt.Fprintf(stderr, "tarav validate: no input file\n\n%s", usage)
		return exitUsage
	}
	code := exitOK
	for _, f := range files {
		_, ok, err := validateFile(f, stdout, stderr)
		if err != nil {
			fmt.Fprintf(stderr, "tarav validate: %v\n", err)
			return exitUsage
		}
		if !ok {
			code = exitFindings
		} else {
			fmt.Fprintf(stdout, "%s: valid\n", f)
		}
	}
	return code
}

func runLint(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("lint", stderr)
	format := fs.String("format", "text", "output format: text or json")
	files, err := parse(fs, args)
	if errors.Is(err, flag.ErrHelp) {
		return exitOK
	}
	if err != nil {
		return exitUsage
	}
	if *format != "text" && *format != "json" {
		fmt.Fprintf(stderr, "tarav lint: unknown --format %q (want text or json)\n", *format)
		return exitUsage
	}
	if len(files) == 0 {
		fmt.Fprintf(stderr, "tarav lint: no input file\n\n%s", usage)
		return exitUsage
	}
	// The finding shape has no file field (plan §7), so JSON output is for
	// one file at a time.
	if *format == "json" && len(files) != 1 {
		fmt.Fprintln(stderr, "tarav lint: --format json takes exactly one file")
		return exitUsage
	}
	// Keep stdout pure JSON: schema errors go to stderr in json mode.
	schemaOut := stdout
	if *format == "json" {
		schemaOut = stderr
	}
	code := exitOK
	for _, f := range files {
		// Lint validates the schema first; rules only run on valid input.
		data, ok, err := validateFile(f, schemaOut, stderr)
		if err != nil {
			fmt.Fprintf(stderr, "tarav lint: %v\n", err)
			return exitUsage
		}
		if !ok {
			code = exitFindings
			continue
		}
		it, err := model.Load(data)
		if err != nil {
			fmt.Fprintf(stderr, "tarav lint: %s: %v\n", f, err)
			return exitUsage
		}
		findings := lint.Run(it)
		if lint.HasErrors(findings) {
			code = exitFindings
		}
		if *format == "json" {
			if findings == nil {
				findings = []lint.Finding{} // "[]", not "null"
			}
			b, err := json.MarshalIndent(findings, "", "  ")
			if err != nil {
				fmt.Fprintf(stderr, "tarav lint: %v\n", err)
				return exitUsage
			}
			fmt.Fprintf(stdout, "%s\n", b)
			continue
		}
		for _, x := range findings {
			fmt.Fprintf(stdout, "%s:%s: %s %s [%s] %s\n", f, x.JSONPath, x.Severity, x.Rule, x.ElementID, x.Message)
		}
	}
	return code
}

func runRender(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("render", stderr)
	out := fs.String("o", "", "output HTML file (- for stdout)")
	files, err := parse(fs, args)
	if errors.Is(err, flag.ErrHelp) {
		return exitOK
	}
	if err != nil {
		return exitUsage
	}
	if len(files) != 1 || *out == "" {
		fmt.Fprintf(stderr, "tarav render: want exactly one input file and -o OUT.html\n\n%s", usage)
		return exitUsage
	}
	in := files[0]
	raw, err := os.ReadFile(in)
	if err != nil {
		fmt.Fprintf(stderr, "tarav render: %v\n", err)
		return exitUsage
	}
	res, err := render.Render(raw, render.Options{})
	if err != nil {
		fmt.Fprintf(stderr, "tarav render: %s: %v\n", in, err)
		return exitUsage
	}
	if res.Schema.Notice != "" {
		fmt.Fprintf(stderr, "%s: note: %s\n", in, res.Schema.Notice)
	}
	if !res.Schema.OK() {
		for _, e := range res.Schema.Errors {
			fmt.Fprintf(stderr, "%s: %s\n", in, e)
		}
		fmt.Fprintf(stderr, "tarav render: %s: schema errors, no page written\n", in)
		return exitFindings
	}
	if *out == "-" {
		_, err = stdout.Write(res.HTML)
	} else {
		err = os.WriteFile(*out, res.HTML, 0o644)
	}
	if err != nil {
		fmt.Fprintf(stderr, "tarav render: %v\n", err)
		return exitUsage
	}
	counts := map[lint.Severity]int{}
	for _, f := range res.Findings {
		counts[f.Severity]++
	}
	dest := *out
	if dest == "-" {
		dest = "stdout"
	}
	fmt.Fprintf(stderr, "%s: wrote %s (%s, %s, %d info)\n", in, dest,
		plural(counts[lint.Error], "error"), plural(counts[lint.Warning], "warning"), counts[lint.Info])
	if lint.HasErrors(res.Findings) {
		return exitFindings
	}
	return exitOK
}

func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return fmt.Sprintf("%d %ss", n, word)
}

func runServe(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("serve", stderr)
	addr := fs.String("addr", "127.0.0.1:8000", "listen address")
	open := fs.Bool("open", false, "open the page in the default browser")
	review := fs.Bool("review", false, "review mode: Approve and Reject on the page; exit with the decision")
	stage := fs.String("stage", defaultStage, "pipeline stage being reviewed (--review)")
	reviewer := fs.String("reviewer", "", "reviewer name to pre-fill (--review)")
	polPath := fs.String("policy", "", "policy file (default: fail on error findings)")
	approvals := fs.String("approvals", "", "approvals log (default FILE.approvals.json)")
	files, err := parse(fs, args)
	if errors.Is(err, flag.ErrHelp) {
		return exitOK
	}
	if err != nil {
		return exitUsage
	}
	if len(files) != 1 {
		fmt.Fprintf(stderr, "tarav serve: want exactly one input file\n\n%s", usage)
		return exitUsage
	}
	file := files[0]
	if _, err := os.Stat(file); err != nil {
		fmt.Fprintf(stderr, "tarav serve: %v\n", err)
		return exitUsage
	}
	pol, err := loadPolicy(*polPath)
	if err != nil {
		fmt.Fprintf(stderr, "tarav serve: %v\n", err)
		return exitUsage
	}
	opts := render.ServeOptions{Policy: pol}
	if *review {
		if err := approval.ValidStage(*stage); err != nil {
			fmt.Fprintf(stderr, "tarav serve: %v\n", err)
			return exitUsage
		}
		if opts.Review, err = render.NewReview(*stage, *reviewer, approvalsPath(*approvals, file)); err != nil {
			fmt.Fprintf(stderr, "tarav serve: %v\n", err)
			return exitUsage
		}
	} else if setFlag(fs, "stage", "reviewer", "approvals") {
		fmt.Fprintln(stderr, "tarav serve: --stage, --reviewer and --approvals need --review")
		return exitUsage
	}
	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		fmt.Fprintf(stderr, "tarav serve: %v\n", err)
		return exitUsage
	}
	url := "http://" + ln.Addr().String() + "/"
	// In review mode stdout carries only the outcome JSON.
	if *review {
		display := file
		if cwd, err := os.Getwd(); err == nil {
			display = strings.TrimPrefix(file, cwd+string(os.PathSeparator))
		}
		fmt.Fprintf(stderr, "Reviewing  %s\n           %s\n\n", display, url)
	} else {
		fmt.Fprintf(stdout, "serving %s at %s (Ctrl-C to stop)\n", file, url)
	}
	if *open {
		if err := openBrowser(url); err != nil {
			fmt.Fprintf(stderr, "tarav serve: could not open a browser: %v\n", err)
		}
	}
	srv := &http.Server{Handler: render.Handler(file, opts), ReadHeaderTimeout: 10 * time.Second}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	var done chan render.Outcome
	if opts.Review != nil {
		done = opts.Review.Done
	}
	var outcome *render.Outcome
	served := make(chan error, 1)
	go func() { served <- srv.Serve(ln) }()
	select {
	case <-ctx.Done():
	case o := <-done:
		outcome = &o
	case err := <-served:
		fmt.Fprintf(stderr, "tarav serve: %v\n", err)
		return exitUsage
	}
	shut, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	srv.Shutdown(shut)
	if opts.Review == nil {
		return exitOK
	}
	if outcome == nil {
		raw, _ := os.ReadFile(file)
		d := approval.Denial{Stage: *stage, File: file, Reason: "review interrupted before a decision"}
		if raw != nil {
			d.SHA256 = check.Hash(raw)
		}
		fmt.Fprintln(stderr, "Review interrupted.")
		return printJSON(stdout, stderr, d, exitNotApproved)
	}
	if outcome.Record != nil {
		fmt.Fprintf(stderr, "Approved by %s\n", outcome.Record.Reviewer)
		return printJSON(stdout, stderr, outcome.Record, exitOK)
	}
	fmt.Fprintf(stderr, "Review rejected.\nReason: %s\n", outcome.Denial.Reason)
	return printJSON(stdout, stderr, outcome.Denial, exitNotApproved)
}

func runCheck(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("check", stderr)
	format := fs.String("format", "text", "output format: text or json")
	polPath := fs.String("policy", "", "policy file (default: fail on error findings)")
	files, err := parse(fs, args)
	if errors.Is(err, flag.ErrHelp) {
		return exitOK
	}
	if err != nil {
		return exitUsage
	}
	if *format != "text" && *format != "json" {
		fmt.Fprintf(stderr, "tarav check: unknown --format %q (want text or json)\n", *format)
		return exitUsage
	}
	if len(files) != 1 {
		fmt.Fprintf(stderr, "tarav check: want exactly one input file\n\n%s", usage)
		return exitUsage
	}
	rep, code := checkFile("check", files[0], *polPath, stderr)
	if rep == nil {
		return code
	}
	if *format == "json" {
		return printJSON(stdout, stderr, rep, code)
	}
	printReport(stdout, rep)
	return code
}

// checkFile loads the policy and checks file. rep is nil on usage or I/O
// errors; code is the D21 exit code otherwise.
func checkFile(cmd, file, polPath string, stderr io.Writer) (rep *check.Report, code int) {
	pol, err := loadPolicy(polPath)
	if err != nil {
		fmt.Fprintf(stderr, "tarav %s: %v\n", cmd, err)
		return nil, exitUsage
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		fmt.Fprintf(stderr, "tarav %s: %v\n", cmd, err)
		return nil, exitUsage
	}
	rep, err = check.Run(raw, pol)
	if err != nil {
		fmt.Fprintf(stderr, "tarav %s: %s: %v\n", cmd, file, err)
		return nil, exitUsage
	}
	rep.File = file
	if rep.Notice != "" {
		fmt.Fprintf(stderr, "%s: note: %s\n", file, rep.Notice)
	}
	if !rep.Passed {
		return rep, exitFindings
	}
	return rep, exitOK
}

func printReport(w io.Writer, rep *check.Report) {
	for _, e := range rep.SchemaErrors {
		fmt.Fprintf(w, "%s: %s\n", rep.File, e)
	}
	for _, x := range rep.Findings {
		fmt.Fprintf(w, "%s:%s: %s %s [%s] %s\n", rep.File, x.JSONPath, x.Severity, x.Rule, x.ElementID, x.Message)
	}
	verdict := "passed"
	switch {
	case len(rep.SchemaErrors) > 0:
		verdict = fmt.Sprintf("FAILED (%s)", plural(len(rep.SchemaErrors), "schema error"))
	case !rep.Passed:
		verdict = fmt.Sprintf("FAILED (%s at or above %s)", plural(rep.Blocking, "blocking finding"), rep.FailOn)
	}
	fmt.Fprintf(w, "%s: %s; %s, %s, %d info\n", rep.File, verdict,
		plural(rep.Counts.Error, "error"), plural(rep.Counts.Warning, "warning"), rep.Counts.Info)
}

func runApprove(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("approve", stderr)
	stage := fs.String("stage", defaultStage, "pipeline stage being approved")
	reviewer := fs.String("reviewer", "", "reviewer name (required)")
	comment := fs.String("comment", "", "optional comment stored with the approval")
	polPath := fs.String("policy", "", "policy file (default: fail on error findings)")
	approvals := fs.String("approvals", "", "approvals log (default FILE.approvals.json)")
	files, err := parse(fs, args)
	if errors.Is(err, flag.ErrHelp) {
		return exitOK
	}
	if err != nil {
		return exitUsage
	}
	if len(files) != 1 {
		fmt.Fprintf(stderr, "tarav approve: want exactly one input file\n\n%s", usage)
		return exitUsage
	}
	if err := approval.ValidStage(*stage); err != nil {
		fmt.Fprintf(stderr, "tarav approve: %v\n", err)
		return exitUsage
	}
	name, err := approval.ValidReviewer(*reviewer)
	if err != nil {
		fmt.Fprintf(stderr, "tarav approve: --reviewer: %v\n", err)
		return exitUsage
	}
	file := files[0]
	rep, code := checkFile("approve", file, *polPath, stderr)
	if rep == nil {
		return code
	}
	if code != exitOK {
		printReport(stderr, rep)
		fmt.Fprintf(stderr, "tarav approve: %s does not pass the checks; nothing recorded\n", file)
		return code
	}
	rec := approval.Record{
		Approved: true, Stage: *stage, File: file, SHA256: rep.SHA256,
		Reviewer: name, ApprovedAt: now().UTC().Truncate(time.Second), Comment: *comment,
		Tarav: render.Version, PolicySHA256: rep.PolicySHA256,
		Findings: approval.Counts{Error: rep.Counts.Error, Warning: rep.Counts.Warning, Info: rep.Counts.Info},
	}
	if err := approval.Append(approvalsPath(*approvals, file), rec); err != nil {
		fmt.Fprintf(stderr, "tarav approve: %v\n", err)
		return exitUsage
	}
	fmt.Fprintf(stderr, "%s: approved for %s by %s\n", file, rec.Stage, rec.Reviewer)
	return printJSON(stdout, stderr, rec, exitOK)
}

// runGate is the pipeline's signal to start the next step (D25): exit 0
// only if the file's current bytes carry an approval for the stage.
func runGate(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("gate", stderr)
	stage := fs.String("stage", defaultStage, "pipeline stage to check")
	approvals := fs.String("approvals", "", "approvals log (default FILE.approvals.json)")
	files, err := parse(fs, args)
	if errors.Is(err, flag.ErrHelp) {
		return exitOK
	}
	if err != nil {
		return exitUsage
	}
	if len(files) != 1 {
		fmt.Fprintf(stderr, "tarav gate: want exactly one input file\n\n%s", usage)
		return exitUsage
	}
	if err := approval.ValidStage(*stage); err != nil {
		fmt.Fprintf(stderr, "tarav gate: %v\n", err)
		return exitUsage
	}
	file := files[0]
	raw, err := os.ReadFile(file)
	if err != nil {
		fmt.Fprintf(stderr, "tarav gate: %v\n", err)
		return exitUsage
	}
	log, err := approval.Read(approvalsPath(*approvals, file))
	if err != nil {
		fmt.Fprintf(stderr, "tarav gate: %v\n", err)
		return exitUsage
	}
	sha := check.Hash(raw)
	rec, reason := log.Find(*stage, sha)
	if rec == nil {
		fmt.Fprintf(stderr, "%s: gate closed for %s: %s\n", file, *stage, reason)
		return printJSON(stdout, stderr, approval.Denial{Stage: *stage, File: file, SHA256: sha, Reason: reason}, exitNotApproved)
	}
	fmt.Fprintf(stderr, "%s: gate open for %s (approved by %s)\n", file, *stage, rec.Reviewer)
	return printJSON(stdout, stderr, rec, exitOK)
}

// now is the clock for approve; tests replace it.
var now = time.Now

func loadPolicy(path string) (*policy.Policy, error) {
	if path == "" {
		return policy.Default(), nil
	}
	return policy.Load(path)
}

func approvalsPath(flagVal, file string) string {
	if flagVal != "" {
		return flagVal
	}
	return approval.DefaultPath(file)
}

// setFlag reports whether any of the named flags was given.
func setFlag(fs *flag.FlagSet, names ...string) bool {
	set := false
	fs.Visit(func(f *flag.Flag) {
		for _, n := range names {
			if f.Name == n {
				set = true
			}
		}
	})
	return set
}

// printJSON writes v as indented JSON and returns code, or exitUsage if
// encoding fails.
func printJSON(stdout, stderr io.Writer, v any, code int) int {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		fmt.Fprintf(stderr, "tarav: %v\n", err)
		return exitUsage
	}
	fmt.Fprintf(stdout, "%s\n", b)
	return code
}

func openBrowser(url string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	return cmd.Start()
}
