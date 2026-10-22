package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/0x4272616E646F6E/decision-waf/internal/classifier"
	"github.com/0x4272616E646F6E/decision-waf/internal/classifier/fake"
	"github.com/0x4272616E646F6E/decision-waf/internal/config"
	"github.com/0x4272616E646F6E/decision-waf/internal/eval/results"
	"github.com/0x4272616E646F6E/decision-waf/internal/inspect"
	"github.com/0x4272616E646F6E/decision-waf/internal/policy"
)

const tiny = `{"decision_waf_eval_dataset":1,"name":"tiny"}
{"id":"b1","label":"benign","method":"GET","path":"/home"}
{"id":"b2","label":"benign","method":"GET","path":"/about"}
{"id":"a1","label":"sqli","method":"GET","path":"/evil"}
`

func env(model string) map[string]string {
	return map[string]string{"DECISION_WAF_CLASSIFIER_BACKEND": "jev", "DECISION_WAF_CLASSIFIER_MODEL": model}
}

func keyword() *fake.Classifier {
	return fake.New(func(_ context.Context, r *inspect.Request, _ []policy.Category) (classifier.Verdict, error) {
		if strings.Contains(r.Path, "evil") {
			return classifier.Verdict{Benign: 0.1, Category: "sqli", Confidence: 0.9}, nil
		}
		return classifier.Verdict{Benign: 0.95}, nil
	})
}

type harness struct {
	cli            cli
	stdout, stderr *bytes.Buffer
}

func newCLI(vars map[string]string, cls classifier.Classifier, probeErr error) *harness {
	h := &harness{stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{}}
	h.cli = cli{
		stdout: h.stdout, stderr: h.stderr,
		lookup:   func(k string) (string, bool) { v, ok := vars[k]; return v, ok },
		readFile: os.ReadFile,
		backend: func(config.Config, *slog.Logger) (classifier.Classifier, func(context.Context) error, error) {
			return cls, func(context.Context) error { return probeErr }, nil
		},
		now: func() time.Time { return time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC) },
	}
	return h
}

func (h *harness) main(args ...string) int { return h.cli.main(context.Background(), args) }

func writeFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func runTiny(t *testing.T, model string, cls classifier.Classifier, extra ...string) (string, string) {
	t.Helper()
	ds := writeFile(t, "tiny.jsonl", tiny)
	out := filepath.Join(t.TempDir(), "r.jsonl")
	h := newCLI(env(model), cls, nil)
	if code := h.main(append([]string{"run", "--dataset", ds, "--out", out}, extra...)...); code != 0 {
		t.Fatalf("run exit %d: %s", code, h.stderr)
	}
	return ds, out
}

func TestRunThenReport(t *testing.T) {
	_, out := runTiny(t, "fake-model", keyword())
	f, err := results.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Results) != 3 || f.Header.Model != "fake-model" || f.Header.Threshold != 0.8 || f.Header.Dataset.Name != "tiny" || f.Header.DecisionWafVersion != "dev" {
		t.Errorf("results %+v", f)
	}
	h := newCLI(nil, nil, nil)
	if code := h.main("report", out, "--json"); code != 0 {
		t.Fatalf("report exit %d: %s", code, h.stderr)
	}
	var got struct {
		Summary struct {
			Detection struct{ TP, FP int }
		}
	}
	if err := json.Unmarshal(h.stdout.Bytes(), &got); err != nil {
		t.Fatalf("report --json is not JSON (was the flag ignored?): %v\n%s", err, h.stdout)
	}
	if got.Summary.Detection.TP != 1 || got.Summary.Detection.FP != 0 {
		t.Errorf("detection = %+v", got.Summary.Detection)
	}
	h = newCLI(nil, nil, nil)
	if code := h.main("report", "--markdown", out); code != 0 || !strings.Contains(h.stdout.String(), "# decision-waf-eval report") {
		t.Errorf("markdown exit %d: %s", code, h.stdout)
	}
}

func TestRunPrintsResultsPath(t *testing.T) {
	ds := writeFile(t, "tiny.jsonl", tiny)
	out := filepath.Join(t.TempDir(), "r.jsonl")
	h := newCLI(env("m"), keyword(), nil)
	if code := h.main("run", "--dataset", ds, "--out", out); code != 0 || strings.TrimSpace(h.stdout.String()) != out {
		t.Errorf("exit %d stdout %q", code, h.stdout)
	}
}

func TestRunRefusesToOverwrite(t *testing.T) {
	ds, out := runTiny(t, "m", keyword())
	h := newCLI(env("m"), keyword(), nil)
	if code := h.main("run", "--dataset", ds, "--out", out); code != 2 || !strings.Contains(h.stderr.String(), "--resume") {
		t.Errorf("exit %d: %s", code, h.stderr)
	}
}

func TestResumeContinuesAfterPartialLine(t *testing.T) {
	ds, out := runTiny(t, "m", keyword())
	data, _ := os.ReadFile(out)
	lines := strings.SplitAfter(string(data), "\n")
	if err := os.WriteFile(out, []byte(lines[0]+lines[1]+`{"id":"b2","lab`), 0o644); err != nil {
		t.Fatal(err)
	}
	cls := keyword()
	h := newCLI(env("m"), cls, nil)
	if code := h.main("run", "--dataset", ds, "--out", out, "--resume"); code != 0 {
		t.Fatalf("resume exit %d: %s", code, h.stderr)
	}
	f, err := results.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Results) != 3 || cls.Calls() != 2 {
		t.Errorf("results %d, classifier calls %d; want 3 and 2", len(f.Results), cls.Calls())
	}
}

func TestResumeRefusesDifferentRun(t *testing.T) {
	for name, vars := range map[string]map[string]string{
		"model":    env("other-model"),
		"timeout":  {"DECISION_WAF_CLASSIFIER_BACKEND": "jev", "DECISION_WAF_CLASSIFIER_MODEL": "m", "DECISION_WAF_CLASSIFIER_TIMEOUT": "60s"},
		"base URL": {"DECISION_WAF_CLASSIFIER_BACKEND": "jev", "DECISION_WAF_CLASSIFIER_MODEL": "m", "DECISION_WAF_CLASSIFIER_BASE_URL": "http://other:1234"},
	} {
		ds, out := runTiny(t, "m", keyword())
		h := newCLI(vars, keyword(), nil)
		if code := h.main("run", "--dataset", ds, "--out", out, "--resume"); code != 2 || !strings.Contains(h.stderr.String(), "different run") {
			t.Errorf("%s: exit %d: %s", name, code, h.stderr)
		}
	}
}

func TestBaseURLRecordedWithoutCredentials(t *testing.T) {
	ds := writeFile(t, "tiny.jsonl", tiny)
	out := filepath.Join(t.TempDir(), "r.jsonl")
	vars := env("m")
	vars["DECISION_WAF_CLASSIFIER_BASE_URL"] = "http://user:secret@models.internal:1234/v1"
	if code := newCLI(vars, keyword(), nil).main("run", "--dataset", ds, "--out", out); code != 0 {
		t.Fatal("run failed")
	}
	f, err := results.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if f.Header.BaseURL != "http://models.internal:1234/v1" || f.Header.TimeoutMS != 1000 {
		t.Errorf("header base URL %q, timeout %d ms", f.Header.BaseURL, f.Header.TimeoutMS)
	}
}

func TestUsageErrors(t *testing.T) {
	ds := writeFile(t, "tiny.jsonl", tiny)
	_, out := runTiny(t, "m", keyword())
	for _, args := range [][]string{
		{},
		{"bogus"},
		{"run"},
		{"run", "--dataset", ds, "extra"},
		{"run", "--dataset", ds, "--concurrency", "0"},
		{"run", "--dataset", ds, "--sample", "-1"},
		{"report"},
		{"report", out, "--json", "--markdown"},
		{"report", out, "--threshold", "1.5"},
		{"report", out, "--max-fpr", "-0.1"},
		{"compare", out},
	} {
		h := newCLI(env("m"), keyword(), nil)
		if code := h.main(args...); code != 2 || !strings.Contains(h.stderr.String(), "usage:") {
			t.Errorf("%q: exit %d, stderr %s", args, code, h.stderr)
		}
	}
}

func TestInvalidInputs(t *testing.T) {
	bad := writeFile(t, "bad.jsonl", `{"decision_waf_eval_dataset":1}`+"\n"+`{"id":"x","label":"nope","method":"GET","path":"/"}`+"\n")
	ds := writeFile(t, "tiny.jsonl", tiny)
	cases := []struct {
		name string
		vars map[string]string
		args []string
		want string
	}{
		{"bad dataset", env("m"), []string{"run", "--dataset", bad}, "line 2"},
		{"missing dataset", env("m"), []string{"run", "--dataset", ds + ".missing"}, "no such file"},
		{"no backend", map[string]string{}, []string{"run", "--dataset", ds}, "DECISION_WAF_CLASSIFIER_BACKEND"},
		{"not results", env("m"), []string{"report", ds}, "header"},
	}
	for _, c := range cases {
		h := newCLI(c.vars, keyword(), nil)
		if code := h.main(c.args...); code != 2 || !strings.Contains(h.stderr.String(), c.want) {
			t.Errorf("%s: exit %d, stderr %s", c.name, code, h.stderr)
		}
	}
}

func TestProbeFailureWritesNothing(t *testing.T) {
	ds := writeFile(t, "tiny.jsonl", tiny)
	out := filepath.Join(t.TempDir(), "r.jsonl")
	h := newCLI(env("m"), keyword(), errors.New("connection refused"))
	if code := h.main("run", "--dataset", ds, "--out", out); code != 1 || !strings.Contains(h.stderr.String(), "connection refused") {
		t.Errorf("exit %d: %s", code, h.stderr)
	}
	if _, err := os.Stat(out); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("results file created despite the probe failing: %v", err)
	}
}

func TestCompare(t *testing.T) {
	_, a := runTiny(t, "model-a", keyword())
	_, b := runTiny(t, "model-b", keyword())
	h := newCLI(nil, nil, nil)
	if code := h.main("compare", a, b); code != 0 || !strings.Contains(h.stdout.String(), "model-a") || !strings.Contains(h.stdout.String(), "model-b") {
		t.Errorf("exit %d: %s %s", code, h.stdout, h.stderr)
	}
	other := writeFile(t, "other.jsonl", strings.Replace(tiny, `"/about"`, `"/contact"`, 1))
	c := filepath.Join(t.TempDir(), "c.jsonl")
	if code := newCLI(env("m"), keyword(), nil).main("run", "--dataset", other, "--out", c); code != 0 {
		t.Fatal("run on other dataset failed")
	}
	h = newCLI(nil, nil, nil)
	if code := h.main("compare", a, c); code != 2 || !strings.Contains(h.stderr.String(), "--allow-different-datasets") {
		t.Errorf("different datasets: exit %d: %s", code, h.stderr)
	}
	if code := newCLI(nil, nil, nil).main("compare", a, c, "--allow-different-datasets"); code != 0 {
		t.Errorf("allowed comparison: exit %d", code)
	}
}

func TestSampleRecordedInHeader(t *testing.T) {
	_, out := runTiny(t, "m", keyword(), "--sample", "2", "--seed", "7")
	f, err := results.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Results) != 2 || f.Header.Sample != 2 || f.Header.Seed != 7 {
		t.Errorf("header %+v with %d results", f.Header, len(f.Results))
	}
}

func TestDefaultOut(t *testing.T) {
	if got, want := defaultOut("eval/datasets/sample.jsonl", "liquid/d1-3b"), filepath.Join("bin", "eval", "sample-liquid_d1-3b.jsonl"); got != want {
		t.Errorf("defaultOut = %q, want %q", got, want)
	}
}

func TestInterruptedNamesResultsPath(t *testing.T) {
	ds := writeFile(t, "tiny.jsonl", tiny)
	out := filepath.Join(t.TempDir(), "r.jsonl")
	ctx, cancel := context.WithCancel(context.Background())
	cls := fake.New(func(context.Context, *inspect.Request, []policy.Category) (classifier.Verdict, error) {
		cancel()
		return classifier.Verdict{Benign: 0.95}, nil
	})
	h := newCLI(env("m"), cls, nil)
	code := h.cli.main(ctx, []string{"run", "--dataset", ds, "--out", out})
	if code != 1 || !strings.Contains(h.stderr.String(), "interrupted; rerun with --resume --out "+out+" to continue") {
		t.Errorf("exit %d: %s", code, h.stderr)
	}
}

func TestRunReportsErrors(t *testing.T) {
	ds := writeFile(t, "tiny.jsonl", tiny)
	out := filepath.Join(t.TempDir(), "r.jsonl")
	cls := fake.New(func(_ context.Context, r *inspect.Request, _ []policy.Category) (classifier.Verdict, error) {
		if strings.Contains(r.Path, "evil") || strings.Contains(r.Path, "about") {
			return classifier.Verdict{}, context.DeadlineExceeded
		}
		return classifier.Verdict{Benign: 0.95}, nil
	})
	h := newCLI(env("m"), cls, nil)
	if code := h.main("run", "--dataset", ds, "--out", out); code != 0 {
		t.Fatalf("exit %d: %s", code, h.stderr)
	}
	if !strings.Contains(h.stderr.String(), "2 of 3 requests failed (timeout 2); see decision-waf-eval report") {
		t.Errorf("stderr lacks the error summary:\n%s", h.stderr)
	}
}

func TestRunWithoutErrorsStaysQuiet(t *testing.T) {
	ds := writeFile(t, "tiny.jsonl", tiny)
	h := newCLI(env("m"), keyword(), nil)
	if code := h.main("run", "--dataset", ds, "--out", filepath.Join(t.TempDir(), "r.jsonl")); code != 0 || strings.Contains(h.stderr.String(), "failed") {
		t.Errorf("exit %d: %s", code, h.stderr)
	}
}

func TestResumeRefusesChangedPolicyContent(t *testing.T) {
	pol := writeFile(t, "policy.yaml", "categories: [{name: sqli}]")
	vars := env("m")
	vars["DECISION_WAF_POLICY_FILE"] = pol
	ds := writeFile(t, "tiny.jsonl", tiny)
	out := filepath.Join(t.TempDir(), "r.jsonl")
	h := newCLI(vars, keyword(), nil)
	if code := h.main("run", "--dataset", ds, "--out", out); code != 0 {
		t.Fatalf("run exit %d: %s", code, h.stderr)
	}
	f, err := results.ReadFile(out)
	if err != nil || len(f.Header.PolicySHA256) != 64 {
		t.Fatalf("policy hash %q err %v", f.Header.PolicySHA256, err)
	}
	h = newCLI(vars, keyword(), nil)
	if code := h.main("run", "--dataset", ds, "--out", out, "--resume"); code != 0 {
		t.Fatalf("unchanged policy: resume exit %d: %s", code, h.stderr)
	}
	if err := os.WriteFile(pol, []byte("categories: [{name: sqli}, {name: xss}]"), 0o644); err != nil {
		t.Fatal(err)
	}
	h = newCLI(vars, keyword(), nil)
	if code := h.main("run", "--dataset", ds, "--out", out, "--resume"); code != 2 || !strings.Contains(h.stderr.String(), "different run") {
		t.Errorf("exit %d: %s", code, h.stderr)
	}
}

func TestNotReadyErrorHidesCredentials(t *testing.T) {
	ds := writeFile(t, "tiny.jsonl", tiny)
	vars := env("m")
	vars["DECISION_WAF_CLASSIFIER_BASE_URL"] = "http://user:secret@models.internal:1234/v1"
	h := newCLI(vars, keyword(), errors.New("down"))
	if code := h.main("run", "--dataset", ds, "--out", filepath.Join(t.TempDir(), "r.jsonl")); code == 0 || strings.Contains(h.stderr.String(), "secret") {
		t.Errorf("exit %d, stderr %q; want a failure without the password", code, h.stderr)
	}
}

func TestPolicyReadOnce(t *testing.T) {
	ds := writeFile(t, "tiny.jsonl", tiny)
	pf := writeFile(t, "policy.yaml", "not: [valid")
	good := []byte("routes: [{match: {path_prefix: /admin}, failure_mode: closed}]\n")
	vars := env("m")
	vars["DECISION_WAF_POLICY_FILE"] = pf
	h := newCLI(vars, keyword(), nil)
	reads, read := 0, h.cli.readFile
	h.cli.readFile = func(p string) ([]byte, error) {
		if p == pf {
			reads++
			return good, nil
		}
		return read(p)
	}
	out := filepath.Join(t.TempDir(), "r.jsonl")
	if code := h.main("run", "--dataset", ds, "--out", out); code != 0 || reads != 1 {
		t.Fatalf("exit %d (%s), policy read %d times; want success after one read", code, h.stderr, reads)
	}
	f, err := results.ReadFile(out)
	if err != nil || f.Header.PolicySHA256 != fmt.Sprintf("%x", sha256.Sum256(good)) {
		t.Errorf("policy hash %q, err %v; want the hash of the bytes evaluated", f.Header.PolicySHA256, err)
	}
}

func TestResultsFileCheckedBeforeProbe(t *testing.T) {
	ds, out := runTiny(t, "m", keyword())
	h := newCLI(env("m"), keyword(), errors.New("model down"))
	if code := h.main("run", "--dataset", ds, "--out", out); code != 2 || !strings.Contains(h.stderr.String(), "already exists") {
		t.Errorf("exit %d, stderr %q; want 2 about the existing file", code, h.stderr)
	}
}
