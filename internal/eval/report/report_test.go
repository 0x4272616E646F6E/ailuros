package report

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0x4272616E646F6E/ailuros/internal/eval/metrics"
	"github.com/0x4272616E646F6E/ailuros/internal/eval/results"
)

var update = flag.Bool("update", false, "rewrite golden files")

func load(t *testing.T, name string) *results.File {
	t.Helper()
	f, err := results.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func golden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s differs; rerun with -update and review the diff. got:\n%s", name, got)
	}
}

func contains(t *testing.T, got string, wants ...string) {
	t.Helper()
	for _, w := range wants {
		if !strings.Contains(got, w) {
			t.Errorf("output lacks %q:\n%s", w, got)
		}
	}
}

func summary(f *results.File) metrics.Summary {
	return metrics.Summarize(f, metrics.Options{MaxFPR: 0.01, ByTag: true})
}

func TestText(t *testing.T) {
	a := load(t, "run-a.jsonl")
	var buf bytes.Buffer
	if err := Text(&buf, a.Header, summary(a)); err != nil {
		t.Fatal(err)
	}
	contains(t, buf.String(),
		"dataset  fixture (eval/datasets/fixture.jsonl, sha256 aaaaaaaaaaaa, 11 requests)",
		"backend  jev, model d1-3b, policy default, run threshold 0.8, ailuros dev",
		"warning: 2 of 11 requests failed",
		"precision 0.750  recall 0.750  f1 0.750  false-positive rate 0.200",
		"best F1: threshold 0.40",
		"best recall with fpr <= 0.010: threshold 0.90",
		"latency p50 600 ms, p95 1100 ms, p99 1100 ms",
		"errors 2 of 11 (18.2%): rate_limited 1, timeout 1",
	)
	golden(t, "report.txt", buf.Bytes())
}

func TestMarkdown(t *testing.T) {
	a := load(t, "run-a.jsonl")
	var buf bytes.Buffer
	if err := Markdown(&buf, a.Header, summary(a)); err != nil {
		t.Fatal(err)
	}
	contains(t, buf.String(),
		"# ailuros-eval report",
		"> **Warning:** 2 of 11 requests failed",
		"| 0.750 | 0.750 | 0.750 | 0.200 | 3 | 1 | 4 | 1 |",
		"| sqli | 3 | 2 | 0.667 | 1 | 1 |",
		"## Threshold sweep",
		"- Best F1: threshold 0.40",
	)
	golden(t, "report.md", buf.Bytes())
}

func TestUndefinedRatesPrintNA(t *testing.T) {
	a := load(t, "run-a.jsonl")
	s := summary(a)
	var text, md bytes.Buffer
	if err := Text(&text, a.Header, s); err != nil {
		t.Fatal(err)
	}
	if err := Markdown(&md, a.Header, s); err != nil {
		t.Fatal(err)
	}
	var row string
	for _, line := range strings.Split(text.String(), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "lookalike") {
			row = line
		}
	}
	if row == "" || len(strings.Fields(row)) < 9 || strings.Fields(row)[2] != "n/a" || strings.Fields(row)[4] != "n/a" {
		t.Errorf("text by-tag row for a benign-only tag = %q; want recall and f1 n/a", row)
	}
	contains(t, md.String(), "| lookalike | 0.000 | n/a | 0.500 | n/a |")
	if h, v := rate(0, 0), rate(0.5, 2); h != "n/a" || v != "0.500" {
		t.Errorf("rate = %q, %q", h, v)
	}
	var js bytes.Buffer
	if err := JSON(&js, a.Header, s); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(js.String(), "n/a") {
		t.Errorf("JSON contains n/a:\n%s", js.String())
	}
}

func TestUndefinedRatesElsewherePrintNA(t *testing.T) {
	s := metrics.Summary{
		Threshold:  0.825,
		Detection:  metrics.Point{FN: 3},
		Categories: []metrics.Category{{Label: "sqli", Total: 3}},
		BestF1:     &metrics.Point{Threshold: 0.5, TP: 1, FN: 2, Precision: 1, Recall: 1.0 / 3, F1: 0.5},
	}
	var text bytes.Buffer
	if err := Text(&text, results.Header{Threshold: 0.825}, s); err != nil {
		t.Fatal(err)
	}
	contains(t, text.String(), "threshold 0.825:", "run threshold 0.825", "category attribution n/a",
		"best F1: threshold 0.50 (precision 1.000, recall 0.333, fpr n/a, f1 0.500)")
	if pts := metrics.BestRecall([]metrics.Point{{Threshold: 0.5, TP: 2, FN: 1, Recall: 2.0 / 3}}, 0.01); pts != nil {
		t.Errorf("BestRecall with no benign request scored = %+v, want none: the FPR is unmeasured", pts)
	}
}

func TestMarkdownEscapesPipes(t *testing.T) {
	a := load(t, "run-a.jsonl")
	a.Header.Model = "a|b"
	var buf bytes.Buffer
	if err := Markdown(&buf, a.Header, summary(a)); err != nil {
		t.Fatal(err)
	}
	contains(t, buf.String(), `a\|b`)
}

func TestJSON(t *testing.T) {
	a := load(t, "run-a.jsonl")
	var buf bytes.Buffer
	if err := JSON(&buf, a.Header, summary(a)); err != nil {
		t.Fatal(err)
	}
	var got struct {
		Run     results.Header  `json:"run"`
		Summary metrics.Summary `json:"summary"`
	}
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Run.Model != "d1-3b" || got.Summary.Detection.TP != 3 || got.Summary.BestF1.Threshold != 0.4 {
		t.Errorf("decoded %+v", got)
	}
}

func TestCompare(t *testing.T) {
	a, b := load(t, "run-a.jsonl"), load(t, "run-b.jsonl")
	var buf bytes.Buffer
	if err := Compare(&buf, a, b, metrics.Options{MaxFPR: 0.01}); err != nil {
		t.Fatal(err)
	}
	contains(t, buf.String(), "compare at threshold 0.8", "jev / d1-3b", "openai / local-llm", "warning (A): 2 of 11 requests failed")
	golden(t, "compare.txt", buf.Bytes())
}

func TestCheckComparable(t *testing.T) {
	a, b := load(t, "run-a.jsonl").Header, load(t, "run-b.jsonl").Header
	if err := CheckComparable(a, b, false); err != nil {
		t.Errorf("same dataset refused: %v", err)
	}
	other := b
	other.Dataset.SHA256 = "bbbb"
	if err := CheckComparable(a, other, false); err == nil || !strings.Contains(err.Error(), "--allow-different-datasets") {
		t.Errorf("different datasets: %v", err)
	}
	if err := CheckComparable(a, other, true); err != nil {
		t.Errorf("allowed comparison refused: %v", err)
	}
	sampled := b
	sampled.Sample, sampled.Seed = 5, 1
	if err := CheckComparable(a, sampled, false); err == nil {
		t.Error("runs over different samples compared without --allow-different-datasets")
	}
}

func ptr(f float64) *float64 { return &f }

func TestCompareWarnsOnPromptVersion(t *testing.T) {
	rs := []results.Result{
		{ID: "1", Label: "benign", AttackScore: ptr(0.1), Outcome: "allow"},
		{ID: "2", Label: "sqli", AttackScore: ptr(0.9), Outcome: "block"},
	}
	a := &results.File{Header: results.Header{Threshold: 0.8}, Results: rs}
	b := &results.File{Header: results.Header{Threshold: 0.8, PromptVersion: 2}, Results: rs}
	var out strings.Builder
	if err := Compare(&out, a, b, metrics.Options{MaxFPR: 0.01}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "prompt versions differ (A 1, B 2)") {
		t.Errorf("no prompt version warning:\n%s", out.String())
	}
}

func TestAttributionNAWhenOnlyLimitBlocksDetected(t *testing.T) {
	one := 1.0
	f := &results.File{Header: results.Header{Threshold: 0.5}, Results: []results.Result{
		{ID: "1", Label: "sqli", AttackScore: &one, Limit: "graphql_depth", Outcome: "deny"},
	}}
	s := summary(f)
	if s.AttributionDetected != 0 {
		t.Errorf("AttributionDetected = %d, want 0", s.AttributionDetected)
	}
	var text, md bytes.Buffer
	if err := Text(&text, f.Header, s); err != nil {
		t.Fatal(err)
	}
	if err := Markdown(&md, f.Header, s); err != nil {
		t.Fatal(err)
	}
	contains(t, text.String(), "category attribution n/a")
	contains(t, md.String(), "Category attribution: n/a")

	f.Results = append(f.Results, results.Result{ID: "2", Label: "sqli", AttackScore: &one, Category: "xss", Outcome: "deny"})
	s = summary(f)
	text.Reset()
	if err := Text(&text, f.Header, s); err != nil {
		t.Fatal(err)
	}
	if s.AttributionDetected != 1 {
		t.Errorf("AttributionDetected = %d, want 1", s.AttributionDetected)
	}
	contains(t, text.String(), "category attribution 0.000")
}
