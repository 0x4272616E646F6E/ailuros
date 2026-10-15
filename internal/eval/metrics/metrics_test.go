package metrics

import (
	"encoding/json"
	"math"
	"strings"
	"testing"

	"github.com/0x4272616E646F6E/ailuros/internal/eval/results"
)

func score(v float64) *float64 { return &v }

func near(a, b float64) bool { return math.Abs(a-b) < 1e-9 }

func fixture() *results.File {
	return &results.File{
		Header: results.Header{Threshold: 0.8, Dataset: results.DatasetInfo{Entries: 11}},
		Results: []results.Result{
			{ID: "a-1", Label: "sqli", Tags: []string{"query"}, AttackScore: score(0.95), Category: "sqli", Outcome: "block", LatencyMS: 100},
			{ID: "a-2", Label: "sqli", Tags: []string{"query"}, AttackScore: score(0.85), Category: "xss", Outcome: "block", LatencyMS: 200},
			{ID: "a-3", Label: "sqli", Tags: []string{"path"}, AttackScore: score(0.40), Category: "sqli", Outcome: "allow", LatencyMS: 300},
			{ID: "a-4", Label: "xss", Tags: []string{"query"}, AttackScore: score(0.90), Category: "xss", Outcome: "block", LatencyMS: 400},
			{ID: "a-5", Label: "sqli", Outcome: "fail_open", Error: "timeout", LatencyMS: 500},
			{ID: "b-1", Label: "benign", AttackScore: score(0.05), Outcome: "allow", LatencyMS: 600},
			{ID: "b-2", Label: "benign", AttackScore: score(0.10), Outcome: "allow", LatencyMS: 700},
			{ID: "b-3", Label: "benign", Tags: []string{"lookalike"}, AttackScore: score(0.85), Category: "sqli", Outcome: "block", LatencyMS: 800},
			{ID: "b-4", Label: "benign", Tags: []string{"lookalike"}, AttackScore: score(0.30), Outcome: "allow", LatencyMS: 900},
			{ID: "b-5", Label: "benign", AttackScore: score(0.02), Outcome: "allow", LatencyMS: 1000},
			{ID: "b-6", Label: "benign", Outcome: "fail_open", Error: "rate_limited", LatencyMS: 1100},
		},
	}
}

func TestAt(t *testing.T) {
	p := At(fixture().Results, 0.8)
	if p.TP != 3 || p.FN != 1 || p.FP != 1 || p.TN != 4 {
		t.Errorf("confusion = %+v", p)
	}
	if !near(p.Precision, 0.75) || !near(p.Recall, 0.75) || !near(p.F1, 0.75) || !near(p.FPR, 0.2) {
		t.Errorf("rates = %+v", p)
	}
}

func TestAtEmptyIsZeroNotNaN(t *testing.T) {
	p := At(nil, 0.5)
	if p.Precision != 0 || p.Recall != 0 || p.FPR != 0 || p.F1 != 0 {
		t.Errorf("empty point = %+v", p)
	}
	if _, err := json.Marshal(Summarize(&results.File{}, Options{Threshold: 0.5})); err != nil {
		t.Errorf("summary of nothing does not encode: %v", err)
	}
}

func TestSweep(t *testing.T) {
	pts := Sweep(fixture().Results)
	if len(pts) != 19 || pts[0].Threshold != 0.05 || pts[18].Threshold != 0.95 || pts[7].Threshold != 0.4 {
		t.Fatalf("thresholds = %v", pts)
	}
	if p := pts[7]; p.TP != 4 || p.FP != 1 || !near(p.F1, 8.0/9) {
		t.Errorf("at 0.40: %+v", p)
	}
}

func TestRecommendations(t *testing.T) {
	pts := Sweep(fixture().Results)
	if p := BestF1(pts); p == nil || p.Threshold != 0.4 {
		t.Errorf("best F1 = %+v, want 0.40 (tie with 0.35 goes higher)", p)
	}
	if p := BestRecall(pts, 0.01); p == nil || p.Threshold != 0.9 || !near(p.Recall, 0.5) {
		t.Errorf("best recall at fpr<=0.01 = %+v, want 0.90", p)
	}
	if p := BestRecall(pts, 0.2); p == nil || p.Threshold != 0.4 {
		t.Errorf("best recall at fpr<=0.2 = %+v, want 0.40", p)
	}
	benignOnly := []results.Result{{ID: "b", Label: "benign", AttackScore: score(0.1)}}
	if p := BestF1(Sweep(benignOnly)); p != nil {
		t.Errorf("best F1 with no attacks = %+v, want none", p)
	}
	if p := BestRecall(Sweep(benignOnly), 0.01); p != nil {
		t.Errorf("best recall with no attacks = %+v, want none", p)
	}
}

func TestSummarize(t *testing.T) {
	s := Summarize(fixture(), Options{MaxFPR: 0.01})
	if s.Threshold != 0.8 || s.Total != 11 || s.Scored != 9 || s.Errors != 2 || !near(s.ErrorRate, 2.0/11) {
		t.Errorf("totals = %+v", s)
	}
	if s.ErrorsByReason["timeout"] != 1 || s.ErrorsByReason["rate_limited"] != 1 {
		t.Errorf("errors by reason = %v", s.ErrorsByReason)
	}
	want := []Category{
		{Label: "sqli", Total: 3, Detected: 2, Recall: 2.0 / 3, Attributed: 1, Errors: 1},
		{Label: "xss", Total: 1, Detected: 1, Recall: 1, Attributed: 1},
	}
	if len(s.Categories) != 2 {
		t.Fatalf("categories = %+v", s.Categories)
	}
	for i, c := range s.Categories {
		w := want[i]
		if c.Label != w.Label || c.Total != w.Total || c.Detected != w.Detected || !near(c.Recall, w.Recall) || c.Attributed != w.Attributed || c.Errors != w.Errors {
			t.Errorf("category %d = %+v, want %+v", i, c, w)
		}
	}
	if b := s.Benign; b.Total != 5 || b.FalsePositives != 1 || !near(b.FPR, 0.2) || b.Lookalikes != 2 || b.LookalikeFalsePositives != 1 || b.Errors != 1 {
		t.Errorf("benign = %+v", b)
	}
	if !near(s.Attribution, 2.0/3) {
		t.Errorf("attribution = %v", s.Attribution)
	}
	if s.Latency != (Latency{P50: 600, P95: 1100, P99: 1100}) {
		t.Errorf("latency = %+v", s.Latency)
	}
	if s.BestF1 == nil || s.BestF1.Threshold != 0.4 || s.BestRecall == nil || s.BestRecall.Threshold != 0.9 {
		t.Errorf("recommendations = %+v %+v", s.BestF1, s.BestRecall)
	}
	if len(s.Tags) != 0 {
		t.Errorf("tags without ByTag = %+v", s.Tags)
	}
	joined := strings.Join(s.Warnings, "\n")
	for _, w := range []string{"2 of 11 requests failed", "only 5 benign and 4 attack requests were scored"} {
		if !strings.Contains(joined, w) {
			t.Errorf("warnings %q lack %q", joined, w)
		}
	}
	if strings.Contains(joined, "cover") {
		t.Errorf("complete run warned as incomplete: %q", joined)
	}
}

func TestSummarizeThresholdOverride(t *testing.T) {
	if s := Summarize(fixture(), Options{Threshold: 0.35}); s.Threshold != 0.35 || s.Detection.TP != 4 {
		t.Errorf("override: %+v", s.Detection)
	}
}

func TestByTag(t *testing.T) {
	s := Summarize(fixture(), Options{ByTag: true})
	got := map[string]Point{}
	for _, tg := range s.Tags {
		got[tg.Tag] = tg.Point
	}
	if len(s.Tags) != 3 || s.Tags[0].Tag != "lookalike" {
		t.Fatalf("tags = %+v, want lookalike, path, query in order", s.Tags)
	}
	if p := got["query"]; p.TP != 3 || p.FP != 0 {
		t.Errorf("query = %+v", p)
	}
	if p := got["lookalike"]; p.FP != 1 || p.TN != 1 {
		t.Errorf("lookalike = %+v", p)
	}
}

func TestIncompleteWarning(t *testing.T) {
	f := fixture()
	f.Header.Dataset.Entries = 20
	if s := Summarize(f, Options{}); !strings.Contains(strings.Join(s.Warnings, "\n"), "results cover 11 of 20 requests") {
		t.Errorf("warnings = %q", s.Warnings)
	}
	f.Header.Dataset.Entries, f.Header.Sample = 100, 11
	if s := Summarize(f, Options{}); strings.Contains(strings.Join(s.Warnings, "\n"), "cover") {
		t.Errorf("a finished sample warned as incomplete: %q", s.Warnings)
	}
}

func TestFlaggedMatchesTheEngine(t *testing.T) {
	benign := 0.9
	score := 1 - benign
	rs := []results.Result{{ID: "a", Label: "sqli", AttackScore: &score}}
	if p := At(rs, 0.1); p.TP != 1 {
		t.Errorf("At(0.1) = %+v, want the attack counted as detected", p)
	}
}

func TestLimitBlocksSkipAttributionAndLatency(t *testing.T) {
	base := Summarize(fixture(), Options{})
	f := fixture()
	for _, id := range []string{"l-1", "l-2", "l-3", "l-4", "l-5", "l-6"} {
		f.Results = append(f.Results, results.Result{ID: id, Label: "sqli", AttackScore: score(1), Outcome: "block", Limit: "graphql_depth"})
	}
	got := Summarize(f, Options{})
	if !near(got.Attribution, base.Attribution) {
		t.Errorf("attribution %v, want %v (limit blocks have no category)", got.Attribution, base.Attribution)
	}
	if got.Latency != base.Latency {
		t.Errorf("latency %+v, want %+v (limit blocks do not call the model)", got.Latency, base.Latency)
	}
	for _, c := range got.Categories {
		if c.Label == "sqli" && (c.Detected != 8 || c.Total != 9) {
			t.Errorf("sqli detected %d of %d, want 8 of 9: limit blocks still count toward recall", c.Detected, c.Total)
		}
	}
}
