package run

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/0x4272616E646F6E/decision-waf/internal/classifier"
	"github.com/0x4272616E646F6E/decision-waf/internal/classifier/fake"
	"github.com/0x4272616E646F6E/decision-waf/internal/decision"
	"github.com/0x4272616E646F6E/decision-waf/internal/eval/dataset"
	"github.com/0x4272616E646F6E/decision-waf/internal/eval/results"
	"github.com/0x4272616E646F6E/decision-waf/internal/inspect"
	"github.com/0x4272616E646F6E/decision-waf/internal/policy"
)

func entry(id, label, path string) dataset.Entry {
	return dataset.Entry{ID: id, Label: label, Method: "GET", Path: path}
}

func many(prefix, label string, n int) []dataset.Entry {
	var es []dataset.Entry
	for i := range n {
		es = append(es, entry(fmt.Sprintf("%s%03d", prefix, i), label, "/"+prefix))
	}
	return es
}

func keyword() *fake.Classifier {
	return fake.New(func(ctx context.Context, r *inspect.Request, _ []policy.Category) (classifier.Verdict, error) {
		switch {
		case strings.Contains(r.Path, "evil"):
			return classifier.Verdict{Benign: 0.1, Category: "sqli", Confidence: 0.9}, nil
		case strings.Contains(r.Path, "broken"):
			return classifier.Verdict{}, classifier.Errorf(classifier.ReasonUpstream5xx, "503")
		case strings.Contains(r.Path, "hang"):
			<-ctx.Done()
			return classifier.Verdict{}, ctx.Err()
		}
		return classifier.Verdict{Benign: 0.9}, nil
	})
}

func engine(c classifier.Classifier) *decision.Engine {
	return decision.NewEngine(classifier.NewGuard(c, time.Second, NewBreaker()), policy.Default(),
		policy.Defaults{Threshold: 0.8, FailureMode: policy.FailOpen}, nil)
}

func runAll(t *testing.T, eng *decision.Engine, entries []dataset.Entry, done map[string]bool, bodyMax, conc int) map[string]results.Result {
	t.Helper()
	var buf bytes.Buffer
	w, err := results.NewWriter(&buf, results.Header{})
	if err != nil {
		t.Fatal(err)
	}
	if err := Run(context.Background(), eng, entries, done, bodyMax, conc, w, nil); err != nil {
		t.Fatal(err)
	}
	f, err := results.Read(&buf)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]results.Result{}
	for _, r := range f.Results {
		out[r.ID] = r
	}
	return out
}

func TestRunRecordsScoresAndErrors(t *testing.T) {
	got := runAll(t, engine(keyword()), []dataset.Entry{
		entry("ok", "benign", "/home"), entry("evil", "sqli", "/evil"), entry("broken", "benign", "/broken"),
	}, nil, 1024, 1)
	if r := got["ok"]; r.AttackScore == nil || math.Abs(*r.AttackScore-0.1) > 1e-9 || r.Outcome != "allow" || r.Error != "" {
		t.Errorf("ok = %+v", r)
	}
	if r := got["evil"]; r.AttackScore == nil || math.Abs(*r.AttackScore-0.9) > 1e-9 || r.Category != "sqli" || r.Outcome != "block" || r.Label != "sqli" {
		t.Errorf("evil = %+v", r)
	}
	if r := got["broken"]; r.AttackScore != nil || r.Error != "upstream_5xx" || r.Outcome != "fail_open" {
		t.Errorf("broken = %+v, want an error with no score", r)
	}
}

func TestRunSkipsDone(t *testing.T) {
	cls := keyword()
	got := runAll(t, engine(cls), []dataset.Entry{entry("a", "benign", "/a"), entry("b", "benign", "/b")}, map[string]bool{"a": true}, 1024, 1)
	if len(got) != 1 || cls.Calls() != 1 || got["b"].ID != "b" {
		t.Errorf("results %v, calls %d", got, cls.Calls())
	}
}

func TestRunConcurrencySameResults(t *testing.T) {
	var entries []dataset.Entry
	for i := range 40 {
		path := "/ok"
		if i%3 == 0 {
			path = "/evil"
		}
		entries = append(entries, entry(fmt.Sprint(i), "benign", path))
	}
	one := runAll(t, engine(keyword()), entries, nil, 1024, 1)
	eight := runAll(t, engine(keyword()), entries, nil, 1024, 8)
	for id, a := range one {
		b := eight[id]
		if *a.AttackScore != *b.AttackScore || a.Outcome != b.Outcome {
			t.Errorf("%s: %+v vs %+v", id, a, b)
		}
	}
	if len(one) != 40 || len(eight) != 40 {
		t.Errorf("counts %d %d", len(one), len(eight))
	}
}

func TestRunCancelDoesNotRecordInFlight(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan struct{})
	cls := fake.New(func(ctx context.Context, r *inspect.Request, _ []policy.Category) (classifier.Verdict, error) {
		if strings.Contains(r.Path, "hang") {
			close(started)
			<-ctx.Done()
			return classifier.Verdict{}, ctx.Err()
		}
		return classifier.Verdict{Benign: 0.9}, nil
	})
	var buf bytes.Buffer
	w, _ := results.NewWriter(&buf, results.Header{})
	wrote := make(chan struct{}, 2)
	entries := []dataset.Entry{entry("a", "benign", "/ok"), entry("b", "benign", "/hang")}
	errc := make(chan error, 1)
	go func() {
		errc <- Run(ctx, engine(cls), entries, nil, 1024, 2, w, func() { wrote <- struct{}{} })
	}()
	<-wrote
	<-started
	cancel()
	if err := <-errc; !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
	f, _ := results.Read(&buf)
	if len(f.Results) != 1 || f.Results[0].ID != "a" {
		t.Errorf("results = %+v, want only a (b was in flight)", f.Results)
	}
}

func TestRunTruncatesBodies(t *testing.T) {
	cls := keyword()
	e := entry("big", "benign", "/upload")
	e.Method = "POST"
	e.BodyB64 = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte("x"), 100))
	runAll(t, engine(cls), []dataset.Entry{e}, nil, 10, 1)
	if r := cls.Last(); len(r.Body) != 10 || !r.BodyTruncated {
		t.Errorf("classifier saw %d bytes, truncated=%v; want 10, true", len(r.Body), r.BodyTruncated)
	}
}

type failAfterHeader struct{ calls int }

func (f *failAfterHeader) Write(p []byte) (int, error) {
	if f.calls++; f.calls > 1 {
		return 0, errors.New("disk full")
	}
	return len(p), nil
}

func TestRunStopsOnWriteError(t *testing.T) {
	w, err := results.NewWriter(&failAfterHeader{}, results.Header{})
	if err != nil {
		t.Fatal(err)
	}
	err = Run(context.Background(), engine(keyword()), many("b", "benign", 5), nil, 1024, 2, w, nil)
	if err == nil || !strings.Contains(err.Error(), "disk full") {
		t.Errorf("err = %v, want the write error", err)
	}
}

func TestBreakerNeverOpens(t *testing.T) {
	eng := engine(fake.Failing(classifier.Errorf(classifier.ReasonTimeout, "slow")))
	got := runAll(t, eng, many("b", "benign", 50), nil, 1024, 1)
	for id, r := range got {
		if r.Error != "timeout" {
			t.Fatalf("%s: error %q, want timeout (the breaker must never open)", id, r.Error)
		}
	}
}

func labelCounts(es []dataset.Entry) map[string]int {
	c := map[string]int{}
	for _, e := range es {
		c[e.Label]++
	}
	return c
}

func TestSampleStratified(t *testing.T) {
	entries := append(many("b", "benign", 80), many("s", "sqli", 20)...)
	got := Sample(entries, 10, 1)
	if c := labelCounts(got); c["benign"] != 8 || c["sqli"] != 2 {
		t.Errorf("counts = %v, want 8 benign 2 sqli", c)
	}
	if again := Sample(entries, 10, 1); !slices.EqualFunc(got, again, func(a, b dataset.Entry) bool { return a.ID == b.ID }) {
		t.Error("same seed gave a different sample")
	}
	if other := Sample(entries, 10, 2); slices.EqualFunc(got, other, func(a, b dataset.Entry) bool { return a.ID == b.ID }) {
		t.Error("a different seed gave the same sample")
	}
	pos := map[string]int{}
	for i, e := range entries {
		pos[e.ID] = i
	}
	if !slices.IsSortedFunc(got, func(a, b dataset.Entry) int { return pos[a.ID] - pos[b.ID] }) {
		t.Error("sample is not in dataset order")
	}
}

func TestSampleKeepsEveryLabel(t *testing.T) {
	entries := append(many("b", "benign", 98), entry("x", "xss", "/x"), entry("s", "sqli", "/s"))
	got := Sample(entries, 10, 1)
	if c := labelCounts(got); len(got) != 10 || c["xss"] != 1 || c["sqli"] != 1 || c["benign"] != 8 {
		t.Errorf("counts = %v (len %d), want 8/1/1", c, len(got))
	}
}

func TestSampleNoOp(t *testing.T) {
	entries := many("b", "benign", 5)
	for _, n := range []int{0, 5, 9} {
		if got := Sample(entries, n, 1); len(got) != 5 {
			t.Errorf("Sample(n=%d) = %d entries, want all 5", n, len(got))
		}
	}
}

func TestResultOfLimit(t *testing.T) {
	r := ResultOf(dataset.Entry{ID: "1", Label: "scanner"}, decision.Decision{Outcome: decision.Block, Note: decision.NoteLimit, Limit: "graphql_depth"})
	if r.Failed() || *r.AttackScore != 1 || r.Limit != "graphql_depth" || r.Error != "" {
		t.Errorf("result %+v; want a block at every threshold, recorded with its limit", r)
	}
}
