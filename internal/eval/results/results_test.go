package results

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func score(v float64) *float64 { return &v }

func header() Header {
	return Header{
		Dataset: DatasetInfo{Path: "d.jsonl", Name: "d", SHA256: "abc", Entries: 3},
		Backend: "jev", Model: "m", Threshold: 0.8, Policy: "default", BodyMaxBytes: 16384,
		DecisionWafVersion: "dev", Started: time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC),
	}
}

func TestRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	w, err := NewWriter(&buf, header())
	if err != nil {
		t.Fatal(err)
	}
	want := []Result{
		{ID: "a", Label: "injection", Tags: []string{"query"}, AttackScore: score(0.97), Category: "injection", Outcome: "block", LatencyMS: 2143},
		{ID: "b", Label: "benign", AttackScore: score(0), Outcome: "allow", LatencyMS: 5},
		{ID: "c", Label: "benign", Outcome: "fail_open", Error: "timeout", LatencyMS: 1000},
	}
	for _, r := range want {
		if err := w.Write(r); err != nil {
			t.Fatal(err)
		}
	}
	size := int64(buf.Len())
	f, err := Read(&buf)
	if err != nil {
		t.Fatal(err)
	}
	h := header()
	h.Version = Version
	if f.Header != h || !reflect.DeepEqual(f.Results, want) || f.Complete != size {
		t.Errorf("read back %+v %+v complete=%d (size %d)", f.Header, f.Results, f.Complete, size)
	}
	if !f.Results[0].Attack() || f.Results[1].Attack() || f.Results[1].Failed() || !f.Results[2].Failed() {
		t.Error("Attack/Failed wrong")
	}
}

func TestPartialLastLineDropped(t *testing.T) {
	var buf bytes.Buffer
	w, _ := NewWriter(&buf, header())
	_ = w.Write(Result{ID: "a", Label: "benign", AttackScore: score(0.1), Outcome: "allow"})
	complete := int64(buf.Len())
	buf.WriteString(`{"id":"b","lab`)
	f, err := Read(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Results) != 1 || f.Complete != complete {
		t.Errorf("results %d complete %d, want 1 and %d", len(f.Results), f.Complete, complete)
	}
}

func TestReadErrors(t *testing.T) {
	hdr := `{"decision_waf_eval_results":1,"dataset":{"path":"d","sha256":"x","entries":1},"backend":"jev","model":"m","threshold":0.8,"policy":"default","body_max_bytes":1,"decision_waf_version":"dev","started":"2026-10-13T12:00:00Z"}` + "\n"
	ok := `{"id":"a","label":"benign","attack_score":0.1,"outcome":"allow","latency_ms":1}` + "\n"
	cases := map[string]struct{ in, want string }{
		"empty":          {"", "no header"},
		"other version":  {strings.Replace(hdr, `"decision_waf_eval_results":1`, `"decision_waf_eval_results":2`, 1), "unsupported results version 2"},
		"malformed line": {hdr + ok + "{nope\n", "line 3"},
		"duplicate id":   {hdr + ok + ok, `line 3: duplicate id "a" (first on line 2)`},
		"missing id":     {hdr + `{"label":"benign","outcome":"allow","latency_ms":1}` + "\n", "line 2: missing id"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Read(strings.NewReader(c.in))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("err = %v, want it to contain %q", err, c.want)
			}
		})
	}
}

func TestSameRun(t *testing.T) {
	a, b := header(), header()
	b.Started = b.Started.Add(time.Hour)
	b.Dataset.Path = "moved/d.jsonl"
	if !a.SameRun(b) {
		t.Error("start time and dataset path must not matter")
	}
	for name, change := range map[string]func(*Header){
		"model":          func(h *Header) { h.Model = "other" },
		"base URL":       func(h *Header) { h.BaseURL = "http://other:1234" },
		"timeout":        func(h *Header) { h.TimeoutMS = 60000 },
		"dataset":        func(h *Header) { h.Dataset.SHA256 = "def" },
		"threshold":      func(h *Header) { h.Threshold = 0.5 },
		"sample":         func(h *Header) { h.Sample = 2 },
		"policy content": func(h *Header) { h.PolicySHA256 = "abc" },
		"version":        func(h *Header) { h.DecisionWafVersion = "v1" },
	} {
		c := header()
		change(&c)
		if a.SameRun(c) {
			t.Errorf("a different %s must not be the same run", name)
		}
	}
}

func TestConcurrentWrites(t *testing.T) {
	var buf bytes.Buffer
	w, _ := NewWriter(&buf, header())
	var wg sync.WaitGroup
	for i := range 50 {
		wg.Go(func() {
			_ = w.Write(Result{ID: fmt.Sprint(i), Label: "benign", AttackScore: score(0.1), Outcome: "allow"})
		})
	}
	wg.Wait()
	f, err := Read(&buf)
	if err != nil || len(f.Results) != 50 {
		t.Fatalf("results %d err %v", len(f.Results), err)
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

func TestWriteErrors(t *testing.T) {
	if _, err := NewWriter(failWriter{}, header()); err == nil {
		t.Error("NewWriter ignored a write error")
	}
	if err := AppendWriter(failWriter{}).Write(Result{ID: "a"}); err == nil {
		t.Error("Write ignored a write error")
	}
}

type failAfter struct {
	n   int
	buf bytes.Buffer
}

func (f *failAfter) Write(p []byte) (int, error) {
	if f.n == 0 {
		return 0, errors.New("disk full")
	}
	f.n--
	return f.buf.Write(p)
}

func TestWriterStopsAfterAFailedWrite(t *testing.T) {
	f := &failAfter{n: 1}
	w := AppendWriter(f)
	if err := w.Write(Result{ID: "a"}); err != nil {
		t.Fatal(err)
	}
	if err := w.Write(Result{ID: "b"}); err == nil {
		t.Fatal("second write: want the failure")
	}
	f.n = 10
	if err := w.Write(Result{ID: "c"}); err == nil || strings.Contains(f.buf.String(), `"c"`) {
		t.Errorf("write after a failure: err %v, file %q; want it refused", err, f.buf.String())
	}
}
