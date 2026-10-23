package telemetry

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/0x4272616E646F6E/decision-waf/internal/classifier"
	"github.com/0x4272616E646F6E/decision-waf/internal/decision"
	"github.com/0x4272616E646F6E/decision-waf/internal/inspect"
)

var src = decision.Source{Frontend: "forwardauth", Mode: inspect.ModeLite}

func logLine(t *testing.T, buf *bytes.Buffer) map[string]any {
	t.Helper()
	var line map[string]any
	if err := json.Unmarshal(buf.Bytes(), &line); err != nil {
		t.Fatalf("log is not one JSON line: %v\n%s", err, buf)
	}
	return line
}

func TestRecorderBlock(t *testing.T) {
	var buf bytes.Buffer
	m := NewMetrics()
	rec := NewRecorder(NewLogger(&buf, slog.LevelInfo), m, "openai")
	req := &inspect.Request{Method: "POST", Host: "h", Path: "/login", ClientIP: "1.2.3.4", Body: []byte("password=[REDACTED]")}
	d := decision.Decision{
		RequestID: "abc", Outcome: decision.Block, Classified: true,
		Verdict: classifier.Verdict{Benign: 0.045, Category: "injection", Confidence: 0.576},
		Route:   "default", Latency: 120 * time.Millisecond, Source: src,
	}
	rec.Observe(context.Background(), req, d)

	if got := testutil.ToFloat64(m.decisions.WithLabelValues("block", "injection", "default", "forwardauth")); got != 1 {
		t.Errorf("decisions = %v, want 1", got)
	}
	if got := testutil.CollectAndCount(m.latency); got != 1 {
		t.Errorf("latency series = %d, want 1", got)
	}
	line := logLine(t, &buf)
	want := map[string]any{
		"msg": "decision", "level": "INFO", "request_id": "abc", "frontend": "forwardauth", "mode": "lite", "route": "default",
		"method": "POST", "host": "h", "path": "/login", "outcome": "block", "attack_score": 0.955, "category": "injection", "confidence": 0.576,
		"backend": "openai", "classifier_latency_ms": 120.0, "client_ip": "1.2.3.4",
	}
	for k, v := range want {
		if line[k] != v {
			t.Errorf("log %s = %v, want %v", k, line[k], v)
		}
	}
	if _, ok := line["body"]; ok {
		t.Error("body logged at info level")
	}
}

func TestRecorderFailure(t *testing.T) {
	var buf bytes.Buffer
	m := NewMetrics()
	rec := NewRecorder(NewLogger(&buf, slog.LevelInfo), m, "jev")
	d := decision.Decision{RequestID: "x", Outcome: decision.FailOpen, Reason: classifier.ReasonTimeout, Route: "default", Latency: time.Second, Source: src, ClassifierCalled: true}
	rec.Observe(context.Background(), &inspect.Request{}, d)
	if got := testutil.ToFloat64(m.errors.WithLabelValues("jev", "timeout")); got != 1 {
		t.Errorf("errors = %v, want 1", got)
	}
	if got := testutil.ToFloat64(m.decisions.WithLabelValues("fail_open", "none", "default", "forwardauth")); got != 1 {
		t.Errorf("decisions = %v, want 1", got)
	}
	if line := logLine(t, &buf); line["level"] != "WARN" || line["reason"] != "timeout" {
		t.Errorf("log = %v", line)
	}
}

func TestRecorderCircuitOpenSkipsLatency(t *testing.T) {
	m := NewMetrics()
	rec := NewRecorder(NewLogger(&bytes.Buffer{}, slog.LevelInfo), m, "jev")
	d := decision.Decision{Outcome: decision.FailOpen, Reason: classifier.ReasonCircuitOpen, Latency: time.Microsecond, Source: src, Route: "default"}
	rec.Observe(context.Background(), &inspect.Request{}, d)
	if got := testutil.CollectAndCount(m.latency); got != 0 {
		t.Errorf("latency series = %d, want 0 for circuit_open", got)
	}
}

func TestRecorderDebugLogsTruncatedBody(t *testing.T) {
	var buf bytes.Buffer
	rec := NewRecorder(NewLogger(&buf, slog.LevelDebug), NewMetrics(), "jev")
	req := &inspect.Request{Body: []byte(strings.Repeat("a", 2000))}
	rec.Observe(context.Background(), req, decision.Decision{Outcome: decision.Allow, Route: "default", Source: src})
	if body, _ := logLine(t, &buf)["body"].(string); len(body) != 1024 {
		t.Errorf("debug body length = %d, want 1024", len(body))
	}
}

func TestRecorderCategoryLabel(t *testing.T) {
	cases := []struct {
		name string
		d    decision.Decision
		want string
	}{
		{"block uses the attack category", decision.Decision{Outcome: decision.Block, Classified: true, Verdict: classifier.Verdict{Benign: 0.1, Category: "xss", Confidence: 0.5}}, "xss"},
		{"allow is benign even with a likely category", decision.Decision{Outcome: decision.Allow, Classified: true, Verdict: classifier.Verdict{Benign: 0.97, Category: "injection", Confidence: 0.02}}, "benign"},
		{"block without a category", decision.Decision{Outcome: decision.Block, Classified: true, Verdict: classifier.Verdict{Benign: 0.1}}, "none"},
		{"oversize block", decision.Decision{Outcome: decision.Block, Note: decision.NoteOversize}, "none"},
		{"message limit block", decision.Decision{Outcome: decision.Block, Note: decision.NoteMessageLimit}, "none"},
		{"fail closed", decision.Decision{Outcome: decision.FailClosed, Reason: classifier.ReasonTimeout}, "none"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := NewMetrics()
			c.d.Route, c.d.Source = "default", src
			NewRecorder(NewLogger(&bytes.Buffer{}, slog.LevelInfo), m, "jev").Observe(context.Background(), &inspect.Request{}, c.d)
			if got := testutil.ToFloat64(m.decisions.WithLabelValues(string(c.d.Outcome), c.want, "default", "forwardauth")); got != 1 {
				t.Errorf("decisions{category=%q} = %v, want 1", c.want, got)
			}
		})
	}
}

func TestRecorderNoteIsReasonButNotAnError(t *testing.T) {
	var buf bytes.Buffer
	m := NewMetrics()
	rec := NewRecorder(NewLogger(&buf, slog.LevelInfo), m, "jev")
	rec.Observe(context.Background(), &inspect.Request{}, decision.Decision{Outcome: decision.Block, Note: decision.NoteOversize, Route: "default", Source: src})
	line := logLine(t, &buf)
	if line["reason"] != "oversize" || line["outcome"] != "block" {
		t.Errorf("log = %v, want outcome=block reason=oversize", line)
	}
	if v, ok := line["attack_score"]; !ok || v != nil {
		t.Errorf("attack_score = %v (present %v), want null for an unclassified decision", v, ok)
	}
	if got := testutil.CollectAndCount(m.errors); got != 0 {
		t.Errorf("classifier error series = %d, want 0 for an oversize note", got)
	}
}

func TestRecorderFrontendFailureIsNotAClassifierError(t *testing.T) {
	m := NewMetrics()
	rec := NewRecorder(NewLogger(io.Discard, slog.LevelInfo), m, "jev")
	for _, d := range []decision.Decision{
		{Outcome: decision.FailOpen, Reason: classifier.ReasonProtocol, Route: "default", Source: src},
		{Outcome: decision.FailOpen, Reason: classifier.ReasonPanic, Route: "default", Source: src},
		{Outcome: decision.FailOpen, Reason: classifier.ReasonCanceled, Route: "default", Source: src, ClassifierCalled: true},
	} {
		rec.Observe(context.Background(), &inspect.Request{}, d)
	}
	if got := testutil.CollectAndCount(m.errors); got != 0 {
		t.Errorf("classifier error series = %d, want 0", got)
	}
}

func TestRecorderStableSchema(t *testing.T) {
	want := []string{"request_id", "frontend", "mode", "route", "method", "host", "path", "outcome", "backend",
		"classifier_latency_ms", "client_ip", "grpc_method", "stream_id", "attack_score", "category", "confidence", "reason", "limit"}
	for _, d := range []decision.Decision{
		{RequestID: "a", Outcome: decision.Allow, Classified: true, Verdict: classifier.Verdict{Benign: 1}, Route: "default", Source: src},
		{RequestID: "b", StreamID: "s", Outcome: decision.Block, Note: decision.NoteOversize, Route: "default", Source: src},
	} {
		var buf bytes.Buffer
		NewRecorder(NewLogger(&buf, slog.LevelInfo), NewMetrics(), "jev").Observe(context.Background(), &inspect.Request{}, d)
		line := logLine(t, &buf)
		for _, k := range want {
			if _, ok := line[k]; !ok {
				t.Errorf("%s: field %q missing from %v", d.RequestID, k, line)
			}
		}
		if d.StreamID != "" && line["stream_id"] != d.StreamID {
			t.Errorf("stream_id = %v, want %q", line["stream_id"], d.StreamID)
		}
	}
}

func TestDebugBodyCutsOnARuneBoundary(t *testing.T) {
	body := append(bytes.Repeat([]byte("a"), debugBodyLimit-1), "é and more"...)
	if got := debugBody(body); !utf8.ValidString(got) || len(got) != debugBodyLimit-1 {
		t.Errorf("debugBody = %d bytes, valid UTF-8 %v; want the %d bytes before é", len(got), utf8.ValidString(got), debugBodyLimit-1)
	}
}

func TestDecisionLogHasSignals(t *testing.T) {
	var buf bytes.Buffer
	rec := NewRecorder(NewLogger(&buf, slog.LevelInfo), NewMetrics(), "fake")
	d := decision.Decision{Outcome: decision.Allow, Source: src, Route: "default"}
	rec.Observe(context.Background(), &inspect.Request{Signals: []string{"smuggling: te_on_h2"}}, d)
	rec.Observe(context.Background(), &inspect.Request{}, d)
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	var first, second map[string]any
	_ = json.Unmarshal([]byte(lines[0]), &first)
	_ = json.Unmarshal([]byte(lines[1]), &second)
	if first["signals"] != "smuggling te_on_h2" {
		t.Errorf("signals = %v", first["signals"])
	}
	if v, ok := second["signals"]; !ok || v != "" {
		t.Errorf("signals field missing or not empty without signals: %v, %v", v, ok)
	}
}

func TestDecisionLogHasLimit(t *testing.T) {
	var buf bytes.Buffer
	rec := NewRecorder(NewLogger(&buf, slog.LevelInfo), NewMetrics(), "fake")
	rec.Observe(context.Background(), &inspect.Request{}, decision.Decision{Outcome: decision.Block, Note: decision.NoteLimit, Limit: "graphql_depth", Source: src, Route: "default"})
	rec.Observe(context.Background(), &inspect.Request{}, decision.Decision{Outcome: decision.Allow, Source: src, Route: "default"})
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	var first, second map[string]any
	_ = json.Unmarshal([]byte(lines[0]), &first)
	_ = json.Unmarshal([]byte(lines[1]), &second)
	if first["reason"] != "limit" || first["limit"] != "graphql_depth" {
		t.Errorf("limit decision log = %v", first)
	}
	if v, ok := second["limit"]; !ok || v != "" {
		t.Errorf("limit field missing or not empty without a limit: %v, %v", v, ok)
	}
}
