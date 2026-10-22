package telemetry

import (
	"context"
	"log/slog"
	"unicode/utf8"

	"github.com/0x4272616E646F6E/decision-waf/internal/classifier"
	"github.com/0x4272616E646F6E/decision-waf/internal/decision"
	"github.com/0x4272616E646F6E/decision-waf/internal/inspect"
)

const debugBodyLimit = 1024

type Recorder struct {
	log     *slog.Logger
	metrics *Metrics
	backend string
}

func NewRecorder(log *slog.Logger, m *Metrics, backend string) *Recorder {
	return &Recorder{log: log, metrics: m, backend: backend}
}

func categoryLabel(d decision.Decision) string {
	switch d.Outcome {
	case decision.Allow:
		return "benign"
	case decision.Block:
		if d.Verdict.Category != "" {
			return d.Verdict.Category
		}
	}
	return "none"
}

func debugBody(body []byte) string {
	if len(body) <= debugBodyLimit {
		return string(body)
	}
	cut := debugBodyLimit
	for i := 0; i < utf8.UTFMax && cut > 0 && !utf8.RuneStart(body[cut]); i++ {
		cut--
	}
	return string(body[:cut])
}

func (r *Recorder) Observe(ctx context.Context, req *inspect.Request, d decision.Decision) {
	r.metrics.decisions.WithLabelValues(string(d.Outcome), categoryLabel(d), d.Route, d.Source.Frontend).Inc()
	if d.Reason != "" && d.ClassifierCalled && d.Reason != classifier.ReasonCanceled {
		r.metrics.errors.WithLabelValues(r.backend, string(d.Reason)).Inc()
	}
	if d.Latency > 0 && d.Reason != classifier.ReasonCircuitOpen {
		r.metrics.latency.WithLabelValues(r.backend).Observe(d.Latency.Seconds())
	}

	level := slog.LevelInfo
	if d.Outcome == decision.FailOpen || d.Outcome == decision.FailClosed {
		level = slog.LevelWarn
	}
	attrs := []slog.Attr{
		slog.String("request_id", d.RequestID),
		slog.String("frontend", d.Source.Frontend),
		slog.String("mode", string(d.Source.Mode)),
		slog.String("route", d.Route),
		slog.String("method", req.Method),
		slog.String("host", req.Host),
		slog.String("path", req.Path),
		slog.String("outcome", string(d.Outcome)),
		slog.String("backend", r.backend),
		slog.Float64("classifier_latency_ms", float64(d.Latency.Microseconds())/1000),
		slog.String("client_ip", req.ClientIP),
		slog.String("signals", req.SignalSummary()),
	}
	grpcMethod := ""
	if req.IsGRPC() {
		grpcMethod = req.GRPCService + "/" + req.GRPCMethod
	}
	var score, confidence any
	if d.Classified {
		score = d.Verdict.AttackScore()
		if d.Verdict.Category != "" {
			confidence = d.Verdict.Confidence
		}
	}
	reason := string(d.Reason)
	if reason == "" {
		reason = string(d.Note)
	}
	attrs = append(attrs,
		slog.String("grpc_method", grpcMethod),
		slog.String("stream_id", d.StreamID),
		slog.Any("attack_score", score),
		slog.String("category", d.Verdict.Category),
		slog.Any("confidence", confidence),
		slog.String("reason", reason),
		slog.String("limit", d.Limit),
	)
	if len(req.Body) > 0 && r.log.Enabled(ctx, slog.LevelDebug) {
		attrs = append(attrs, slog.String("body", debugBody(req.Body)))
	}
	r.log.LogAttrs(ctx, level, "decision", attrs...)
}
