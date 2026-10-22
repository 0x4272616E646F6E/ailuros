package decision

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/0x4272616E646F6E/decision-waf/internal/classifier"
	"github.com/0x4272616E646F6E/decision-waf/internal/inspect"
	"github.com/0x4272616E646F6E/decision-waf/internal/policy"
	"github.com/0x4272616E646F6E/decision-waf/internal/redact"
	"github.com/0x4272616E646F6E/decision-waf/internal/signals"
)

var tracer = otel.Tracer("github.com/0x4272616E646F6E/decision-waf/internal/decision")

type Outcome string

const (
	Allow      Outcome = "allow"
	Block      Outcome = "block"
	FailOpen   Outcome = "fail_open"
	FailClosed Outcome = "fail_closed"
)

func (o Outcome) Denied() bool { return o == Block || o == FailClosed }

type Note string

const (
	NoteOversize      Note = "oversize"
	NoteUninspectable Note = "uninspectable"
	NoteMessageLimit  Note = "message_limit"
	NoteLimit         Note = "limit"
	NoteMalformed     Note = "malformed"
)

type Source struct {
	Frontend string
	Mode     inspect.Mode
}

type Decision struct {
	RequestID        string
	Outcome          Outcome
	Classified       bool
	Verdict          classifier.Verdict
	Reason           classifier.Reason
	Note             Note
	Limit            string
	Route            string
	Latency          time.Duration
	Source           Source
	StreamID         string
	ClassifierCalled bool
}

func (d Decision) DebugHeader() string {
	if !d.Classified {
		reason := string(d.Reason)
		if reason == "" {
			reason = string(d.Note)
		}
		return fmt.Sprintf("%s; reason=%s", d.Outcome, reason)
	}
	s := fmt.Sprintf("%s; attack_score=%.3f", d.Outcome, d.Verdict.AttackScore())
	if d.Verdict.Category != "" {
		s += fmt.Sprintf("; category=%s; confidence=%.3f", d.Verdict.Category, d.Verdict.Confidence)
	}
	return s
}

type Observer interface {
	Observe(ctx context.Context, r *inspect.Request, d Decision)
}

type state struct {
	policy   *policy.Policy
	redactor *redact.Redactor
}

type Engine struct {
	classifier classifier.Classifier
	defaults   policy.Defaults
	observer   Observer
	state      atomic.Pointer[state]
}

func NewEngine(c classifier.Classifier, p *policy.Policy, d policy.Defaults, obs Observer) *Engine {
	e := &Engine{classifier: c, defaults: d, observer: obs}
	e.SetPolicy(p)
	return e
}

func (e *Engine) SetPolicy(p *policy.Policy) {
	e.state.Store(&state{policy: p, redactor: redact.New(p.Redact)})
}

func (e *Engine) Decide(ctx context.Context, r *inspect.Request, src Source) Decision {
	return e.DecideNote(ctx, r, src, "")
}

func (e *Engine) DecideNote(ctx context.Context, r *inspect.Request, src Source, note Note) Decision {
	p := e.begin(ctx, r, src)
	if e.limited(p) {
		return e.finish(p)
	}
	p.d.Note, p.d.ClassifierCalled = note, true
	start := time.Now()
	v, err := e.classify(p.ctx, p.redacted, p.st.policy.Categories)
	p.d.Latency = time.Since(start)
	if err != nil {
		p.span.RecordError(err)
		p.d.Reason = classifier.ReasonOf(err)
		p.d.Outcome = failureOutcome(p.res.FailureMode)
		if p.d.Reason == classifier.ReasonBadOutput {
			p.d.Outcome = badOutputOutcome(e.defaults.BadOutput, p.res.FailureMode)
		}
	} else {
		p.d.Classified, p.d.Verdict = true, v
		p.d.Outcome = verdictOutcome(v, p.res)
	}
	return e.finish(p)
}

type pending struct {
	ctx      context.Context
	span     trace.Span
	st       *state
	res      policy.Resolved
	redacted *inspect.Request
	sig      signals.Signals
	d        Decision
}

func (e *Engine) begin(ctx context.Context, r *inspect.Request, src Source) *pending {
	ctx, span := tracer.Start(ctx, "ailuros.decide")
	if r == nil {
		r = &inspect.Request{}
	}
	st := e.state.Load()
	res := st.policy.Resolve(r, e.defaults)
	sig := signals.Extract(r)
	redacted := st.redactor.Apply(r)
	redacted.Signals = sig.Lines()
	return &pending{ctx: ctx, span: span, st: st, res: res, sig: sig, redacted: redacted,
		d: Decision{RequestID: requestID(ctx), StreamID: streamID(ctx), Route: res.Route, Source: src}}
}

func (e *Engine) finish(p *pending) Decision {
	endSpan(p.span, p.d)
	p.span.End()
	e.observe(p.ctx, p.redacted, p.d)
	return p.d
}

func endSpan(span trace.Span, d Decision) {
	attrs := []attribute.KeyValue{
		attribute.String("ailuros.request_id", d.RequestID),
		attribute.String("ailuros.outcome", string(d.Outcome)),
		attribute.String("ailuros.route", d.Route),
	}
	if d.Reason != "" {
		attrs = append(attrs, attribute.String("ailuros.reason", string(d.Reason)))
		span.SetStatus(codes.Error, string(d.Reason))
	} else if d.Note != "" {
		attrs = append(attrs, attribute.String("ailuros.reason", string(d.Note)))
	}
	if d.Limit != "" {
		attrs = append(attrs, attribute.String("ailuros.limit", d.Limit))
	}
	span.SetAttributes(attrs...)
}

func (e *Engine) limited(p *pending) bool {
	if p.d.Outcome.Denied() {
		return false
	}
	limit, hit := signals.Check(p.sig, p.res.Limits)
	if hit {
		p.d.Outcome, p.d.Note, p.d.Limit, p.d.Reason = Block, NoteLimit, limit, ""
	}
	return hit
}

func (e *Engine) Fail(ctx context.Context, r *inspect.Request, src Source, reason classifier.Reason) Decision {
	p := e.begin(ctx, r, src)
	p.d.Outcome, p.d.Reason = failureOutcome(p.res.FailureMode), reason
	e.limited(p)
	return e.finish(p)
}

func (e *Engine) Bypass(ctx context.Context, r *inspect.Request, src Source, o Outcome, note Note) Decision {
	p := e.begin(ctx, r, src)
	p.d.Outcome, p.d.Note = o, note
	e.limited(p)
	return e.finish(p)
}

func (e *Engine) classify(ctx context.Context, r *inspect.Request, cats []policy.Category) (v classifier.Verdict, err error) {
	defer func() {
		if p := recover(); p != nil {
			err = classifier.Errorf(classifier.ReasonPanic, "classifier panic: %v", p)
		}
	}()
	return e.classifier.Classify(ctx, r, cats)
}

func (e *Engine) observe(ctx context.Context, r *inspect.Request, d Decision) {
	if p, ok := ctx.Value(sinkKey{}).(*Decision); ok {
		*p = d
	}
	if e.observer != nil {
		e.observer.Observe(ctx, r, d)
	}
}

func verdictOutcome(v classifier.Verdict, res policy.Resolved) Outcome {
	if policy.Blocks(v.AttackScore(), res.Threshold()) {
		return Block
	}
	return Allow
}

func badOutputOutcome(b policy.BadOutput, m policy.FailureMode) Outcome {
	switch b {
	case policy.BadOutputFailClosed:
		return FailClosed
	case policy.BadOutputFailureMode:
		return failureOutcome(m)
	}
	return Block
}

func failureOutcome(m policy.FailureMode) Outcome {
	if m == policy.FailClosed {
		return FailClosed
	}
	return FailOpen
}

type requestIDKey struct{}

func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey{}, id)
}

func requestID(ctx context.Context) string {
	if id, ok := ctx.Value(requestIDKey{}).(string); ok && id != "" {
		return id
	}
	return NewRequestID()
}

type streamIDKey struct{}

func WithStreamID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, streamIDKey{}, id)
}

func streamID(ctx context.Context) string {
	id, _ := ctx.Value(streamIDKey{}).(string)
	return id
}

func NewRequestID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

type sinkKey struct{}

func WithSink(ctx context.Context, p *Decision) context.Context {
	return context.WithValue(ctx, sinkKey{}, p)
}

func (e *Engine) DefaultFailureMode() policy.FailureMode { return e.defaults.FailureMode }

func (e *Engine) FailureModeFor(r *inspect.Request) (m policy.FailureMode) {
	m = e.defaults.FailureMode
	defer func() { _ = recover() }()
	if r == nil {
		r = &inspect.Request{}
	}
	return e.state.Load().policy.Resolve(r, e.defaults).FailureMode
}
