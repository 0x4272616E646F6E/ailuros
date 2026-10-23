package decision

import (
	"context"
	"errors"
	"go.opentelemetry.io/otel"
	otelcodes "go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/0x4272616E646F6E/decision-waf/internal/classifier"
	"github.com/0x4272616E646F6E/decision-waf/internal/classifier/fake"
	"github.com/0x4272616E646F6E/decision-waf/internal/inspect"
	"github.com/0x4272616E646F6E/decision-waf/internal/policy"
	"github.com/0x4272616E646F6E/decision-waf/internal/redact"
)

var (
	ctx      = context.Background()
	defaults = policy.Defaults{Threshold: 0.8, FailureMode: policy.FailOpen}
	src      = Source{Frontend: "test", Mode: inspect.ModeLite}
)

type recorder struct {
	mu        sync.Mutex
	reqs      []*inspect.Request
	decisions []Decision
}

func (r *recorder) Observe(_ context.Context, req *inspect.Request, d Decision) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.reqs = append(r.reqs, req)
	r.decisions = append(r.decisions, d)
}

func verdict(benign float64, cat string, conf float64) *fake.Classifier {
	return fake.Returning(classifier.Verdict{Benign: benign, Category: cat, Confidence: conf})
}

func TestOutcomes(t *testing.T) {
	cases := []struct {
		name   string
		benign float64
		cat    string
		conf   float64
		want   Outcome
	}{
		{"clearly benign", 0.99, "injection", 0.01, Allow},
		{"clear attack", 0.05, "injection", 0.95, Block},
		{"attack score exactly at threshold", 0.2, "injection", 0.8, Block},
		{"attack score just below threshold", 0.21, "injection", 0.79, Allow},
		{"split attack", 0.045, "auth_abuse", 0.58, Block},
		{"no category reported", 0.1, "", 0, Block},
		{"benign with no category", 1, "", 0, Allow},
	}
	for _, c := range cases {
		d := NewEngine(verdict(c.benign, c.cat, c.conf), policy.Default(), defaults, nil).Decide(ctx, &inspect.Request{Path: "/"}, src)
		if d.Outcome != c.want {
			t.Errorf("%s (benign %v): outcome = %q, want %q", c.name, c.benign, d.Outcome, c.want)
		}
	}
}

func TestRouteOverrides(t *testing.T) {
	th := 0.6
	p := policy.Default()
	p.Routes = []policy.Route{{Match: policy.Match{PathPrefix: "/admin"}, FailureMode: policy.FailClosed, Threshold: &th}}

	e := NewEngine(verdict(0.4, "injection", 0.3), p, defaults, nil)
	if d := e.Decide(ctx, &inspect.Request{Path: "/admin/users"}, src); d.Outcome != Block || d.Route != "0" {
		t.Errorf("/admin attack 0.6: %+v, want block on route 0", d)
	}
	if d := e.Decide(ctx, &inspect.Request{Path: "/"}, src); d.Outcome != Allow || d.Route != "default" {
		t.Errorf("/ attack 0.6: %+v, want allow on default route", d)
	}

	down := NewEngine(fake.Failing(classifier.Errorf(classifier.ReasonUpstream5xx, "503")), p, defaults, nil)
	if d := down.Decide(ctx, &inspect.Request{Path: "/admin"}, src); d.Outcome != FailClosed || d.Reason != classifier.ReasonUpstream5xx {
		t.Errorf("/admin down: %+v, want fail_closed upstream_5xx", d)
	}
	if d := down.Decide(ctx, &inspect.Request{Path: "/"}, src); d.Outcome != FailOpen {
		t.Errorf("/ down: %+v, want fail_open", d)
	}
}

func TestPanicFollowsFailureMode(t *testing.T) {
	boom := fake.New(func(context.Context, *inspect.Request, []policy.Category) (classifier.Verdict, error) { panic("boom") })
	d := NewEngine(boom, policy.Default(), defaults, nil).Decide(ctx, &inspect.Request{}, src)
	if d.Outcome != FailOpen || d.Reason != classifier.ReasonPanic {
		t.Errorf("decision = %+v, want fail_open panic", d)
	}
}

func TestRedactsBeforeClassifyingAndObserving(t *testing.T) {
	f := verdict(1, "", 0)
	rec := &recorder{}
	in := &inspect.Request{Headers: map[string][]string{"authorization": {"Bearer secret"}}}
	NewEngine(f, policy.Default(), defaults, rec).Decide(ctx, in, src)
	if got := f.Last().Headers["authorization"][0]; got != redact.Mask {
		t.Errorf("classifier saw authorization %q", got)
	}
	if got := rec.reqs[0].Headers["authorization"][0]; got != redact.Mask {
		t.Errorf("observer saw authorization %q", got)
	}
	if in.Headers["authorization"][0] != "Bearer secret" {
		t.Error("Decide mutated the frontend's request")
	}
}

func TestDecisionFields(t *testing.T) {
	rec := &recorder{}
	e := NewEngine(verdict(1, "", 0), policy.Default(), defaults, rec)
	a := e.Decide(ctx, &inspect.Request{}, src)
	b := e.Decide(ctx, &inspect.Request{}, src)
	hex16 := regexp.MustCompile(`^[0-9a-f]{16}$`)
	if !hex16.MatchString(a.RequestID) || a.RequestID == b.RequestID {
		t.Errorf("request IDs %q, %q", a.RequestID, b.RequestID)
	}
	if a.Source != src || a.Route != "default" || len(rec.decisions) != 2 {
		t.Errorf("decision = %+v, observed %d", a, len(rec.decisions))
	}
}

func TestFail(t *testing.T) {
	p := policy.Default()
	p.Routes = []policy.Route{{Match: policy.Match{PathPrefix: "/admin"}, FailureMode: policy.FailClosed}}
	rec := &recorder{}
	e := NewEngine(verdict(1, "", 0), p, defaults, rec)
	if d := e.Fail(ctx, &inspect.Request{Path: "/admin"}, src, classifier.ReasonPanic); d.Outcome != FailClosed || d.Reason != classifier.ReasonPanic {
		t.Errorf("Fail(/admin) = %+v", d)
	}
	if d := e.Fail(ctx, nil, src, classifier.ReasonPanic); d.Outcome != FailOpen {
		t.Errorf("Fail(nil) = %+v", d)
	}
	if len(rec.decisions) != 2 {
		t.Errorf("observed %d decisions, want 2", len(rec.decisions))
	}
}

func TestDenied(t *testing.T) {
	for o, want := range map[Outcome]bool{Allow: false, Block: true, FailOpen: false, FailClosed: true} {
		if o.Denied() != want {
			t.Errorf("%q.Denied() = %v", o, !want)
		}
	}
}

func TestSetPolicyConcurrent(t *testing.T) {
	e := NewEngine(fake.Failing(errors.New("down")), policy.Default(), defaults, nil)
	closed := policy.Default()
	closed.Routes = []policy.Route{{Match: policy.Match{PathPrefix: "/"}, FailureMode: policy.FailClosed}}
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(2)
		go func() { defer wg.Done(); e.Decide(ctx, &inspect.Request{Path: "/"}, src) }()
		go func(i int) {
			defer wg.Done()
			if i%2 == 0 {
				e.SetPolicy(closed)
			} else {
				e.SetPolicy(policy.Default())
			}
		}(i)
	}
	wg.Wait()
}

func TestDebugHeader(t *testing.T) {
	cases := []struct {
		d    Decision
		want string
	}{
		{Decision{Outcome: Block, Classified: true, Verdict: classifier.Verdict{Benign: 0.045, Category: "injection", Confidence: 0.576}}, "block; attack_score=0.955; category=injection; confidence=0.576"},
		{Decision{Outcome: Allow, Classified: true, Verdict: classifier.Verdict{Benign: 0.97}}, "allow; attack_score=0.030"},
		{Decision{Outcome: FailClosed, Reason: classifier.ReasonTimeout}, "fail_closed; reason=timeout"},
		{Decision{Outcome: Block, Note: NoteOversize}, "block; reason=oversize"},
	}
	for _, c := range cases {
		if got := c.d.DebugHeader(); got != c.want {
			t.Errorf("DebugHeader = %q, want %q", got, c.want)
		}
	}
}

func TestDecideNoteAndBypass(t *testing.T) {
	rec := &recorder{}
	e := NewEngine(verdict(1, "", 0), policy.Default(), defaults, rec)
	d := e.DecideNote(ctx, &inspect.Request{Path: "/"}, src, NoteUninspectable)
	if !d.Classified || d.Outcome != Allow || d.Note != NoteUninspectable {
		t.Errorf("DecideNote = %+v", d)
	}
	f := verdict(1, "", 0)
	e = NewEngine(f, policy.Default(), defaults, rec)
	d = e.Bypass(ctx, &inspect.Request{Path: "/"}, src, Block, NoteOversize)
	if d.Classified || d.Outcome != Block || d.Note != NoteOversize || d.Route != "default" || f.Calls() != 0 {
		t.Errorf("Bypass = %+v, classifier calls = %d; want block oversize without classifying", d, f.Calls())
	}
	if len(rec.decisions) != 2 {
		t.Errorf("observed %d decisions, want 2", len(rec.decisions))
	}
}

func TestWithRequestID(t *testing.T) {
	e := NewEngine(verdict(1, "", 0), policy.Default(), defaults, nil)
	c := WithRequestID(ctx, "0123456789abcdef")
	if d := e.Decide(c, &inspect.Request{}, src); d.RequestID != "0123456789abcdef" {
		t.Errorf("Decide RequestID = %q", d.RequestID)
	}
	if d := e.Bypass(c, &inspect.Request{}, src, Allow, NoteOversize); d.RequestID != "0123456789abcdef" {
		t.Errorf("Bypass RequestID = %q", d.RequestID)
	}
	if d := e.Fail(c, nil, src, classifier.ReasonPanic); d.RequestID != "0123456789abcdef" {
		t.Errorf("Fail RequestID = %q", d.RequestID)
	}
}

func TestBadOutput(t *testing.T) {
	p := policy.Default()
	p.Routes = []policy.Route{{Match: policy.Match{PathPrefix: "/admin"}, FailureMode: policy.FailClosed}}
	offFormat := fake.Failing(classifier.Errorf(classifier.ReasonBadOutput, "unknown category"))
	for _, c := range []struct {
		action      policy.BadOutput
		open, admin Outcome
	}{
		{"", Block, Block},
		{policy.BadOutputBlock, Block, Block},
		{policy.BadOutputFailClosed, FailClosed, FailClosed},
		{policy.BadOutputFailureMode, FailOpen, FailClosed},
	} {
		e := NewEngine(offFormat, p, policy.Defaults{Threshold: 0.8, FailureMode: policy.FailOpen, BadOutput: c.action}, nil)
		for path, want := range map[string]Outcome{"/": c.open, "/admin": c.admin} {
			d := e.Decide(ctx, &inspect.Request{Path: path}, src)
			if d.Outcome != want || d.Classified || d.Reason != classifier.ReasonBadOutput {
				t.Errorf("%q %s: %+v, want %s with reason bad_output", c.action, path, d, want)
			}
		}
	}
	broken := NewEngine(fake.Failing(classifier.Errorf(classifier.ReasonBadResponse, "no choices")), p,
		policy.Defaults{Threshold: 0.8, FailureMode: policy.FailOpen, BadOutput: policy.BadOutputBlock}, nil)
	if d := broken.Decide(ctx, &inspect.Request{Path: "/"}, src); d.Outcome != FailOpen || d.Reason != classifier.ReasonBadResponse {
		t.Errorf("bad response: %+v, want fail_open (the failure mode)", d)
	}
}

func TestThresholdBoundaryIsInclusive(t *testing.T) {
	e := NewEngine(verdict(0.9, "injection", 0.1), policy.Default(), policy.Defaults{Threshold: 0.1, FailureMode: policy.FailOpen}, nil)
	if d := e.Decide(ctx, &inspect.Request{Path: "/"}, src); d.Outcome != Block {
		t.Errorf("attack score at the threshold: %s, want block", d.Outcome)
	}
}

func TestDecisionSpans(t *testing.T) {
	sr := tracetest.NewSpanRecorder()
	prev := otel.GetTracerProvider()
	otel.SetTracerProvider(sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(sr)))
	t.Cleanup(func() { otel.SetTracerProvider(prev) })

	down := NewEngine(fake.Failing(classifier.Errorf(classifier.ReasonUpstream5xx, "503")), policy.Default(), defaults, nil)
	down.Decide(ctx, &inspect.Request{Path: "/"}, src)
	down.Fail(ctx, &inspect.Request{Path: "/"}, src, classifier.ReasonProtocol)
	down.Bypass(ctx, &inspect.Request{Path: "/"}, src, Block, NoteOversize)

	spans := sr.Ended()
	if len(spans) < 3 {
		t.Fatalf("spans = %d, want one per decision", len(spans))
	}
	byReason := map[string]sdktrace.ReadOnlySpan{}
	for _, s := range spans {
		if s.Name() != "decision_waf.decide" {
			continue
		}
		for _, a := range s.Attributes() {
			if a.Key == "decision_waf.reason" {
				byReason[a.Value.AsString()] = s
			}
		}
	}
	for reason, wantErr := range map[string]bool{"upstream_5xx": true, "protocol_error": true, "oversize": false} {
		s, ok := byReason[reason]
		if !ok {
			t.Errorf("no decide span with reason %s", reason)
			continue
		}
		if isErr := s.Status().Code == otelcodes.Error; isErr != wantErr {
			t.Errorf("%s span status %v, want error %v", reason, s.Status(), wantErr)
		}
	}
	if s := byReason["upstream_5xx"]; s != nil && len(s.Events()) == 0 {
		t.Error("the classifier error was not recorded on the span")
	}
}

func TestNilRequestOnEveryPath(t *testing.T) {
	cls := verdict(1, "", 0)
	e := NewEngine(cls, policy.Default(), defaults, nil)
	if d := e.Decide(ctx, nil, src); d.Outcome != Allow || !d.Classified || cls.Last() == nil {
		t.Errorf("Decide(nil) = %+v, classifier saw %v; want an empty request classified", d, cls.Last())
	}
	if d := e.Fail(ctx, nil, src, classifier.ReasonPanic); d.Outcome != FailOpen {
		t.Errorf("Fail(nil) = %+v", d)
	}
	if d := e.Bypass(ctx, nil, src, Block, NoteMalformed); d.Outcome != Block {
		t.Errorf("Bypass(nil) = %+v", d)
	}
}

func TestSignalsReachThePrompt(t *testing.T) {
	cls := verdict(1, "", 0)
	e := NewEngine(cls, policy.Default(), defaults, nil)
	r := &inspect.Request{Method: "GET", Path: "/graphql", Query: "query=%7B+__schema+%7B+types+%7D+%7D", Protocol: "HTTP/2"}
	e.Decide(ctx, r, src)
	got := cls.Last()
	if got == nil || !slices.Contains(got.Signals, "protocol: HTTP/2") ||
		!slices.ContainsFunc(got.Signals, func(s string) bool {
			return strings.HasPrefix(s, "graphql: ") && strings.Contains(s, "introspection=yes")
		}) {
		t.Fatalf("classifier saw %+v", got)
	}
	if r.Signals != nil {
		t.Errorf("the frontend's request was changed: %q", r.Signals)
	}
}

func TestLimitBlocksWithoutTheClassifier(t *testing.T) {
	p, err := policy.Parse([]byte("limits:\n  graphql: { introspection: block }\n"))
	if err != nil {
		t.Fatal(err)
	}
	cls := verdict(1, "", 0)
	e := NewEngine(cls, p, defaults, nil)
	d := e.Decide(ctx, &inspect.Request{Method: "GET", Path: "/graphql", Query: "query=%7B+__schema+%7B+types+%7D+%7D"}, src)
	if d.Outcome != Block || d.Note != NoteLimit || d.Limit != "graphql_introspection" || d.ClassifierCalled || cls.Calls() != 0 {
		t.Errorf("decision %+v, classifier calls %d; want a limit block without the classifier", d, cls.Calls())
	}
	if d := e.Decide(ctx, &inspect.Request{Method: "GET", Path: "/graphql", Query: "query=%7B+a+%7D"}, src); d.Outcome != Allow || cls.Calls() != 1 {
		t.Errorf("a query under the limits: %+v", d)
	}
}

var smugglingReq = &inspect.Request{Method: "POST", Path: "/", Headers: map[string][]string{"transfer-encoding": {"chunked"}, "content-length": {"5"}}}

func smugglingEngine(t *testing.T, mode policy.FailureMode) *Engine {
	t.Helper()
	p, err := policy.Parse([]byte("limits:\n  smuggling: block\n"))
	if err != nil {
		t.Fatal(err)
	}
	return NewEngine(verdict(1, "", 0), p, policy.Defaults{Threshold: 0.8, FailureMode: mode}, nil)
}

func TestBypassAllowStillAppliesLimits(t *testing.T) {
	d := smugglingEngine(t, policy.FailOpen).Bypass(ctx, smugglingReq, src, Allow, NoteOversize)
	if d.Outcome != Block || d.Note != NoteLimit || d.Limit != "smuggling" {
		t.Errorf("decision %+v; want a smuggling limit block", d)
	}
}

func TestFailOpenStillAppliesLimits(t *testing.T) {
	d := smugglingEngine(t, policy.FailOpen).Fail(ctx, smugglingReq, src, classifier.ReasonPanic)
	if d.Outcome != Block || d.Note != NoteLimit || d.Limit != "smuggling" {
		t.Errorf("decision %+v; want a smuggling limit block", d)
	}
	if d := smugglingEngine(t, policy.FailClosed).Fail(ctx, smugglingReq, src, classifier.ReasonPanic); d.Outcome != FailClosed || d.Note == NoteLimit {
		t.Errorf("fail_closed decision %+v; want it left as it was", d)
	}
}

func TestBypassBlockKeepsItsNote(t *testing.T) {
	d := smugglingEngine(t, policy.FailOpen).Bypass(ctx, smugglingReq, src, Block, NoteMalformed)
	if d.Outcome != Block || d.Note != NoteMalformed || d.Limit != "" {
		t.Errorf("decision %+v; want the malformed block unchanged", d)
	}
}
