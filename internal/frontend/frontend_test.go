package frontend

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"

	"github.com/0x4272616E646F6E/decision-waf/internal/classifier"
	"github.com/0x4272616E646F6E/decision-waf/internal/classifier/fake"
	"github.com/0x4272616E646F6E/decision-waf/internal/decision"
	"github.com/0x4272616E646F6E/decision-waf/internal/frontend/frontendtest"
	"github.com/0x4272616E646F6E/decision-waf/internal/inspect"
	"github.com/0x4272616E646F6E/decision-waf/internal/policy"
)

func TestDenialFor(t *testing.T) {
	cases := []struct {
		d     decision.Decision
		http  int
		grpc  codes.Code
		error string
	}{
		{decision.Decision{Outcome: decision.Block, Classified: true, Verdict: classifier.Verdict{Benign: 0}}, 403, codes.PermissionDenied, "request blocked"},
		{decision.Decision{Outcome: decision.Block, Classified: true, ClassifierCalled: true, Note: decision.NoteOversize}, 403, codes.PermissionDenied, "request blocked"},
		{decision.Decision{Outcome: decision.FailClosed, Reason: classifier.ReasonTimeout}, 503, codes.Unavailable, "service unavailable"},
		{decision.Decision{Outcome: decision.Block, Note: decision.NoteOversize}, 413, codes.ResourceExhausted, "request too large"},
		{decision.Decision{Outcome: decision.Block, Note: decision.NoteUninspectable}, 413, codes.ResourceExhausted, "request too large"},
		{decision.Decision{Outcome: decision.Block, Note: decision.NoteMessageLimit}, 413, codes.ResourceExhausted, "request too large"},
		{decision.Decision{Outcome: decision.Block, Note: decision.NoteLimit, Limit: "graphql_depth"}, 403, codes.PermissionDenied, "request blocked"},
		{decision.Decision{Outcome: decision.Block, Note: decision.NoteMalformed}, 400, codes.InvalidArgument, "malformed request"},
		{decision.Decision{Outcome: decision.Block, Note: decision.NoteOversize, ClassifierCalled: true, Reason: classifier.ReasonBadOutput}, 403, codes.PermissionDenied, "request blocked"},
	}
	for _, c := range cases {
		dn := DenialFor(c.d)
		if dn.HTTPStatus != c.http || dn.GRPCStatus != c.grpc {
			t.Errorf("DenialFor(%+v) = %+v", c.d, dn)
		}
		var body map[string]string
		if err := json.Unmarshal(dn.Body("abc"), &body); err != nil || body["error"] != c.error || body["request_id"] != "abc" || len(body) != 2 {
			t.Errorf("body = %v (%v)", body, err)
		}
	}
}

func TestLastForwardedHop(t *testing.T) {
	cases := []struct {
		name string
		xff  []string
		want string
	}{
		{"last hop of the last header", []string{"9.9.9.9", "6.6.6.6, 10.0.0.2"}, "10.0.0.2"},
		{"port stripped", []string{"6.6.6.6, 10.0.0.2:5678"}, "10.0.0.2"},
		{"ipv6 with port", []string{"[2001:db8::1]:443"}, "2001:db8::1"},
		{"ipv6 with a zone", []string{"fe80::1%eth0"}, "fe80::1%eth0"},
		{"ipv6 with a zone and port", []string{"[fe80::1%eth0]:443"}, "fe80::1%eth0"},
		{"bracketed ipv6", []string{"[2001:db8::1]"}, "2001:db8::1"},
		{"invalid last hop is not skipped", []string{"1.2.3.4, junk"}, ""},
		{"none", nil, ""},
	}
	for _, c := range cases {
		if got := LastForwardedHop(c.xff); got != c.want {
			t.Errorf("%s: LastForwardedHop(%q) = %q, want %q", c.name, c.xff, got, c.want)
		}
	}
}

func engine(failure policy.FailureMode, obs decision.Observer) *decision.Engine {
	return frontendtest.Engine(fake.Attacks(), failure, obs)
}

var src = decision.Source{Frontend: "test", Mode: inspect.ModeLite}

func decide(t *testing.T, e *decision.Engine, path string) decision.Decision {
	t.Helper()
	r := &inspect.Request{Method: "GET", Path: path}
	return Decide(context.Background(), e, src, slog.New(slog.DiscardHandler),
		func() *inspect.Request { return r },
		func(ctx context.Context, r *inspect.Request) decision.Decision { return e.Decide(ctx, r, src) })
}

func TestDecideReturnsTheDecision(t *testing.T) {
	e := engine(policy.FailOpen, nil)
	if d := decide(t, e, "/ok"); d.Outcome != decision.Allow {
		t.Errorf("outcome = %s, want allow", d.Outcome)
	}
	if d := decide(t, e, "/attack"); d.Outcome != decision.Block {
		t.Errorf("outcome = %s, want block", d.Outcome)
	}
}

func TestDecideKeepsADenialAlreadyTaken(t *testing.T) {
	d := decide(t, engine(policy.FailOpen, frontendtest.PanicObserver{OnBlock: true}), "/attack")
	if d.Outcome != decision.Block {
		t.Errorf("outcome = %s, want the block the engine had taken", d.Outcome)
	}
}

func TestDecideSurvivesAPanicDuringRecovery(t *testing.T) {
	for _, c := range []struct {
		failure policy.FailureMode
		want    decision.Outcome
	}{{policy.FailOpen, decision.FailOpen}, {policy.FailClosed, decision.FailClosed}} {
		d := decide(t, engine(c.failure, frontendtest.PanicObserver{Always: true}), "/ok")
		if d.Outcome != c.want || d.Reason != classifier.ReasonPanic || d.RequestID == "" || d.Source != src {
			t.Errorf("%s route: decision = %+v, want %s with reason panic, a request ID, and the source", c.failure, d, c.want)
		}
	}
}

func TestDecidePanicBeforeTheEngine(t *testing.T) {
	e := engine(policy.FailClosed, nil)
	d := Decide(context.Background(), e, src, slog.New(slog.DiscardHandler),
		func() *inspect.Request { panic("bad request") },
		func(context.Context, *inspect.Request) decision.Decision {
			t.Fatal("decide ran after build panicked")
			return decision.Decision{}
		})
	if d.Outcome != decision.FailClosed || d.Reason != classifier.ReasonPanic {
		t.Errorf("decision = %+v, want fail_closed with reason panic", d)
	}
}

func TestDecideKeepsAComputedFailClosed(t *testing.T) {
	failing := fake.Failing(classifier.Errorf(classifier.ReasonUpstream5xx, "503"))
	e := frontendtest.Engine(failing, policy.FailClosed, frontendtest.PanicObserver{Always: true})
	d := decide(t, e, "/ok")
	if d.Outcome != decision.FailClosed || d.Reason != classifier.ReasonUpstream5xx {
		t.Errorf("decision = %+v, want the computed fail_closed with reason upstream_5xx", d)
	}
}

func TestDecideBlocksSeveralContentTypes(t *testing.T) {
	e := engine(policy.FailOpen, nil)
	r := &inspect.Request{Method: "POST", Path: "/ok", Headers: map[string][]string{"content-type": {"text/plain", "application/grpc"}}}
	d := Decide(context.Background(), e, src, slog.New(slog.DiscardHandler),
		func() *inspect.Request { return r },
		func(context.Context, *inspect.Request) decision.Decision {
			t.Fatal("decide ran for a malformed request")
			return decision.Decision{}
		})
	if d.Outcome != decision.Block || d.Note != decision.NoteMalformed || d.Classified {
		t.Errorf("decision = %+v, want an unclassified block with note malformed", d)
	}
}

func TestTakeJA4(t *testing.T) {
	fp := "t13d1516h2_8daaf6152771_b186095e22b6"
	cases := []struct {
		name    string
		header  string
		values  []string
		want    string
		removed bool
	}{
		{"off", "", []string{fp}, "", false},
		{"set", "x-decision-waf-ja4", []string{fp}, fp, true},
		{"no tls", "x-decision-waf-ja4", []string{"-"}, "", true},
		{"two values", "x-decision-waf-ja4", []string{fp, "forged"}, "", true},
		{"absent", "x-decision-waf-ja4", nil, "", false},
	}
	for _, c := range cases {
		h := map[string][]string{}
		if c.values != nil {
			h["x-decision-waf-ja4"] = c.values
		}
		got := TakeJA4(h, c.header)
		_, still := h["x-decision-waf-ja4"]
		if got != c.want || still == c.removed && c.values != nil {
			t.Errorf("%s: got %q, header kept %v", c.name, got, still)
		}
	}
}

func TestLiteOnly(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	calls := 0
	LiteOnly(inspect.ModeLite, func() { calls++ }, log, "lite only")()
	if calls != 0 || buf.Len() != 0 {
		t.Errorf("lite: calls = %d, log = %q; want neither", calls, buf.String())
	}
	hook := LiteOnly(inspect.ModeDeep, func() { calls++ }, log, "lite only")
	hook()
	hook()
	if calls != 2 || strings.Count(buf.String(), "lite only") != 1 || !strings.Contains(buf.String(), "configured_mode=deep") {
		t.Errorf("deep: calls = %d, log = %q; want 2 calls and one warning", calls, buf.String())
	}
	LiteOnly(inspect.ModeStandard, nil, log, "lite only")()
}
