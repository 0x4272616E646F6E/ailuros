package extproc

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	filterv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/0x4272616E646F6E/decision-waf/internal/classifier"
	"github.com/0x4272616E646F6E/decision-waf/internal/classifier/fake"
	"github.com/0x4272616E646F6E/decision-waf/internal/frontend/frontendtest"
	"github.com/0x4272616E646F6E/decision-waf/internal/inspect"
	"github.com/0x4272616E646F6E/decision-waf/internal/policy"
)

var (
	lite     = Config{Mode: inspect.ModeLite, BodyMaxBytes: 65536, DeepMaxBytes: 1 << 20, DeepOversize: inspect.OversizeClassifyPrefix}
	standard = Config{Mode: inspect.ModeStandard, BodyMaxBytes: 65536, DeepMaxBytes: 1 << 20, DeepOversize: inspect.OversizeClassifyPrefix}
)

func TestLiteAllowAddsRequestID(t *testing.T) {
	f := fake.Attacks()
	h := newHarness(t, f, lite, policy.FailOpen)
	s := h.open()
	send(t, s, withAttributes(headersMsg(false, with(httpHeaders, "x-forwarded-for", "6.6.6.6", "user-agent", "curl/8.9")...), map[string]any{
		"source.address": "203.0.113.9:51234", "connection.requested_server_name": "shop.example.com", "connection.tls_version": "TLSv1.3", "request.protocol": "HTTP/2",
	}))
	got := mutationHeaders(t, recv(t, s))
	if !hex16.MatchString(got["x-decision-waf-request-id"]) || len(got) != 1 {
		t.Errorf("header mutation = %v, want only x-decision-waf-request-id", got)
	}
	r := f.Last()
	if r.Method != "POST" || r.Scheme != "https" || r.Host != "shop.example.com" || r.Path != "/api/cart" || r.Query != "id=7" ||
		r.ClientIP != "203.0.113.9" || r.TLS == nil || r.TLS.SNI != "shop.example.com" || r.TLS.Version != "TLSv1.3" || r.Protocol != "HTTP/2" ||
		r.Headers["user-agent"][0] != "curl/8.9" || r.Body != nil {
		t.Errorf("request = %+v", r)
	}
	if _, ok := r.Headers[":path"]; ok {
		t.Error("pseudo-header passed to the classifier as a header")
	}
	if d := h.obs.All(); len(d) != 1 || d[0].RequestID != got["x-decision-waf-request-id"] || d[0].Source.Frontend != "extproc" {
		t.Errorf("decisions = %+v", d)
	}
}

func TestHeaderValuesInValueField(t *testing.T) {
	f := fake.Attacks()
	h := newHarness(t, f, lite, policy.FailOpen)
	s := h.open()
	msg := headersMsg(false)
	for i := 0; i < len(httpHeaders); i += 2 {
		hv := &corev3.HeaderValue{Key: httpHeaders[i], Value: httpHeaders[i+1]}
		msg.GetRequestHeaders().Headers.Headers = append(msg.GetRequestHeaders().Headers.Headers, hv)
	}
	send(t, s, msg)
	recv(t, s)
	if r := f.Last(); r.Method != "POST" || r.Path != "/api/cart" || r.Host != "shop.example.com" || r.Headers["content-type"][0] != "application/json" {
		t.Errorf("request = %+v", r)
	}
}

func TestClientIPFallsBackToLastForwardedHop(t *testing.T) {
	f := fake.Attacks()
	h := newHarness(t, f, lite, policy.FailOpen)
	s := h.open()
	send(t, s, headersMsg(false, with(httpHeaders, "x-forwarded-for", "6.6.6.6, 198.51.100.7")...))
	recv(t, s)
	if got := f.Last().ClientIP; got != "198.51.100.7" {
		t.Errorf("ClientIP = %q, want last XFF hop", got)
	}
}

func TestLiteDenials(t *testing.T) {
	cases := []struct {
		name     string
		c        classifier.Classifier
		failure  policy.FailureMode
		headers  []string
		status   int
		grpc     uint32
		errorMsg string
	}{
		{"block", fake.Attacks(), policy.FailOpen, with(httpHeaders[:6], ":path", "/attack"), 403, 0, "request blocked"},
		{"fail closed", fake.Failing(errors.New("down")), policy.FailClosed, httpHeaders, 503, 0, "service unavailable"},
		{"grpc block", fake.Returning(classifier.Verdict{Benign: 0, Category: "sqli", Confidence: 1}), policy.FailOpen, grpcHeaders, 403, 7, "request blocked"},
		{"grpc fail closed", fake.Failing(errors.New("down")), policy.FailClosed, grpcHeaders, 503, 14, "service unavailable"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t, c.c, lite, c.failure)
			s := h.open()
			send(t, s, headersMsg(false, c.headers...))
			expectImmediate(t, recv(t, s), c.status, c.grpc, c.errorMsg)
			if _, err := s.Recv(); err == nil {
				t.Error("stream still open after ImmediateResponse")
			}
		})
	}
}

func TestLiteFailOpenContinues(t *testing.T) {
	h := newHarness(t, fake.Failing(errors.New("down")), lite, policy.FailOpen)
	s := h.open()
	send(t, s, headersMsg(false, httpHeaders...))
	if got := mutationHeaders(t, recv(t, s)); !hex16.MatchString(got["x-decision-waf-request-id"]) {
		t.Errorf("header mutation = %v", got)
	}
}

func TestExposeVerdictHeader(t *testing.T) {
	cfg := lite
	cfg.ExposeVerdict = true
	h := newHarness(t, fake.Returning(classifier.Verdict{Benign: 0.97, Category: "sqli", Confidence: 0.02}), cfg, policy.FailOpen)
	s := h.open()
	send(t, s, headersMsg(false, httpHeaders...))
	if got := mutationHeaders(t, recv(t, s))["x-decision-waf-decision"]; got != "allow; attack_score=0.030; category=sqli; confidence=0.020" {
		t.Errorf("x-decision-waf-decision = %q", got)
	}
}

func TestLiteIgnoresBody(t *testing.T) {
	f := fake.Attacks()
	h := newHarness(t, f, lite, policy.FailOpen)
	s := h.open()
	send(t, s, headersMsg(false, httpHeaders...))
	recv(t, s)
	send(t, s, bodyMsg([]byte("attack"), true))
	r := recv(t, s)
	if r.GetRequestBody() == nil || r.GetRequestBody().GetResponse().GetStatus() != extprocv3.CommonResponse_CONTINUE {
		t.Errorf("response = %v, want body CONTINUE", r)
	}
	if f.Calls() != 1 {
		t.Errorf("classifier calls = %d, want 1 (body ignored in lite)", f.Calls())
	}
}

func TestStandardClassifiesBufferedBody(t *testing.T) {
	f := fake.Attacks()
	h := newHarness(t, f, standard, policy.FailOpen)
	s := h.open()
	send(t, s, headersMsg(false, httpHeaders...))
	if got := mutationHeaders(t, recv(t, s)); len(got) != 0 || f.Calls() != 0 {
		t.Fatalf("headers response mutation = %v, classifier calls = %d; want no decision yet", got, f.Calls())
	}
	send(t, s, bodyMsg([]byte(`{"item":1}`), true))
	got := mutationHeaders(t, recv(t, s))
	if !hex16.MatchString(got["x-decision-waf-request-id"]) {
		t.Errorf("body response mutation = %v", got)
	}
	if r := f.Last(); string(r.Body) != `{"item":1}` || r.BodyTruncated || f.Calls() != 1 {
		t.Errorf("classified body %q truncated=%v calls=%d", r.Body, r.BodyTruncated, f.Calls())
	}
}

func TestStandardTruncation(t *testing.T) {
	cases := []struct {
		name string
		body string
		eos  bool
		want string
	}{
		{"over the cap", "0123456789abcdef", true, "01234567"},
		{"Envoy buffer full", "0123", false, "0123"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := standard
			cfg.BodyMaxBytes = 8
			f := fake.Attacks()
			h := newHarness(t, f, cfg, policy.FailOpen)
			s := h.open()
			send(t, s, headersMsg(false, httpHeaders...))
			recv(t, s)
			send(t, s, bodyMsg([]byte(c.body), c.eos))
			recv(t, s)
			if r := f.Last(); string(r.Body) != c.want || !r.BodyTruncated {
				t.Errorf("body = %q truncated = %v; want %q truncated", r.Body, r.BodyTruncated, c.want)
			}
		})
	}
}

func TestStandardBlocksOnBody(t *testing.T) {
	h := newHarness(t, fake.Attacks(), standard, policy.FailOpen)
	s := h.open()
	send(t, s, headersMsg(false, httpHeaders...))
	recv(t, s)
	send(t, s, bodyMsg([]byte(`{"q":"attack"}`), true))
	expectImmediate(t, recv(t, s), 403, 0, "request blocked")
}

func TestStandardHeadersOnlyRequest(t *testing.T) {
	f := fake.Attacks()
	h := newHarness(t, f, standard, policy.FailOpen)
	s := h.open()
	send(t, s, headersMsg(true, ":method", "GET", ":path", "/", ":authority", "a"))
	if got := mutationHeaders(t, recv(t, s)); !hex16.MatchString(got["x-decision-waf-request-id"]) || f.Calls() != 1 {
		t.Errorf("mutation = %v, calls = %d; want a decision on headers", got, f.Calls())
	}
	if h.downgrades.Load() != 0 {
		t.Error("a request without a body was counted as a mode downgrade")
	}
}

func TestModeMismatchDowngrades(t *testing.T) {
	protocol := func(m *extprocv3.ProcessingRequest, mode filterv3.ProcessingMode_BodySendMode) *extprocv3.ProcessingRequest {
		m.ProtocolConfig = &extprocv3.ProtocolConfiguration{RequestBodyMode: mode}
		return m
	}
	cases := []struct {
		name string
		cfg  Config
		msg  *extprocv3.ProcessingRequest
	}{
		{"headers end the stream but content-length > 0", standard, headersMsg(true, with(httpHeaders, "content-length", "10")...)},
		{"protocol_config NONE in standard", standard, protocol(headersMsg(false, httpHeaders...), filterv3.ProcessingMode_NONE)},
		{"protocol_config BUFFERED_PARTIAL in deep", Config{Mode: inspect.ModeDeep, BodyMaxBytes: 65536, DeepMaxBytes: 1 << 20, DeepOversize: inspect.OversizeClassifyPrefix},
			protocol(headersMsg(false, httpHeaders...), filterv3.ProcessingMode_BUFFERED_PARTIAL)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := fake.Attacks()
			h := newHarness(t, f, c.cfg, policy.FailOpen)
			s := h.open()
			send(t, s, c.msg)
			if got := mutationHeaders(t, recv(t, s)); !hex16.MatchString(got["x-decision-waf-request-id"]) || f.Calls() != 1 {
				t.Errorf("mutation = %v, calls = %d; want a headers-only decision", got, f.Calls())
			}
			if h.downgrades.Load() != 1 {
				t.Errorf("downgrades = %d, want 1", h.downgrades.Load())
			}
			if d := h.obs.All(); d[0].Source.Mode != inspect.ModeLite {
				t.Errorf("logged mode = %q, want lite", d[0].Source.Mode)
			}
		})
	}
	t.Run("protocol_config matching", func(t *testing.T) {
		h := newHarness(t, fake.Attacks(), standard, policy.FailOpen)
		s := h.open()
		send(t, s, protocol(headersMsg(false, httpHeaders...), filterv3.ProcessingMode_BUFFERED_PARTIAL))
		recv(t, s)
		if h.downgrades.Load() != 0 {
			t.Error("matching body mode counted as a downgrade")
		}
	})
}

func TestBodyAfterEndOfStreamIgnored(t *testing.T) {
	f := fake.Attacks()
	h := newHarness(t, f, standard, policy.FailOpen)
	s := h.open()
	send(t, s, headersMsg(false, httpHeaders...))
	recv(t, s)
	send(t, s, bodyMsg([]byte("x"), true))
	recv(t, s)
	send(t, s, bodyMsg([]byte("x"), true))
	expectEnd(t, s)
	if f.Calls() != 1 {
		t.Errorf("classifier calls = %d, want 1", f.Calls())
	}
}

func TestResponsePhasePassesThrough(t *testing.T) {
	h := newHarness(t, fake.Attacks(), lite, policy.FailOpen)
	s := h.open()
	send(t, s, headersMsg(false, httpHeaders...))
	recv(t, s)
	send(t, s, &extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_ResponseHeaders{ResponseHeaders: &extprocv3.HttpHeaders{}}})
	if r := recv(t, s); r.GetResponseHeaders() == nil {
		t.Errorf("response = %v, want response-headers CONTINUE", r)
	}
}

func TestBodyBeforeHeadersFollowsFailureMode(t *testing.T) {
	h := newHarness(t, fake.Attacks(), standard, policy.FailClosed)
	s := h.open()
	send(t, s, bodyMsg([]byte("x"), true))
	expectImmediate(t, recv(t, s), 503, 0, "service unavailable")
	if d := h.obs.All(); len(d) != 1 || d[0].Reason != classifier.ReasonProtocol {
		t.Errorf("decisions = %+v, want one protocol_error", d)
	}
}

func TestIncomingDeadlineShorterThanClassifierTimeout(t *testing.T) {
	hang := fake.New(func(ctx context.Context, _ *inspect.Request, _ []policy.Category) (classifier.Verdict, error) {
		<-ctx.Done()
		return classifier.Verdict{}, ctx.Err()
	})
	h := newHarness(t, hang, lite, policy.FailClosed)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	s := h.openCtx(ctx)
	start := time.Now()
	send(t, s, headersMsg(false, httpHeaders...))
	expectImmediate(t, recv(t, s), 503, 0, "service unavailable")
	if elapsed := time.Since(start); elapsed >= 300*time.Millisecond {
		t.Errorf("answered after %v, not before the 300ms deadline", elapsed)
	}
	if d := h.obs.All(); len(d) != 1 || d[0].Reason != classifier.ReasonTimeout {
		t.Errorf("decisions = %+v, want one timeout", d)
	}
}

type resetStream struct {
	grpc.ServerStream
	ctx  context.Context
	msgs []*extprocv3.ProcessingRequest
	sent []*extprocv3.ProcessingResponse
}

func (s *resetStream) Context() context.Context { return s.ctx }

func (s *resetStream) Recv() (*extprocv3.ProcessingRequest, error) {
	if len(s.msgs) > 0 {
		m := s.msgs[0]
		s.msgs = s.msgs[1:]
		return m, nil
	}
	<-s.ctx.Done()
	return nil, status.FromContextError(s.ctx.Err()).Err()
}

func (s *resetStream) Send(r *extprocv3.ProcessingResponse) error {
	s.sent = append(s.sent, r)
	return nil
}

func TestStreamResetStopsWithoutAnswer(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hang := fake.New(func(ctx context.Context, _ *inspect.Request, _ []policy.Category) (classifier.Verdict, error) {
		cancel()
		<-ctx.Done()
		return classifier.Verdict{}, ctx.Err()
	})
	obs := &frontendtest.Recorder{}
	srv := New(frontendtest.Engine(hang, policy.FailClosed, obs), lite, nil, slog.New(slog.DiscardHandler))
	ps := &resetStream{ctx: ctx, msgs: []*extprocv3.ProcessingRequest{headersMsg(false, httpHeaders...)}}
	err := srv.Process(ps)
	if status.Code(err) != codes.Canceled || len(ps.sent) != 0 {
		t.Errorf("Process = %v, sent %d responses; want canceled and nothing sent", err, len(ps.sent))
	}
	if d := obs.All(); len(d) != 1 || d[0].Reason != classifier.ReasonCanceled {
		t.Errorf("decisions = %+v, want one canceled", d)
	}
}

func TestDecisionUsesStreamDeadlineMargin(t *testing.T) {
	remaining := make(chan time.Duration, 1)
	f := fake.New(func(ctx context.Context, _ *inspect.Request, _ []policy.Category) (classifier.Verdict, error) {
		dl, _ := ctx.Deadline()
		remaining <- time.Until(dl)
		return classifier.Verdict{Benign: 1}, nil
	})
	h := newHarness(t, f, lite, policy.FailOpen)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	s := h.openCtx(ctx)
	send(t, s, headersMsg(false, httpHeaders...))
	recv(t, s)
	if got := <-remaining; got <= 0 || got > time.Second-40*time.Millisecond {
		t.Errorf("classifier deadline in %v, want at least 50ms before the 1s call deadline", got)
	}
}

func TestPanicFollowsFailureMode(t *testing.T) {
	cases := []struct {
		failure policy.FailureMode
		closed  bool
	}{{policy.FailClosed, true}, {policy.FailOpen, false}}
	for _, c := range cases {
		t.Run(string(c.failure), func(t *testing.T) {
			h := newHarness(t, fake.Attacks(), lite, c.failure)
			h.obs.PanicNext.Store(true)
			s := h.open()
			send(t, s, headersMsg(false, httpHeaders...))
			r := recv(t, s)
			if c.closed {
				expectImmediate(t, r, 503, 0, "service unavailable")
			} else if got := mutationHeaders(t, r); !hex16.MatchString(got["x-decision-waf-request-id"]) {
				t.Errorf("fail_open mutation = %v", got)
			}
			if d := h.obs.All(); len(d) != 1 || d[0].Reason != classifier.ReasonPanic {
				t.Errorf("decisions = %+v, want one panic", d)
			}
		})
	}
}

func TestPanicDuringRecoveryClosedAnswersStatically(t *testing.T) {
	h := newHarness(t, fake.Attacks(), lite, policy.FailClosed)
	h.obs.PanicAlways.Store(true)
	s := h.open()
	send(t, s, headersMsg(false, httpHeaders...))
	expectImmediate(t, recv(t, s), 503, 0, "service unavailable")
	g := h.open()
	send(t, g, headersMsg(false, grpcHeaders...))
	expectImmediate(t, recv(t, g), 503, 14, "service unavailable")
	h.obs.PanicAlways.Store(false)
	s2 := h.open()
	send(t, s2, headersMsg(false, httpHeaders...))
	if got := mutationHeaders(t, recv(t, s2)); !hex16.MatchString(got["x-decision-waf-request-id"]) {
		t.Errorf("mutation = %v", got)
	}
}

func TestPanicDuringRecoveryOpenLetsRequestThrough(t *testing.T) {
	h := newHarness(t, fake.Attacks(), lite, policy.FailOpen)
	h.obs.PanicAlways.Store(true)
	s := h.open()
	send(t, s, headersMsg(false, httpHeaders...))
	r, err := s.Recv()
	if err != nil {
		t.Fatalf("Recv: %v, want the request let through, not a stream reset", err)
	}
	if r.GetRequestHeaders() == nil {
		t.Fatalf("response = %v, want a request-headers continue", r)
	}
	if got := mutationHeaders(t, r); !hex16.MatchString(got["x-decision-waf-request-id"]) {
		t.Errorf("fail_open mutation = %v, want an x-decision-waf-request-id", got)
	}
	h.obs.PanicAlways.Store(false)
	s2 := h.open()
	send(t, s2, headersMsg(false, httpHeaders...))
	mutationHeaders(t, recv(t, s2))
}

func TestPanicDuringRecoveryOpenReleasesHeldDeepBody(t *testing.T) {
	h := newHarness(t, fake.Attacks(), deep(1<<20, inspect.OversizeClassifyPrefix), policy.FailOpen)
	s := h.open()
	send(t, s, headersMsg(false, httpHeaders...))
	recv(t, s)
	h.obs.PanicAlways.Store(true)
	body := []byte("hello held body")
	send(t, s, bodyMsg(body, true))
	got, eos := streamed(t, s, 1)
	if !bytes.Equal(got, body) || !eos {
		t.Errorf("upstream got %q (eos %v), want the held body released", got, eos)
	}
}

func TestObserverPanicAfterBlockStillBlocks(t *testing.T) {
	h := newHarness(t, fake.Attacks(), lite, policy.FailOpen)
	h.obs.PanicOnBlock.Store(true)
	s := h.open()
	send(t, s, headersMsg(false, with(httpHeaders[:6], ":path", "/attack")...))
	expectImmediate(t, recv(t, s), 403, 0, "request blocked")
}

func TestExpiredDeadlineSkipsClassifier(t *testing.T) {
	f := fake.Attacks()
	h := newHarness(t, f, lite, policy.FailClosed)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	s := h.openCtx(ctx)
	send(t, s, headersMsg(false, httpHeaders...))
	expectImmediate(t, recv(t, s), 503, 0, "service unavailable")
	if f.Calls() != 0 {
		t.Errorf("classifier calls = %d, want 0 past the deadline margin", f.Calls())
	}
	if d := h.obs.All(); len(d) != 1 || d[0].Reason != classifier.ReasonTimeout {
		t.Errorf("decisions = %+v, want one timeout", d)
	}
}

func TestUndecidedStreamCountsAsDowngrade(t *testing.T) {
	t.Run("standard stream ends after headers", func(t *testing.T) {
		h := newHarness(t, fake.Attacks(), standard, policy.FailOpen)
		s := h.open()
		send(t, s, headersMsg(false, httpHeaders...))
		recv(t, s)
		expectEnd(t, s)
		waitFor(t, func() bool { return h.downgrades.Load() == 1 })
	})
	t.Run("a client that goes away is not a mismatch when Envoy stated its body mode", func(t *testing.T) {
		h := newHarness(t, fake.Attacks(), standard, policy.FailOpen)
		ctx, cancel := context.WithCancel(context.Background())
		s := h.openCtx(ctx)
		m := headersMsg(false, httpHeaders...)
		m.ProtocolConfig = &extprocv3.ProtocolConfiguration{RequestBodyMode: filterv3.ProcessingMode_BUFFERED_PARTIAL}
		send(t, s, m)
		recv(t, s)
		cancel()
		time.Sleep(100 * time.Millisecond)
		if n := h.downgrades.Load(); n != 0 {
			t.Errorf("downgrades = %d, want 0", n)
		}
	})
	t.Run("stream reset counts too", func(t *testing.T) {
		h := newHarness(t, fake.Attacks(), standard, policy.FailOpen)
		ctx, cancel := context.WithCancel(context.Background())
		s := h.openCtx(ctx)
		send(t, s, headersMsg(false, httpHeaders...))
		recv(t, s)
		cancel()
		waitFor(t, func() bool { return h.downgrades.Load() == 1 })
	})
	t.Run("decided and lite streams do not count", func(t *testing.T) {
		h := newHarness(t, fake.Attacks(), standard, policy.FailOpen)
		s := h.open()
		send(t, s, headersMsg(false, httpHeaders...), bodyMsg([]byte("x"), true))
		recv(t, s)
		recv(t, s)
		expectEnd(t, s)
		l := newHarness(t, fake.Attacks(), lite, policy.FailOpen)
		s2 := l.open()
		send(t, s2, headersMsg(false, httpHeaders...))
		recv(t, s2)
		expectEnd(t, s2)
		time.Sleep(50 * time.Millisecond)
		if h.downgrades.Load() != 0 || l.downgrades.Load() != 0 {
			t.Errorf("downgrades = %d, %d; want 0", h.downgrades.Load(), l.downgrades.Load())
		}
	})
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met within 2s")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestJA4Header(t *testing.T) {
	fp := "t13d1516h2_8daaf6152771_b186095e22b6"
	for _, c := range []struct {
		name, header, want string
		kept               bool
	}{
		{"on", "x-decision-waf-ja4", fp, false},
		{"off", "", "", true},
	} {
		f := fake.Attacks()
		cfg := lite
		cfg.JA4Header = c.header
		h := newHarness(t, f, cfg, policy.FailOpen)
		s := h.open()
		send(t, s, headersMsg(false, with(httpHeaders, "x-decision-waf-ja4", fp)...))
		recv(t, s)
		r := f.Last()
		if _, kept := r.Headers["x-decision-waf-ja4"]; r.JA4 != c.want || kept != c.kept {
			t.Errorf("%s: JA4 %q, header kept %v", c.name, r.JA4, kept)
		}
	}
}

func TestWebSocketHandshakeDecidedOnHeaders(t *testing.T) {
	for name, cfg := range map[string]Config{"standard": standard, "deep": deep(1<<20, inspect.OversizeClassifyPrefix)} {
		t.Run(name, func(t *testing.T) {
			f := fake.Attacks()
			h := newHarness(t, f, cfg, policy.FailOpen)
			s := h.open()
			send(t, s, headersMsg(false, ":method", "GET", ":path", "/ws", ":authority", "a.example",
				"upgrade", "websocket", "connection", "Upgrade", "sec-websocket-version", "13", "sec-websocket-key", "websocket-test-key"))
			if got := mutationHeaders(t, recv(t, s)); !hex16.MatchString(got["x-decision-waf-request-id"]) || f.Calls() != 1 {
				t.Errorf("mutation = %v, calls = %d; want a decision on the headers alone", got, f.Calls())
			}
		})
	}
}

func TestUpgradeHeadersWithABodyStillTakeTheBodyPath(t *testing.T) {
	upgrade := []string{"upgrade", "websocket", "connection", "Upgrade", "sec-websocket-key", "websocket-test-key", "content-length", "6"}
	for _, method := range []string{"POST", "GET"} {
		for name, cfg := range map[string]Config{"standard": standard, "deep": deep(1<<20, inspect.OversizeClassifyPrefix)} {
			t.Run(method+" "+name, func(t *testing.T) {
				h := newHarness(t, fake.Attacks(), cfg, policy.FailOpen)
				s := h.open()
				send(t, s, headersMsg(false, with([]string{":method", method, ":path", "/ws", ":authority", "a.example"}, upgrade...)...))
				recv(t, s)
				send(t, s, bodyMsg([]byte("attack"), true))
				expectImmediate(t, recv(t, s), 403, 0, "request blocked")
			})
		}
	}
}

func TestPanicLoggedLikeEveryFrontend(t *testing.T) {
	var buf lockedBuffer
	obs := &frontendtest.Recorder{}
	obs.PanicAlways.Store(true)
	e := frontendtest.Engine(fake.Attacks(), policy.FailClosed, obs)
	conn := frontendtest.Dial(t, func(s *grpc.Server) {
		extprocv3.RegisterExternalProcessorServer(s, New(e, lite, nil, slog.New(slog.NewJSONHandler(&buf, nil))))
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, err := extprocv3.NewExternalProcessorClient(conn).Process(ctx)
	if err != nil {
		t.Fatal(err)
	}
	send(t, s, headersMsg(false, httpHeaders...))
	expectImmediate(t, recv(t, s), 503, 0, "service unavailable")
	logs := buf.String()
	for _, want := range []string{`"msg":"panic in frontend handler","frontend":"extproc"`, `"msg":"panic while applying the failure mode","frontend":"extproc"`} {
		if !strings.Contains(logs, want) {
			t.Errorf("logs lack %s:\n%s", want, logs)
		}
	}
}

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}
