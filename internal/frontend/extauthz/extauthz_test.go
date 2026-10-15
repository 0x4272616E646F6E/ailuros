package extauthz

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	rpcstatus "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"

	"github.com/0x4272616E646F6E/ailuros/internal/classifier"
	"github.com/0x4272616E646F6E/ailuros/internal/classifier/fake"
	"github.com/0x4272616E646F6E/ailuros/internal/decision"
	"github.com/0x4272616E646F6E/ailuros/internal/frontend/frontendtest"
	"github.com/0x4272616E646F6E/ailuros/internal/inspect"
	"github.com/0x4272616E646F6E/ailuros/internal/policy"
)

type harness struct {
	client     authv3.AuthorizationClient
	last       *frontendtest.Recorder
	downgrades *atomic.Int64
}

func newHarness(t *testing.T, c classifier.Classifier, failure policy.FailureMode, mode inspect.Mode, expose bool, log *slog.Logger) *harness {
	t.Helper()
	return newHarnessJA4(t, c, failure, mode, expose, "", log)
}

func newHarnessJA4(t *testing.T, c classifier.Classifier, failure policy.FailureMode, mode inspect.Mode, expose bool, ja4Header string, log *slog.Logger) *harness {
	t.Helper()
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	last := &frontendtest.Recorder{}
	e := frontendtest.Engine(c, failure, last)
	var downgrades atomic.Int64
	conn := frontendtest.Dial(t, func(s *grpc.Server) {
		authv3.RegisterAuthorizationServer(s, New(e, mode, expose, ja4Header, func() { downgrades.Add(1) }, log))
	})
	return &harness{client: authv3.NewAuthorizationClient(conn), last: last, downgrades: &downgrades}
}

func checkRequest(path string) *authv3.CheckRequest {
	return &authv3.CheckRequest{Attributes: &authv3.AttributeContext{
		Source: &authv3.AttributeContext_Peer{Address: &corev3.Address{Address: &corev3.Address_SocketAddress{
			SocketAddress: &corev3.SocketAddress{Address: "203.0.113.9", PortSpecifier: &corev3.SocketAddress_PortValue{PortValue: 51234}},
		}}},
		Request: &authv3.AttributeContext_Request{Http: &authv3.AttributeContext_HttpRequest{
			Method: "POST", Scheme: "https", Host: "shop.example.com", Path: path, Protocol: "HTTP/1.1",
			Headers: map[string]string{":path": path, "content-type": "application/json", "user-agent": "curl/8.9", "x-forwarded-for": "6.6.6.6"},
			Body:    "attack in the body is ignored",
		}},
		TlsSession: &authv3.AttributeContext_TLSSession{Sni: "shop.example.com"},
	}}
}

func check(t *testing.T, h *harness, req *authv3.CheckRequest) *authv3.CheckResponse {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := h.client.Check(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func setHeader(k, v string) *corev3.HeaderValueOption {
	return &corev3.HeaderValueOption{Header: &corev3.HeaderValue{Key: k, Value: v, RawValue: []byte(v)}, AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD}
}

func TestAllowBuildsRequestAndAddsRequestID(t *testing.T) {
	f := fake.Attacks()
	h := newHarness(t, f, policy.FailOpen, inspect.ModeLite, false, nil)
	resp := check(t, h, checkRequest("/api/cart?id=7"))
	id := h.last.Last().RequestID
	want := &authv3.CheckResponse{
		Status:       &rpcstatus.Status{Code: int32(codes.OK)},
		HttpResponse: &authv3.CheckResponse_OkResponse{OkResponse: &authv3.OkHttpResponse{Headers: []*corev3.HeaderValueOption{setHeader("x-ailuros-request-id", id)}}},
	}
	if !proto.Equal(resp, want) {
		t.Errorf("response = %v\nwant %v", resp, want)
	}
	r := f.Last()
	if r.Method != "POST" || r.Scheme != "https" || r.Host != "shop.example.com" || r.Path != "/api/cart" || r.Query != "id=7" ||
		r.ClientIP != "203.0.113.9" || r.TLS == nil || r.TLS.SNI != "shop.example.com" || r.Protocol != "HTTP/1.1" || r.Headers["user-agent"][0] != "curl/8.9" || r.Body != nil {
		t.Errorf("request = %+v", r)
	}
	if _, ok := r.Headers[":path"]; ok {
		t.Error("pseudo-header passed as a header")
	}
}

func TestRawHeaderMap(t *testing.T) {
	f := fake.Attacks()
	h := newHarness(t, f, policy.FailOpen, inspect.ModeLite, false, nil)
	req := checkRequest("/")
	req.Attributes.Request.Http.Headers = nil
	req.Attributes.Request.Http.HeaderMap = &corev3.HeaderMap{Headers: []*corev3.HeaderValue{
		{Key: "user-agent", RawValue: []byte("sqlmap/1.8")}, {Key: "accept", RawValue: []byte("a")}, {Key: "accept", RawValue: []byte("b")},
	}}
	check(t, h, req)
	if r := f.Last(); r.Headers["user-agent"][0] != "sqlmap/1.8" || len(r.Headers["accept"]) != 2 {
		t.Errorf("headers = %v", r.Headers)
	}
}

func TestHeaderMapWinsOverHeaders(t *testing.T) {
	f := fake.Attacks()
	h := newHarness(t, f, policy.FailOpen, inspect.ModeLite, false, nil)
	req := checkRequest("/")
	req.Attributes.Request.Http.Headers = map[string]string{"user-agent": "curl/8", "content-type": "text/plain,application/grpc"}
	req.Attributes.Request.Http.HeaderMap = &corev3.HeaderMap{Headers: []*corev3.HeaderValue{
		{Key: "user-agent", RawValue: []byte("sqlmap/1.8")}, {Key: "content-type", RawValue: []byte("text/plain")},
	}}
	check(t, h, req)
	if r := f.Last(); r.Headers["user-agent"][0] != "sqlmap/1.8" || len(r.Headers["content-type"]) != 1 || r.Headers["content-type"][0] != "text/plain" {
		t.Errorf("headers = %v, want header_map's values", r.Headers)
	}
}

func TestDenials(t *testing.T) {
	cases := []struct {
		name    string
		c       classifier.Classifier
		failure policy.FailureMode
		path    string
		http    typev3.StatusCode
		code    codes.Code
		msg     string
	}{
		{"block", fake.Attacks(), policy.FailOpen, "/attack", typev3.StatusCode_Forbidden, codes.PermissionDenied, "request blocked"},
		{"fail closed", fake.Failing(errors.New("down")), policy.FailClosed, "/", typev3.StatusCode_ServiceUnavailable, codes.Unavailable, "service unavailable"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t, c.c, c.failure, inspect.ModeLite, false, nil)
			resp := check(t, h, checkRequest(c.path))
			id := h.last.Last().RequestID
			want := &authv3.CheckResponse{
				Status: &rpcstatus.Status{Code: int32(c.code), Message: c.msg},
				HttpResponse: &authv3.CheckResponse_DeniedResponse{DeniedResponse: &authv3.DeniedHttpResponse{
					Status:  &typev3.HttpStatus{Code: c.http},
					Headers: []*corev3.HeaderValueOption{setHeader("x-ailuros-request-id", id), setHeader("content-type", "application/json")},
					Body:    `{"error":"` + c.msg + `","request_id":"` + id + `"}`,
				}},
			}
			if !proto.Equal(resp, want) {
				t.Errorf("response = %v\nwant %v", resp, want)
			}
		})
	}
}

func TestFailOpenAllows(t *testing.T) {
	h := newHarness(t, fake.Failing(errors.New("down")), policy.FailOpen, inspect.ModeLite, false, nil)
	if resp := check(t, h, checkRequest("/")); resp.GetOkResponse() == nil || resp.GetStatus().GetCode() != int32(codes.OK) {
		t.Errorf("response = %v, want ok", resp)
	}
}

func TestExposeVerdict(t *testing.T) {
	h := newHarness(t, fake.Attacks(), policy.FailOpen, inspect.ModeLite, true, nil)
	resp := check(t, h, checkRequest("/attack"))
	var got string
	for _, o := range resp.GetDeniedResponse().GetHeaders() {
		if o.GetHeader().GetKey() == "x-ailuros-decision" {
			got = o.GetHeader().GetValue()
		}
	}
	if got != "block; attack_score=0.990; category=sqli; confidence=0.990" {
		t.Errorf("x-ailuros-decision = %q", got)
	}
	if strings.Contains(resp.GetDeniedResponse().GetBody(), "sqli") {
		t.Error("category leaked in the body")
	}
}

func TestDowngradeWarnsOnceAndCountsEachRequest(t *testing.T) {
	var logs bytes.Buffer
	h := newHarness(t, fake.Attacks(), policy.FailOpen, inspect.ModeStandard, false, slog.New(slog.NewTextHandler(&logs, nil)))
	check(t, h, checkRequest("/"))
	check(t, h, checkRequest("/"))
	if h.downgrades.Load() != 2 {
		t.Errorf("downgrades = %d, want 2", h.downgrades.Load())
	}
	if n := strings.Count(logs.String(), "ext_authz cannot inspect request bodies"); n != 1 {
		t.Errorf("startup warning logged %d times, want 1", n)
	}
	if h.last.Last().Source.Mode != inspect.ModeLite {
		t.Error("decision not logged as lite")
	}
}

func TestDeadlineShorterThanClassifierTimeout(t *testing.T) {
	hang := fake.New(func(ctx context.Context, _ *inspect.Request, _ []policy.Category) (classifier.Verdict, error) {
		<-ctx.Done()
		return classifier.Verdict{}, ctx.Err()
	})
	h := newHarness(t, hang, policy.FailClosed, inspect.ModeLite, false, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	resp, err := h.client.Check(ctx, checkRequest("/"))
	if err != nil {
		t.Fatalf("Check failed (%v) after %v; want an answer before the deadline", err, time.Since(start))
	}
	if resp.GetStatus().GetCode() != int32(codes.Unavailable) || resp.GetDeniedResponse().GetStatus().GetCode() != typev3.StatusCode_ServiceUnavailable {
		t.Errorf("response = %v, want fail_closed 503 / UNAVAILABLE", resp)
	}
	if d := h.last.Last(); d.Reason != classifier.ReasonTimeout {
		t.Errorf("reason = %q, want timeout", d.Reason)
	}
}

func TestPanicAfterBlockStillDenies(t *testing.T) {
	e := frontendtest.Engine(fake.Attacks(), policy.FailOpen, frontendtest.PanicObserver{Always: true})
	srv := New(e, inspect.ModeLite, false, "", nil, slog.New(slog.DiscardHandler))
	resp, err := srv.Check(context.Background(), checkRequest("/attack"))
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetDeniedResponse().GetStatus().GetCode() != typev3.StatusCode_Forbidden {
		t.Errorf("response = %v, want 403 denial", resp)
	}
}

func directServer(t *testing.T, c classifier.Classifier, failure policy.FailureMode) (*Server, *frontendtest.Recorder) {
	t.Helper()
	last := &frontendtest.Recorder{}
	e := frontendtest.Engine(c, failure, last)
	return New(e, inspect.ModeLite, false, "", nil, slog.New(slog.DiscardHandler)), last
}

func honestClassifier() *fake.Classifier {
	return fake.New(func(ctx context.Context, _ *inspect.Request, _ []policy.Category) (classifier.Verdict, error) {
		if err := ctx.Err(); err != nil {
			return classifier.Verdict{}, err
		}
		return classifier.Verdict{Benign: 1}, nil
	})
}

func TestExpiredCallsSkipClassifier(t *testing.T) {
	cases := []struct {
		name   string
		ctx    func() (context.Context, context.CancelFunc)
		reason classifier.Reason
	}{
		{"deadline passed", func() (context.Context, context.CancelFunc) {
			return context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
		}, classifier.ReasonTimeout},
		{"deadline inside margin", func() (context.Context, context.CancelFunc) {
			return context.WithTimeout(context.Background(), 10*time.Millisecond)
		}, classifier.ReasonTimeout},
		{"cancelled", func() (context.Context, context.CancelFunc) {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			return ctx, cancel
		}, classifier.ReasonCanceled},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := honestClassifier()
			srv, last := directServer(t, f, policy.FailClosed)
			ctx, cancel := c.ctx()
			defer cancel()
			_, _ = srv.Check(ctx, checkRequest("/"))
			if n := f.Calls(); n != 0 {
				t.Errorf("classifier called %d times on a dead context", n)
			}
			if d := last.Last(); d == nil || d.Reason != c.reason || d.Outcome != decision.FailClosed {
				t.Errorf("decision = %+v, want fail_closed with reason %q", d, c.reason)
			}
		})
	}
}

func TestExpiredCallsDoNotTripBreaker(t *testing.T) {
	f := honestClassifier()
	srv, _ := directServer(t, f, policy.FailClosed)
	for range classifier.DefaultBreakerSettings.MinCalls + 5 {
		ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
		_, _ = srv.Check(ctx, checkRequest("/"))
		cancel()
	}
	resp, err := srv.Check(context.Background(), checkRequest("/"))
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetOkResponse() == nil {
		t.Errorf("healthy call denied after expired calls: %v", resp)
	}
	if n := f.Calls(); n != 1 {
		t.Errorf("classifier calls = %d, want 1 (only the healthy call)", n)
	}
}

func TestJA4Header(t *testing.T) {
	fp := "t13d1516h2_8daaf6152771_b186095e22b6"
	for _, c := range []struct {
		name, header, want string
		kept               bool
	}{
		{"on", "x-ailuros-ja4", fp, false},
		{"off", "", "", true},
	} {
		f := fake.Attacks()
		h := newHarnessJA4(t, f, policy.FailOpen, inspect.ModeLite, false, c.header, nil)
		req := checkRequest("/")
		req.Attributes.Request.Http.Headers["x-ailuros-ja4"] = fp
		check(t, h, req)
		r := f.Last()
		if _, kept := r.Headers["x-ailuros-ja4"]; r.JA4 != c.want || kept != c.kept {
			t.Errorf("%s: JA4 %q, header kept %v", c.name, r.JA4, kept)
		}
	}
}
