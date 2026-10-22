package forwardauth

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/0x4272616E646F6E/decision-waf/internal/classifier"
	"github.com/0x4272616E646F6E/decision-waf/internal/classifier/fake"
	"github.com/0x4272616E646F6E/decision-waf/internal/decision"
	"github.com/0x4272616E646F6E/decision-waf/internal/frontend/frontendtest"
	"github.com/0x4272616E646F6E/decision-waf/internal/inspect"
	"github.com/0x4272616E646F6E/decision-waf/internal/policy"
)

func newServer(c classifier.Classifier, failure policy.FailureMode, mode inspect.Mode, expose bool) (*Server, *int) {
	downgrades := 0
	e := frontendtest.Engine(c, failure, nil)
	return New(e, mode, expose, func() { downgrades++ }, slog.New(slog.DiscardHandler)), &downgrades
}

func benign() *fake.Classifier {
	return fake.Returning(classifier.Verdict{Benign: 1})
}

func traefik(method, uri string) *http.Request {
	r := httptest.NewRequest("GET", "http://ailuros/", nil)
	r.Header.Set("X-Forwarded-Method", method)
	r.Header.Set("X-Forwarded-Uri", uri)
	r.Header.Set("X-Forwarded-Host", "app.example.com")
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("X-Forwarded-For", "198.51.100.7")
	r.Header.Set("User-Agent", "sqlmap/1.8")
	return r
}

func serve(s *Server, r *http.Request) *httptest.ResponseRecorder {
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, r)
	return rr
}

func TestTraefikHeadersBecomeRequest(t *testing.T) {
	f := benign()
	s, _ := newServer(f, policy.FailOpen, inspect.ModeLite, false)
	rr := serve(s, traefik("POST", "/login?next=/"))
	if rr.Code != 200 || len(rr.Header().Get("X-Ailuros-Request-Id")) != 16 {
		t.Fatalf("status = %d, request id = %q", rr.Code, rr.Header().Get("X-Ailuros-Request-Id"))
	}
	got := f.Last()
	if got.Method != "POST" || got.Path != "/login" || got.Query != "next=/" || got.Host != "app.example.com" ||
		got.Scheme != "https" || got.ClientIP != "198.51.100.7" || got.Headers["user-agent"][0] != "sqlmap/1.8" {
		t.Errorf("request = %+v", got)
	}
	if _, ok := got.Headers["x-forwarded-uri"]; ok {
		t.Error("consumed forwarding header passed to classifier")
	}
}

func TestNginxHeaders(t *testing.T) {
	f := benign()
	s, _ := newServer(f, policy.FailOpen, inspect.ModeLite, false)
	r := httptest.NewRequest("GET", "http://shop.example.com/_ailuros", nil)
	r.Header.Set("X-Original-Method", "GET")
	r.Header.Set("X-Original-URI", "/search?q=x")
	r.Header.Set("X-Real-IP", "203.0.113.4")
	if rr := serve(s, r); rr.Code != 200 {
		t.Fatalf("status = %d", rr.Code)
	}
	got := f.Last()
	if got.Method != "GET" || got.Path != "/search" || got.Query != "q=x" || got.Host != "shop.example.com" || got.ClientIP != "203.0.113.4" {
		t.Errorf("request = %+v", got)
	}
}

func TestMissingOriginalRequestHeaders(t *testing.T) {
	f := benign()
	s, _ := newServer(f, policy.FailOpen, inspect.ModeLite, false)
	rr := serve(s, httptest.NewRequest("GET", "http://ailuros/", nil))
	if rr.Code != http.StatusInternalServerError || f.Calls() != 0 {
		t.Errorf("status = %d, classifier calls = %d; want 500 and no classification", rr.Code, f.Calls())
	}
	if id := rr.Header().Get("X-Ailuros-Request-Id"); id != "" {
		t.Errorf("500 path set X-Ailuros-Request-Id = %q; want none", id)
	}
	if rr.Header().Get("Content-Type") != "application/json" || rr.Body.String() != `{"error":"proxy misconfigured"}` {
		t.Errorf("500 body = %q (%s), want the JSON error", rr.Body.String(), rr.Header().Get("Content-Type"))
	}
}

func TestInvalidOriginalMethod(t *testing.T) {
	for _, m := range []string{"GET /admin HTTP/1.1", "G\tET"} {
		f := benign()
		s, _ := newServer(f, policy.FailOpen, inspect.ModeLite, false)
		rr := serve(s, traefik(m, "/"))
		if rr.Code != http.StatusForbidden || f.Calls() != 0 || !strings.Contains(rr.Body.String(), "malformed request") {
			t.Errorf("method %q: status %d, calls %d, body %q; want a 403 malformed block", m, rr.Code, f.Calls(), rr.Body.String())
		}
	}
	f := benign()
	s, _ := newServer(f, policy.FailOpen, inspect.ModeLite, false)
	if rr := serve(s, traefik(strings.Repeat("A", 40), "/")); rr.Code != http.StatusOK || f.Calls() != 1 {
		t.Errorf("long method: status %d, calls %d; want it classified", rr.Code, f.Calls())
	}
}

func TestClientIPPrecedence(t *testing.T) {
	cases := []struct {
		name, realIP, xff, want string
	}{
		{"spoofed X-Real-IP ignored", "6.6.6.6", "198.51.100.7", "198.51.100.7"},
		{"last XFF hop wins", "", "6.6.6.6, 10.0.0.2", "10.0.0.2"},
		{"no XFF falls to RemoteAddr", "", "", "192.0.2.1"},
		{"invalid last XFF hop falls to RemoteAddr", "", "not-an-ip", "192.0.2.1"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := benign()
			s, _ := newServer(f, policy.FailOpen, inspect.ModeLite, false)
			r := traefik("GET", "/")
			r.Header.Del("X-Forwarded-For")
			if c.realIP != "" {
				r.Header.Set("X-Real-IP", c.realIP)
			}
			if c.xff != "" {
				r.Header.Set("X-Forwarded-For", c.xff)
			}
			serve(s, r)
			if got := f.Last().ClientIP; got != c.want {
				t.Errorf("X-Real-IP=%q XFF=%q: ClientIP = %q, want %q", c.realIP, c.xff, got, c.want)
			}
		})
	}
}

func TestForgedNginxHeadersBehindTraefik(t *testing.T) {
	f := benign()
	s, _ := newServer(f, policy.FailOpen, inspect.ModeLite, false)
	r := traefik("GET", "/")
	r.Header.Set("X-Original-URI", "/x")
	r.Header.Set("X-Real-IP", "6.6.6.6")
	rr := serve(s, r)
	if rr.Code != http.StatusInternalServerError || f.Calls() != 0 {
		t.Errorf("status = %d, classifier calls = %d; want 500 and no classification", rr.Code, f.Calls())
	}
}

func nginx(method, uri string) *http.Request {
	r := httptest.NewRequest("GET", "http://shop.example.com/_ailuros", nil)
	r.Header.Set("X-Original-Method", method)
	r.Header.Set("X-Original-URI", uri)
	return r
}

func TestNginxIgnoresForgedTraefikMethod(t *testing.T) {
	f := benign()
	s, _ := newServer(f, policy.FailOpen, inspect.ModeLite, false)
	r := nginx("POST", "/login")
	r.Header.Set("X-Forwarded-Method", "GET")
	if rr := serve(s, r); rr.Code != 200 {
		t.Fatalf("status = %d", rr.Code)
	}
	if got := f.Last().Method; got != "POST" {
		t.Errorf("Method = %q, want POST from X-Original-Method", got)
	}
}

func TestNginxWithForgedTraefikURIRejected(t *testing.T) {
	f := benign()
	s, _ := newServer(f, policy.FailOpen, inspect.ModeLite, false)
	r := nginx("POST", "/admin?q=' OR 1=1")
	r.Header.Set("X-Forwarded-Uri", "/")
	rr := serve(s, r)
	if rr.Code != http.StatusInternalServerError || f.Calls() != 0 {
		t.Errorf("status = %d, classifier calls = %d; want 500 and no classification", rr.Code, f.Calls())
	}
}

func TestTraefikIgnoresForgedNginxMethod(t *testing.T) {
	f := benign()
	s, _ := newServer(f, policy.FailOpen, inspect.ModeLite, false)
	r := traefik("POST", "/login")
	r.Header.Set("X-Original-Method", "GET")
	if rr := serve(s, r); rr.Code != 200 {
		t.Fatalf("status = %d", rr.Code)
	}
	if got := f.Last().Method; got != "POST" {
		t.Errorf("Method = %q, want POST from X-Forwarded-Method", got)
	}
}

func TestMissingMethodInChosenSet(t *testing.T) {
	cases := map[string]*http.Request{}
	r := nginx("GET", "/")
	r.Header.Del("X-Original-Method")
	r.Header.Set("X-Forwarded-Method", "GET")
	cases["nginx without X-Original-Method"] = r
	r = traefik("GET", "/")
	r.Header.Del("X-Forwarded-Method")
	r.Header.Set("X-Original-Method", "GET")
	cases["traefik without X-Forwarded-Method"] = r
	for name, r := range cases {
		t.Run(name, func(t *testing.T) {
			f := benign()
			s, _ := newServer(f, policy.FailOpen, inspect.ModeLite, false)
			rr := serve(s, r)
			if rr.Code != http.StatusInternalServerError || f.Calls() != 0 {
				t.Errorf("status = %d, classifier calls = %d; want 500 and no classification", rr.Code, f.Calls())
			}
		})
	}
}

func TestFullURLHeadersConsumed(t *testing.T) {
	f := benign()
	s, _ := newServer(f, policy.FailOpen, inspect.ModeLite, false)
	r := nginx("GET", "/search?token=secret")
	r.Header.Set("X-Original-URL", "https://shop.example.com/search?token=secret")
	r.Header.Set("X-Auth-Request-Redirect", "https://shop.example.com/search?token=secret")
	serve(s, r)
	got := f.Last().Headers
	for _, h := range []string{"x-original-url", "x-auth-request-redirect"} {
		if _, ok := got[h]; ok {
			t.Errorf("%s passed to classifier", h)
		}
	}
}

func TestNginxInvalidRealIPFallsThrough(t *testing.T) {
	f := benign()
	s, _ := newServer(f, policy.FailOpen, inspect.ModeLite, false)
	r := httptest.NewRequest("GET", "http://shop.example.com/_ailuros", nil)
	r.Header.Set("X-Original-Method", "GET")
	r.Header.Set("X-Original-URI", "/")
	r.Header.Set("X-Real-IP", "garbage")
	serve(s, r)
	if got := f.Last().ClientIP; got != "192.0.2.1" {
		t.Errorf("ClientIP = %q, want RemoteAddr host 192.0.2.1", got)
	}
}

func TestGRPCDetection(t *testing.T) {
	f := benign()
	s, _ := newServer(f, policy.FailOpen, inspect.ModeLite, false)
	r := traefik("POST", "/payments.v1.Payments/Charge")
	r.Header.Set("Content-Type", "application/grpc+proto")
	serve(s, r)
	if got := f.Last(); got.GRPCService != "payments.v1.Payments" || got.GRPCMethod != "Charge" {
		t.Errorf("grpc = %q/%q", got.GRPCService, got.GRPCMethod)
	}
}

func TestBlockResponse(t *testing.T) {
	s, _ := newServer(fake.Returning(classifier.Verdict{Benign: 0.045, Category: "sqli", Confidence: 0.576}), policy.FailOpen, inspect.ModeLite, false)
	rr := serve(s, traefik("GET", "/items?id=1'--"))
	if rr.Code != http.StatusForbidden || rr.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("status = %d, content-type = %q", rr.Code, rr.Header().Get("Content-Type"))
	}
	var body map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["error"] != "request blocked" || body["request_id"] != rr.Header().Get("X-Ailuros-Request-Id") {
		t.Errorf("body = %v", body)
	}
	if strings.Contains(rr.Body.String(), "sqli") || rr.Header().Get("X-Ailuros-Decision") != "" {
		t.Error("category leaked to client without AILUROS_EXPOSE_VERDICT")
	}
}

func TestFailureModes(t *testing.T) {
	down := fake.Failing(errors.New("down"))
	s, _ := newServer(down, policy.FailClosed, inspect.ModeLite, false)
	rr := serve(s, traefik("GET", "/"))
	if rr.Code != http.StatusServiceUnavailable || !strings.Contains(rr.Body.String(), `"error":"service unavailable"`) {
		t.Errorf("fail closed: status = %d body = %s", rr.Code, rr.Body)
	}
	s, _ = newServer(down, policy.FailOpen, inspect.ModeLite, false)
	if rr := serve(s, traefik("GET", "/")); rr.Code != 200 {
		t.Errorf("fail open: status = %d", rr.Code)
	}
}

func TestExposeVerdict(t *testing.T) {
	s, _ := newServer(fake.Returning(classifier.Verdict{Benign: 0.045, Category: "sqli", Confidence: 0.576}), policy.FailOpen, inspect.ModeLite, true)
	rr := serve(s, traefik("GET", "/"))
	if got := rr.Header().Get("X-Ailuros-Decision"); got != "block; attack_score=0.955; category=sqli; confidence=0.576" {
		t.Errorf("X-Ailuros-Decision = %q", got)
	}
}

func TestDowngradeCounted(t *testing.T) {
	s, n := newServer(benign(), policy.FailOpen, inspect.ModeStandard, false)
	serve(s, traefik("GET", "/"))
	serve(s, traefik("GET", "/"))
	if *n != 2 {
		t.Errorf("standard mode downgrades = %d, want 2", *n)
	}
	s, n = newServer(benign(), policy.FailOpen, inspect.ModeLite, false)
	serve(s, traefik("GET", "/"))
	if *n != 0 {
		t.Errorf("lite mode downgrades = %d, want 0", *n)
	}
}

func newServerObserved(failure policy.FailureMode, obs decision.Observer) *Server {
	e := frontendtest.Engine(fake.Attacks(), failure, obs)
	return New(e, inspect.ModeLite, false, nil, slog.New(slog.DiscardHandler))
}

func TestPanicAfterBlockStillDenies(t *testing.T) {
	rr := serve(newServerObserved(policy.FailOpen, frontendtest.PanicObserver{OnBlock: true}), traefik("GET", "/attack"))
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403: the block the engine had taken must stand", rr.Code)
	}
}

func TestPanicDuringRecoveryAnswersWithFailureMode(t *testing.T) {
	for _, c := range []struct {
		failure policy.FailureMode
		status  int
	}{{policy.FailOpen, http.StatusOK}, {policy.FailClosed, http.StatusServiceUnavailable}} {
		t.Run(string(c.failure), func(t *testing.T) {
			s := newServerObserved(c.failure, frontendtest.PanicObserver{Always: true})
			var rr *httptest.ResponseRecorder
			func() {
				defer func() {
					if p := recover(); p != nil {
						t.Fatalf("the panic escaped ServeHTTP: %v", p)
					}
				}()
				rr = serve(s, traefik("GET", "/home"))
			}()
			if rr.Code != c.status || len(rr.Header().Get("X-Ailuros-Request-Id")) != 16 {
				t.Errorf("status = %d, request id %q; want %d with a request ID", rr.Code, rr.Header().Get("X-Ailuros-Request-Id"), c.status)
			}
		})
	}
}

func TestClientIPFromForwardedHopWithPort(t *testing.T) {
	f := benign()
	s, _ := newServer(f, policy.FailOpen, inspect.ModeLite, false)
	r := traefik("GET", "/")
	r.Header.Set("X-Forwarded-For", "6.6.6.6, 198.51.100.7:5678")
	serve(s, r)
	if got := f.Last().ClientIP; got != "198.51.100.7" {
		t.Errorf("ClientIP = %q, want 198.51.100.7", got)
	}
}

func TestClientIPFromXRealIPWithPort(t *testing.T) {
	f := benign()
	s, _ := newServer(f, policy.FailOpen, inspect.ModeLite, false)
	r := httptest.NewRequest("GET", "http://ailuros/", nil)
	r.Header.Set("X-Original-Method", "GET")
	r.Header.Set("X-Original-Uri", "/")
	r.Header.Set("X-Real-Ip", "198.51.100.7:8080")
	serve(s, r)
	if got := f.Last().ClientIP; got != "198.51.100.7" {
		t.Errorf("ClientIP = %q, want 198.51.100.7", got)
	}
}

func TestMalformedIsForbidden(t *testing.T) {
	f := benign()
	s, _ := newServer(f, policy.FailOpen, inspect.ModeLite, false)
	r := traefik("POST", "/upload")
	r.Header.Add("Content-Type", "text/plain")
	r.Header.Add("Content-Type", "application/grpc")
	rr := serve(s, r)
	if rr.Code != http.StatusForbidden || !strings.Contains(rr.Body.String(), `"malformed request"`) {
		t.Errorf("status = %d, body %s; want 403 with the malformed-request body", rr.Code, rr.Body)
	}
	if f.Calls() != 0 {
		t.Errorf("classifier calls = %d, want none", f.Calls())
	}
}
