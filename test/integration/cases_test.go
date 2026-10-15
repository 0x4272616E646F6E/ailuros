//go:build integration || k8s

package integration

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"

	"github.com/0x4272616E646F6E/ailuros/test/integration/echo/echopb"
)

func binaryBody(marker string) []byte {
	b := []byte(marker + "\n")
	for i := range 256 {
		b = append(b, byte(i))
	}
	return append(b, "\r\nend"...)
}

func bodyCases(t *testing.T, s *Stack) {
	t.Run("POST body attack is blocked", func(t *testing.T) {
		m := newMarker(t)
		resp := s.Send(t, "http1", Request{Method: "POST", Path: "/comments", Body: []byte(m + " attack")})
		s.WantDecision(t, wantDeny(t, resp, http.StatusForbidden, "request blocked"), "block", "")
		if seen := s.Seen(t, m); len(seen) != 0 {
			t.Errorf("echo received the blocked body: %+v", seen)
		}
	})

	t.Run("gzip-compressed body attack is blocked", func(t *testing.T) {
		m := newMarker(t)
		var gz bytes.Buffer
		w := gzip.NewWriter(&gz)
		_, _ = w.Write([]byte(m + " attack"))
		_ = w.Close()
		resp := s.Send(t, "http1", Request{Method: "POST", Path: "/comments/" + m, Body: gz.Bytes(),
			Header: http.Header{"Content-Encoding": {"gzip"}, "Content-Type": {"text/plain"}}})
		s.WantDecision(t, wantDeny(t, resp, http.StatusForbidden, "request blocked"), "block", "")
		if seen := s.Seen(t, m); len(seen) != 0 {
			t.Errorf("echo received the blocked body: %+v", seen)
		}
	})

	t.Run("benign body is forwarded byte-exact", func(t *testing.T) {
		m := newMarker(t)
		body := binaryBody(m)
		v := echoed(t, s.Send(t, "http1", Request{Method: "POST", Path: "/upload", Body: body,
			Header: http.Header{"Content-Type": {"application/octet-stream"}}}))
		if !bytes.Equal(v.Body, body) {
			t.Errorf("echo received %d bytes %q, want the %d bytes sent", len(v.Body), v.Body, len(body))
		}
		s.WantDecision(t, upstreamID(t, v), "allow", "")
	})
}

func grpcUnaryCases(t *testing.T, s *Stack) {
	t.Run("gRPC unary benign reaches echo with a request ID", func(t *testing.T) {
		m := newMarker(t)
		ctx := metadata.AppendToOutgoingContext(grpcContext(t), "x-it-marker", m)
		out, err := echopb.Unary(ctx, s.GRPC(t), &echopb.Msg{Value: "hello " + m})
		if err != nil {
			t.Fatal(err)
		}
		id := out.Fields["metadata"].GetStructValue().Fields["x-ailuros-request-id"].GetStringValue()
		if out.Fields["text"].GetStringValue() != "hello "+m || id == "" {
			t.Fatalf("reply = %v, want the text and an x-ailuros-request-id", out)
		}
		d := s.WantDecision(t, id, "allow", "")
		if d.Str("grpc_method") != "echo.v1.Echo/Unary" {
			t.Errorf("grpc_method = %q, want echo.v1.Echo/Unary", d.Str("grpc_method"))
		}
	})

	t.Run("gRPC attack in the method path is denied with status 7", func(t *testing.T) {
		m := newMarker(t)
		ctx := metadata.AppendToOutgoingContext(grpcContext(t), "x-it-marker", m)
		err := s.GRPC(t).Invoke(ctx, "/echo.v1.Echo/attack", &echopb.Msg{Value: m}, new(echopb.Reply))
		wantCode(t, err, codes.PermissionDenied)
		if seen := s.Seen(t, m); len(seen) != 0 {
			t.Errorf("echo received the denied call: %+v", seen)
		}
	})
}

func deepStreamCases(t *testing.T, s *Stack) {
	t.Run("gRPC stream: an attack as the first message is denied with status 7", func(t *testing.T) {
		m := newMarker(t)
		stream, err := echopb.Stream(grpcContext(t), s.GRPC(t))
		if err != nil {
			t.Fatal(err)
		}
		_ = stream.Send(&echopb.Msg{Value: "attack " + m})
		_, err = stream.Recv()
		wantCode(t, err, codes.PermissionDenied)
		if seen := s.Seen(t, m); len(seen) != 0 {
			t.Errorf("echo received the denied message: %+v", seen)
		}
	})

	t.Run("gRPC stream: a blocked message after a reply resets the stream", func(t *testing.T) {
		m := newMarker(t)
		stream, err := echopb.Stream(grpcContext(t), s.GRPC(t))
		if err != nil {
			t.Fatal(err)
		}
		if err := stream.Send(&echopb.Msg{Value: "first " + m}); err != nil {
			t.Fatal(err)
		}
		if r, err := stream.Recv(); err != nil || r.Fields["text"].GetStringValue() != "first "+m {
			t.Fatalf("first reply = %v, %v", r, err)
		}
		_ = stream.Send(&echopb.Msg{Value: "attack " + m})
		_, err = stream.Recv()
		wantCode(t, err, codes.Internal)
		if !strings.Contains(err.Error(), "RST_STREAM") {
			t.Errorf("error = %v, want a stream reset", err)
		}
		seen := s.Seen(t, m)
		if len(seen) != 1 || string(seen[0].Body) != "first "+m {
			t.Errorf("echo saw %+v, want only the first message", seen)
		}
		if p := s.Prompts(t, "attack "+m); len(p) != 1 {
			t.Errorf("attack message was classified %d times, want 1", len(p))
		}
	})
}

func failClosedWhenAilurosDown(t *testing.T, s *Stack, want int, check func(*testing.T, *Response)) {
	t.Run("Ailuros down: requests fail closed", func(t *testing.T) {
		s.StopAiluros(t)
		deadline := time.Now().Add(30 * time.Second)
		var m string
		var resp *Response
		for {
			m = newMarker(t)
			var err error
			resp, err = s.do(s.http1, Request{Method: "GET", Path: "/down/" + m})
			if err == nil && resp.Status == want {
				break
			}
			if time.Now().After(deadline) {
				last := fmt.Sprintf("transport error %v", err)
				if err == nil {
					last = fmt.Sprintf("status %d, body %s", resp.Status, resp.Body)
				}
				t.Fatalf("no %d within 30s after Ailuros stopped; last answer: %s", want, last)
			}
			time.Sleep(time.Second)
		}
		if seen := s.Seen(t, m); len(seen) != 0 {
			t.Errorf("echo received the refused request: %+v", seen)
		}
		if check != nil {
			check(t, resp)
		}
	})
}

func sharedCases(t *testing.T, s *Stack, proto string) {
	t.Run("benign GET is allowed with a request ID", func(t *testing.T) {
		m := newMarker(t)
		v := echoed(t, s.Get(t, proto, "/hello/"+m+"?page=2", nil))
		if v.Path != "/hello/"+m || v.Query != "page=2" {
			t.Errorf("echo saw %s?%s, want /hello/%s?page=2", v.Path, v.Query, m)
		}
		if v.Headers.Get("X-Envoy-Internal") != "" {
			t.Errorf("upstream saw x-envoy-internal: %q", v.Headers.Get("X-Envoy-Internal"))
		}
		s.WantDecision(t, upstreamID(t, v), "allow", "")
	})

	t.Run("attack in the path and query is blocked before the upstream", func(t *testing.T) {
		m := newMarker(t)
		id := wantDeny(t, s.Get(t, proto, "/search/"+m+"?q=attack", nil), http.StatusForbidden, "request blocked")
		s.WantDecision(t, id, "block", "")
		if seen := s.Seen(t, m); len(seen) != 0 {
			t.Errorf("echo received the blocked request: %+v", seen)
		}
	})

	t.Run("attack in a header is blocked", func(t *testing.T) {
		m := newMarker(t)
		resp := s.Get(t, proto, "/profile/"+m, http.Header{"X-Comment": {"attack"}})
		s.WantDecision(t, wantDeny(t, resp, http.StatusForbidden, "request blocked"), "block", "")
	})

	t.Run("model 503 fails open", func(t *testing.T) {
		defer settle(t, s, proto)
		m := newMarker(t)
		v := echoed(t, s.Get(t, proto, "/items/"+m+"/stub-fail", nil))
		s.WantDecision(t, upstreamID(t, v), "fail_open", "upstream_5xx")
	})

	t.Run("model 503 on a failure_mode closed route fails closed", func(t *testing.T) {
		defer settle(t, s, proto)
		m := newMarker(t)
		id := wantDeny(t, s.Get(t, proto, "/admin/"+m+"/stub-fail", nil), http.StatusServiceUnavailable, "service unavailable")
		s.WantDecision(t, id, "fail_closed", "upstream_5xx")
	})

	t.Run("slow model hits Ailuros's timeout before the proxy's", func(t *testing.T) {
		defer settle(t, s, proto)
		m := newMarker(t)
		v := echoed(t, s.Get(t, proto, "/slow/"+m+"/stub-slow", nil))
		d := s.WantDecision(t, upstreamID(t, v), "fail_open", "timeout")
		if ms, _ := d["classifier_latency_ms"].(float64); ms < 900 || ms > 1500 {
			t.Errorf("classifier_latency_ms = %v, want about the 1s classifier timeout", ms)
		}
		id := wantDeny(t, s.Get(t, proto, "/admin/slow/"+m+"/stub-slow", nil), http.StatusServiceUnavailable, "service unavailable")
		s.WantDecision(t, id, "fail_closed", "timeout")
	})

	t.Run("two content-type headers are refused as malformed", func(t *testing.T) {
		status, msg := http.StatusBadRequest, "malformed request"
		if s.proxy.forwardAuth {
			status = http.StatusForbidden
		}
		if s.proxy.ownDenyBody {
			msg = "request blocked"
		}
		m := newMarker(t)
		resp := s.Get(t, proto, "/upload/"+m, http.Header{"Content-Type": {"text/plain", "application/grpc"}})
		s.WantDecision(t, wantDeny(t, resp, status, msg), "block", "malformed")
		if seen := s.Seen(t, m); len(seen) != 0 {
			t.Errorf("echo received the malformed request: %+v", seen)
		}
	})

	t.Run("client-supplied request ID and forwarding headers are not trusted", func(t *testing.T) {
		m := newMarker(t)
		peer := s.Decision(t, upstreamID(t, echoed(t, s.Get(t, proto, "/peer/"+m, nil)))).Str("client_ip")
		if peer == "" {
			t.Fatal("baseline decision has no client_ip")
		}
		forged := http.Header{
			"X-Ailuros-Request-Id": {"forged-" + m},
			"X-Forwarded-For":      {forgedIP},
			"X-Real-Ip":            {forgedIP},
			"Forwarded":            {"for=" + forgedIP},
		}
		v := echoed(t, s.Get(t, proto, "/forged/"+m, forged))
		id := upstreamID(t, v)
		if id == "forged-"+m {
			t.Errorf("echo saw the client's X-Ailuros-Request-Id")
		}
		if ip := s.Decision(t, id).Str("client_ip"); ip != peer {
			t.Errorf("logged client_ip = %q with forged headers, want the real peer %q", ip, peer)
		}
	})

	t.Run("a GraphQL introspection query is blocked by a policy limit", func(t *testing.T) {
		m := newMarker(t)
		q := url.Values{"query": {"{ __schema { types { name } } }"}}.Encode()
		id := wantDeny(t, s.Get(t, proto, "/graphql/"+m+"?"+q, nil), http.StatusForbidden, "request blocked")
		d := s.WantDecision(t, id, "block", "limit")
		if d.Str("limit") != "graphql_introspection" {
			t.Errorf("limit = %q, want graphql_introspection", d.Str("limit"))
		}
		if p := s.Prompts(t, m); len(p) != 0 {
			t.Errorf("the model was asked: %q", p)
		}
	})

	t.Run("a GraphQL query under the limits reaches the model with its signals", func(t *testing.T) {
		m := newMarker(t)
		q := url.Values{"query": {"{ user { name } }"}}.Encode()
		v := echoed(t, s.Get(t, proto, "/graphql/"+m+"?"+q, nil))
		d := s.WantDecision(t, upstreamID(t, v), "allow", "")
		if !strings.Contains(d.Str("signals"), "graphql op=query operations=1 depth=2") {
			t.Errorf("signals = %q", d.Str("signals"))
		}
		if p := s.Prompts(t, m); len(p) == 0 || !strings.Contains(p[0], "signals:\n  ") {
			t.Errorf("prompt has no signals block: %q", p)
		}
	})

	t.Run("a cross-origin WebSocket handshake is blocked by a policy limit", func(t *testing.T) {
		if s.proxy.forwardAuth {
			t.Skipf("%s forward-auth does not forward the handshake headers (docs/design/signals.md#verification)", s.Name)
		}
		if proto != "http1" {
			t.Skip("the Upgrade handshake is HTTP/1.1 only; the Go HTTP/2 client refuses to send it")
		}
		m := newMarker(t)
		h := http.Header{"Connection": {"Upgrade"}, "Upgrade": {"websocket"}, "Sec-Websocket-Version": {"13"},
			"Sec-Websocket-Key": {"dGhlIHNhbXBsZSBub25jZQ=="}, "Origin": {"https://evil.example"}}
		id := wantDeny(t, s.Get(t, proto, "/ws/"+m, h), http.StatusForbidden, "request blocked")
		if d := s.WantDecision(t, id, "block", "limit"); d.Str("limit") != "websocket_cross_origin" {
			t.Errorf("limit = %q", d.Str("limit"))
		}
	})

	t.Run("the HTTP protocol is recorded", func(t *testing.T) {
		if s.proxy.forwardAuth {
			t.Skipf("%s forward-auth records no protocol (docs/design/signals.md, frontend table)", s.Name)
		}
		v := echoed(t, s.Get(t, proto, "/proto/"+newMarker(t), nil))
		want := map[string]string{"http1": "protocol HTTP/1.1", "h2c": "protocol HTTP/2"}[proto]
		if d := s.WantDecision(t, upstreamID(t, v), "allow", ""); !strings.Contains(d.Str("signals"), want) {
			t.Errorf("signals = %q, want %q", d.Str("signals"), want)
		}
	})
}
