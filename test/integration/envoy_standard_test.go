//go:build integration

package integration

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"strings"
	"testing"
)

func largeBody(marker string, size int, tail string) []byte {
	b := []byte(marker + " ")
	b = append(b, bytes.Repeat([]byte("."), size-len(b)-len(tail))...)
	return append(b, tail...)
}

func TestEnvoyStandard(t *testing.T) {
	t.Parallel()
	s := up(t, "envoy-standard", nil)
	t.Run("http1", func(t *testing.T) { sharedCases(t, s, "http1") })

	bodyCases(t, s)

	t.Run("body over AILUROS_BODY_MAX_BYTES is classified on its prefix", func(t *testing.T) {
		m := newMarker(t)
		body := largeBody(m, 20000, " attack")
		v := echoed(t, s.Send(t, "http1", Request{Method: "POST", Path: "/upload", Body: body}))
		if !bytes.Equal(v.Body, body) {
			t.Errorf("echo received %d bytes, want the %d bytes sent", len(v.Body), len(body))
		}
		s.WantDecision(t, upstreamID(t, v), "allow", "")
		prompts := s.Prompts(t, m)
		if len(prompts) != 1 || !strings.Contains(prompts[0], "body (truncated):") || strings.Contains(prompts[0], "attack") {
			t.Errorf("prompts = %q, want one truncated body without the tail", prompts)
		}
	})

	t.Run("gRPC-Web text body is decoded before classification", func(t *testing.T) {
		m := newMarker(t)
		msg := "attack " + m
		frame := append([]byte{0, 0, 0, 0, byte(len(msg))}, msg...)
		resp := s.Send(t, "http1", Request{Method: "POST", Path: "/echo.v1.Echo/Unary",
			Header: http.Header{"Content-Type": {"application/grpc-web-text"}},
			Body:   []byte(base64.StdEncoding.EncodeToString(frame))})
		if resp.Status/100 == 2 && resp.Header.Get("Grpc-Status") == "" {
			t.Fatalf("status %d without grpc-status: the request was not denied; body %s", resp.Status, resp.Body)
		}
		id := resp.Header.Get("X-Ailuros-Request-Id")
		if id == "" {
			t.Fatalf("denial has no X-Ailuros-Request-Id (status %d, grpc-status %q)", resp.Status, resp.Header.Get("Grpc-Status"))
		}
		s.WantDecision(t, id, "block", "")
		if seen := s.Seen(t, m); len(seen) != 0 {
			t.Errorf("echo received the blocked call: %+v", seen)
		}
		prompts := s.Prompts(t, m)
		if len(prompts) != 1 || !strings.Contains(prompts[0], "body (decoded from grpc-web-text) [text runs]:\n| "+msg) {
			t.Errorf("prompts = %q, want the decoded message text", prompts)
		}
	})

	t.Run("redacted JSON field never reaches the model", func(t *testing.T) {
		m := newMarker(t)
		secret := "hunter2-" + newMarker(t)
		body := []byte(`{"user":"` + m + `","password":"` + secret + `"}`)
		echoed(t, s.Send(t, "http1", Request{Method: "POST", Path: "/login", Body: body,
			Header: http.Header{"Content-Type": {"application/json"}}}))
		if prompts := s.Prompts(t, m); len(prompts) != 1 || !strings.Contains(prompts[0], `"password"`) {
			t.Errorf("prompts = %q, want one prompt with the redacted body", prompts)
		}
		if leaked := s.Prompts(t, secret); len(leaked) != 0 {
			t.Errorf("the password reached the model: %q", leaked)
		}
	})

	failClosedWhenAilurosDown(t, s, http.StatusInternalServerError, nil)
}
