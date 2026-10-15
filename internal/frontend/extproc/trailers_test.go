package extproc

import (
	"bytes"
	"context"
	"slices"
	"strings"
	"testing"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"

	"github.com/0x4272616E646F6E/ailuros/internal/classifier"
	"github.com/0x4272616E646F6E/ailuros/internal/classifier/fake"
	"github.com/0x4272616E646F6E/ailuros/internal/inspect"
	"github.com/0x4272616E646F6E/ailuros/internal/policy"
)

func byHeaders() *fake.Classifier {
	return fake.New(func(_ context.Context, r *inspect.Request, _ []policy.Category) (classifier.Verdict, error) {
		for _, v := range r.Headers {
			if slices.ContainsFunc(v, func(s string) bool { return strings.Contains(s, "attack") }) {
				return classifier.Verdict{Benign: 0.01, Category: "rce", Confidence: 0.99}, nil
			}
		}
		if bytes.Contains(r.Body, []byte("attack")) {
			return classifier.Verdict{Benign: 0.01, Category: "rce", Confidence: 0.99}, nil
		}
		return classifier.Verdict{Benign: 1}, nil
	})
}

func trailersWith(kv ...string) *extprocv3.ProcessingRequest {
	hm := &corev3.HeaderMap{}
	for i := 0; i < len(kv); i += 2 {
		hm.Headers = append(hm.Headers, &corev3.HeaderValue{Key: kv[i], RawValue: []byte(kv[i+1])})
	}
	return &extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_RequestTrailers{
		RequestTrailers: &extprocv3.HttpTrailers{Trailers: hm},
	}}
}

func TestRequestTrailersAreClassified(t *testing.T) {
	t.Run("deep HTTP", func(t *testing.T) {
		f := byHeaders()
		h := newHarness(t, f, deep(1<<20, inspect.OversizeClassifyPrefix), policy.FailOpen)
		s := h.open()
		send(t, s, headersMsg(false, httpHeaders...))
		recv(t, s)
		send(t, s, bodyMsg([]byte(`{"q":"hello"}`), false), trailersWith("x-cmd", "attack"))
		expectImmediate(t, recv(t, s), 403, 0, "request blocked")
		if got := f.Last().Headers["x-cmd"]; len(got) != 1 || got[0] != "attack" {
			t.Errorf("classifier saw x-cmd %q, want the trailer", got)
		}
	})
	t.Run("deep gRPC", func(t *testing.T) {
		f := byHeaders()
		h := newHarness(t, f, deep(1<<20, inspect.OversizeClassifyPrefix), policy.FailOpen)
		s := h.open()
		send(t, s, headersMsg(false, grpcHeaders...))
		recv(t, s)
		send(t, s, bodyMsg(grpcMsg(false, []byte("hello")), false))
		streamed(t, s, 1)
		send(t, s, trailersWith("x-cmd", "attack"))
		expectImmediate(t, recv(t, s), 403, 7, "request blocked")
		if f.Calls() != 3 {
			t.Errorf("classifier calls = %d, want headers, message, and trailers", f.Calls())
		}
	})
	t.Run("standard, trailers before a body", func(t *testing.T) {
		h := newHarness(t, byHeaders(), standard, policy.FailOpen)
		s := h.open()
		send(t, s, headersMsg(false, httpHeaders...))
		recv(t, s)
		send(t, s, trailersWith("x-cmd", "attack"))
		expectImmediate(t, recv(t, s), 403, 0, "request blocked")
	})
}

func TestEmptyTrailersAddNoDecision(t *testing.T) {
	f := byHeaders()
	h := newHarness(t, f, deep(1<<20, inspect.OversizeClassifyPrefix), policy.FailOpen)
	s := h.open()
	send(t, s, headersMsg(false, grpcHeaders...))
	recv(t, s)
	send(t, s, bodyMsg(grpcMsg(false, []byte("hello")), false), trailersMsg())
	for {
		if r := recv(t, s); r.GetRequestTrailers() != nil || r.GetImmediateResponse() != nil {
			break
		}
	}
	if f.Calls() != 2 {
		t.Errorf("classifier calls = %d, want headers and the message only", f.Calls())
	}
}
