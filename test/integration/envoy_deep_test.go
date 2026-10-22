//go:build integration

package integration

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/encoding"
	"google.golang.org/grpc/encoding/gzip"

	"github.com/0x4272616E646F6E/decision-waf/test/integration/echo/echopb"
)

type fakeSnappy struct{}

type nopWriteCloser struct{ io.Writer }

func (nopWriteCloser) Close() error { return nil }

func (fakeSnappy) Compress(w io.Writer) (io.WriteCloser, error) { return nopWriteCloser{w}, nil }
func (fakeSnappy) Decompress(r io.Reader) (io.Reader, error)    { return r, nil }
func (fakeSnappy) Name() string                                 { return "snappy" }

func init() { encoding.RegisterCompressor(fakeSnappy{}) }

var deepEnv = map[string]string{"AILUROS_DEEP_MAX_MESSAGES": "3"}

func TestEnvoyDeep(t *testing.T) {
	t.Parallel()
	s := up(t, "envoy-deep", deepEnv)
	t.Run("http1", func(t *testing.T) { sharedCases(t, s, "http1") })
	bodyCases(t, s)

	t.Run("benign POST is classified headers first, then body", func(t *testing.T) {
		m := newMarker(t)
		v := echoed(t, s.Send(t, "http1", Request{Method: "POST", Path: "/upload/" + m, Body: []byte("hello " + m)}))
		wantAllows(t, s.Decisions(t, upstreamID(t, v), 2), "", "")
		prompts := s.Prompts(t, m)
		if len(prompts) != 2 || strings.Contains(prompts[0], "\nbody") || !strings.Contains(prompts[1], "\nbody:\n| hello "+m) {
			t.Errorf("prompts = %q, want a headers-only prompt, then one with the body", prompts)
		}
	})

	t.Run("oversize body under classify_prefix: prefix classified, whole body forwarded", func(t *testing.T) {
		m := newMarker(t)
		body := largeBody(m, 40000, " attack")
		v := echoed(t, s.Send(t, "http1", Request{Method: "POST", Path: "/upload", Body: body}))
		if !bytes.Equal(v.Body, body) {
			t.Errorf("echo received %d bytes, want the %d bytes sent", len(v.Body), len(body))
		}
		wantAllows(t, s.Decisions(t, upstreamID(t, v), 2), "", "oversize")
		prompts := s.Prompts(t, m)
		if len(prompts) != 1 || !strings.Contains(prompts[0], "body (truncated):") || strings.Contains(prompts[0], "attack") {
			t.Errorf("prompts = %q, want one truncated body without the tail", prompts)
		}
	})

	deepStreamCases(t, s)

	t.Run("gRPC gzip-compressed attack is decompressed and blocked", func(t *testing.T) {
		m := newMarker(t)
		_, err := echopb.Unary(grpcContext(t), s.GRPC(t), &echopb.Msg{Value: "attack " + m}, grpc.UseCompressor(gzip.Name))
		wantCode(t, err, codes.PermissionDenied)
		prompts := s.Prompts(t, m)
		if len(prompts) != 1 || !strings.Contains(prompts[0], "attack "+m) {
			t.Errorf("prompts = %q, want the decompressed message text", prompts)
		}
	})

	t.Run("gRPC snappy encoding is uninspectable and refused with status 8", func(t *testing.T) {
		m := newMarker(t)
		_, err := echopb.Unary(grpcContext(t), s.GRPC(t), &echopb.Msg{Value: "hello " + m}, grpc.UseCompressor("snappy"))
		wantCode(t, err, codes.ResourceExhausted)
		if seen := s.Seen(t, m); len(seen) != 0 {
			t.Errorf("echo received the refused message: %+v", seen)
		}
	})

	t.Run("gRPC stream past AILUROS_DEEP_MAX_MESSAGES is cut off", func(t *testing.T) {
		m := newMarker(t)
		stream, err := echopb.Stream(grpcContext(t), s.GRPC(t))
		if err != nil {
			t.Fatal(err)
		}
		for i := range 2 {
			if err := stream.Send(&echopb.Msg{Value: m}); err != nil {
				t.Fatal(err)
			}
			if _, err := stream.Recv(); err != nil {
				t.Fatalf("reply %d: %v", i+1, err)
			}
		}
		_ = stream.Send(&echopb.Msg{Value: m})
		_, err = stream.Recv()
		wantCode(t, err, codes.Internal)
		if seen := s.Seen(t, m); len(seen) != 2 {
			t.Errorf("echo saw %d messages, want 2", len(seen))
		}
	})

	t.Run("gRPC protobuf payload reaches the model as text runs", func(t *testing.T) {
		m := newMarker(t)
		if _, err := echopb.Unary(grpcContext(t), s.GRPC(t), &echopb.Msg{Value: "hello " + m}); err != nil {
			t.Fatal(err)
		}
		prompts := s.Prompts(t, m)
		if len(prompts) != 1 || !strings.Contains(prompts[0], "body [text runs]:\n| hello "+m+"\n") {
			t.Errorf("prompts = %q, want the message as a text run", prompts)
		}
	})

	failClosedWhenAilurosDown(t, s, http.StatusInternalServerError, nil)
}

func wantAllows(t *testing.T, ds []Decision, reasons ...string) {
	t.Helper()
	if len(ds) != len(reasons) {
		t.Errorf("logged %d decisions, want %d: %v", len(ds), len(reasons), ds)
	}
	for i, d := range ds[:min(len(ds), len(reasons))] {
		if d.Str("outcome") != "allow" || d.Str("reason") != reasons[i] {
			t.Errorf("decision %d: outcome=%q reason=%q, want allow with reason %q", i+1, d.Str("outcome"), d.Str("reason"), reasons[i])
		}
	}
}

func TestEnvoyDeepOversizeBlock(t *testing.T) {
	t.Parallel()
	s := up(t, "envoy-deep", map[string]string{"AILUROS_DEEP_OVERSIZE": "block"})
	m := newMarker(t)
	resp := s.Send(t, "http1", Request{Method: "POST", Path: "/upload", Body: largeBody(m, 40000, "")})
	s.WantDecision(t, wantDeny(t, resp, http.StatusRequestEntityTooLarge, "request too large"), "block", "oversize")
	if seen := s.Seen(t, m); len(seen) != 0 {
		t.Errorf("echo received the oversize body: %+v", seen)
	}
}
