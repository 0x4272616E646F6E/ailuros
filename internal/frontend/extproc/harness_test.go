package extproc

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/0x4272616E646F6E/ailuros/internal/classifier"
	"github.com/0x4272616E646F6E/ailuros/internal/decision"
	"github.com/0x4272616E646F6E/ailuros/internal/frontend/frontendtest"
	"github.com/0x4272616E646F6E/ailuros/internal/policy"
)

var hex16 = regexp.MustCompile(`^[0-9a-f]{16}$`)

type harness struct {
	t          *testing.T
	client     extprocv3.ExternalProcessorClient
	obs        *frontendtest.Recorder
	downgrades *atomic.Int64
}

func newHarness(t *testing.T, c classifier.Classifier, cfg Config, failure policy.FailureMode) *harness {
	t.Helper()
	obs := &frontendtest.Recorder{}
	return newHarnessEngine(t, frontendtest.Engine(c, failure, obs), obs, cfg)
}

func newHarnessEngine(t *testing.T, e *decision.Engine, obs *frontendtest.Recorder, cfg Config) *harness {
	t.Helper()
	var downgrades atomic.Int64
	conn := frontendtest.Dial(t, func(s *grpc.Server) {
		extprocv3.RegisterExternalProcessorServer(s, New(e, cfg, func() { downgrades.Add(1) }, slog.New(slog.DiscardHandler)))
	})
	return &harness{t: t, client: extprocv3.NewExternalProcessorClient(conn), obs: obs, downgrades: &downgrades}
}

func (h *harness) open() extprocv3.ExternalProcessor_ProcessClient {
	h.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	h.t.Cleanup(cancel)
	return h.openCtx(ctx)
}

func (h *harness) openCtx(ctx context.Context) extprocv3.ExternalProcessor_ProcessClient {
	h.t.Helper()
	s, err := h.client.Process(ctx)
	if err != nil {
		h.t.Fatal(err)
	}
	return s
}

func send(t *testing.T, s extprocv3.ExternalProcessor_ProcessClient, msgs ...*extprocv3.ProcessingRequest) {
	t.Helper()
	for _, m := range msgs {
		if err := s.Send(m); err != nil {
			t.Fatal(err)
		}
	}
}

func recv(t *testing.T, s extprocv3.ExternalProcessor_ProcessClient) *extprocv3.ProcessingResponse {
	t.Helper()
	r, err := s.Recv()
	if err != nil {
		t.Fatalf("Recv: %v", err)
	}
	return r
}

func expectEnd(t *testing.T, s extprocv3.ExternalProcessor_ProcessClient) {
	t.Helper()
	_ = s.CloseSend()
	if r, err := s.Recv(); !errors.Is(err, io.EOF) {
		t.Fatalf("Recv = %v, %v; want end of stream", r, err)
	}
}

var (
	httpHeaders = []string{":method", "POST", ":scheme", "https", ":authority", "shop.example.com", ":path", "/api/cart?id=7", "content-type", "application/json"}
	grpcHeaders = []string{":method", "POST", ":scheme", "http", ":authority", "api.internal", ":path", "/payments.v1.Payments/Charge", "content-type", "application/grpc"}
)

func headersMsg(eos bool, kv ...string) *extprocv3.ProcessingRequest {
	hm := &corev3.HeaderMap{}
	for i := 0; i < len(kv); i += 2 {
		hm.Headers = append(hm.Headers, &corev3.HeaderValue{Key: kv[i], RawValue: []byte(kv[i+1])})
	}
	return &extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_RequestHeaders{
		RequestHeaders: &extprocv3.HttpHeaders{Headers: hm, EndOfStream: eos},
	}}
}

func with(kv []string, extra ...string) []string { return append(append([]string{}, kv...), extra...) }

func withAttributes(m *extprocv3.ProcessingRequest, attrs map[string]any) *extprocv3.ProcessingRequest {
	s, err := structpb.NewStruct(attrs)
	if err != nil {
		panic(err)
	}
	m.Attributes = map[string]*structpb.Struct{attributesKey: s}
	return m
}

func bodyMsg(b []byte, eos bool) *extprocv3.ProcessingRequest {
	return &extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_RequestBody{
		RequestBody: &extprocv3.HttpBody{Body: b, EndOfStream: eos},
	}}
}

func trailersMsg() *extprocv3.ProcessingRequest {
	return &extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_RequestTrailers{
		RequestTrailers: &extprocv3.HttpTrailers{Trailers: &corev3.HeaderMap{}},
	}}
}

func mutationHeaders(t *testing.T, r *extprocv3.ProcessingResponse) map[string]string {
	t.Helper()
	var common *extprocv3.CommonResponse
	switch {
	case r.GetRequestHeaders() != nil:
		common = r.GetRequestHeaders().GetResponse()
	case r.GetRequestBody() != nil:
		common = r.GetRequestBody().GetResponse()
	default:
		t.Fatalf("response = %v, want a request headers/body response", r)
	}
	if common.GetStatus() != extprocv3.CommonResponse_CONTINUE {
		t.Errorf("status = %v, want CONTINUE", common.GetStatus())
	}
	out := map[string]string{}
	for _, o := range common.GetHeaderMutation().GetSetHeaders() {
		out[o.GetHeader().GetKey()] = o.GetHeader().GetValue()
	}
	return out
}

func expectImmediate(t *testing.T, r *extprocv3.ProcessingResponse, httpStatus int, grpcStatus uint32, msg string) string {
	t.Helper()
	ir := r.GetImmediateResponse()
	if ir == nil {
		t.Fatalf("response = %v, want ImmediateResponse", r)
	}
	if int(ir.GetStatus().GetCode()) != httpStatus {
		t.Errorf("status = %v, want %d", ir.GetStatus().GetCode(), httpStatus)
	}
	if grpcStatus == 0 && ir.GetGrpcStatus() != nil || grpcStatus != 0 && ir.GetGrpcStatus().GetStatus() != grpcStatus {
		t.Errorf("grpc status = %v, want %d", ir.GetGrpcStatus(), grpcStatus)
	}
	headers := map[string]string{}
	for _, o := range ir.GetHeaders().GetSetHeaders() {
		headers[o.GetHeader().GetKey()] = o.GetHeader().GetValue()
	}
	var body map[string]string
	if err := json.Unmarshal(ir.GetBody(), &body); err != nil {
		t.Fatalf("body %q: %v", ir.GetBody(), err)
	}
	id := headers["x-ailuros-request-id"]
	if !hex16.MatchString(id) || body["request_id"] != id || body["error"] != msg || headers["content-type"] != "application/json" {
		t.Errorf("headers = %v, body = %v; want error %q with matching request id", headers, body, msg)
	}
	if strings.Contains(string(ir.GetBody()), "sqli") {
		t.Error("category leaked to the client")
	}
	return id
}

func streamed(t *testing.T, s extprocv3.ExternalProcessor_ProcessClient, n int) (data []byte, eos bool) {
	t.Helper()
	for i := 0; n == 0 || i < n; i++ {
		r := recv(t, s)
		sr := r.GetRequestBody().GetResponse().GetBodyMutation().GetStreamedResponse()
		if sr == nil {
			t.Fatalf("response = %v, want a streamed body chunk", r)
		}
		if len(sr.GetBody()) > maxChunk {
			t.Errorf("chunk of %d bytes exceeds 64 KiB", len(sr.GetBody()))
		}
		data = append(data, sr.GetBody()...)
		if sr.GetEndOfStream() {
			return data, true
		}
	}
	return data, false
}
