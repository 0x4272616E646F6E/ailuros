package app

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os/signal"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	"github.com/0x4272616E646F6E/decision-waf/internal/classifier/fake"
	"github.com/0x4272616E646F6E/decision-waf/internal/inspect"
)

func dial(t *testing.T, addr string) *grpc.ClientConn {
	t.Helper()
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func TestServesEnvoyFrontends(t *testing.T) {
	a := start(t, testConfig(""), Options{Classifier: fake.Attacks()})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	authz := authv3.NewAuthorizationClient(dial(t, a.ExtAuthzAddr()))
	resp, err := authz.Check(ctx, &authv3.CheckRequest{Attributes: &authv3.AttributeContext{Request: &authv3.AttributeContext_Request{
		Http: &authv3.AttributeContext_HttpRequest{Method: "GET", Host: "h", Path: "/attack"},
	}}})
	if err != nil || resp.GetStatus().GetCode() != int32(codes.PermissionDenied) || resp.GetDeniedResponse() == nil {
		t.Errorf("ext_authz Check = %v, %v; want denied", resp, err)
	}

	stream, err := extprocv3.NewExternalProcessorClient(dial(t, a.ExtProcAddr())).Process(ctx)
	if err != nil {
		t.Fatal(err)
	}
	headers := &corev3.HeaderMap{Headers: []*corev3.HeaderValue{
		{Key: ":method", RawValue: []byte("GET")}, {Key: ":path", RawValue: []byte("/ok")}, {Key: ":authority", RawValue: []byte("h")},
	}}
	if err := stream.Send(&extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_RequestHeaders{
		RequestHeaders: &extprocv3.HttpHeaders{Headers: headers, EndOfStream: true},
	}}); err != nil {
		t.Fatal(err)
	}
	if r, err := stream.Recv(); err != nil || r.GetRequestHeaders() == nil {
		t.Errorf("ext_proc response = %v, %v; want request-headers CONTINUE", r, err)
	}

	_, metrics := get(t, "http://"+a.AdminAddr()+"/metrics")
	for _, want := range []string{
		`ailuros_decisions_total{category="sqli",frontend="extauthz",outcome="block",route="default"} 1`,
		`ailuros_decisions_total{category="benign",frontend="extproc",outcome="allow",route="default"} 1`,
	} {
		if !strings.Contains(metrics, want) {
			t.Errorf("metrics missing %s", want)
		}
	}
}

func TestGRPCHealthFollowsReadiness(t *testing.T) {
	var healthy atomic.Bool
	probe := func(context.Context) error {
		if healthy.Load() {
			return nil
		}
		return errors.New("model still loading")
	}
	a := start(t, testConfig(""), Options{Classifier: fake.Attacks(), Probe: probe, ProbeInterval: 10 * time.Millisecond})
	status := func(addr string) healthpb.HealthCheckResponse_ServingStatus {
		resp, err := healthpb.NewHealthClient(dial(t, addr)).Check(context.Background(), &healthpb.HealthCheckRequest{})
		if err != nil {
			t.Fatal(err)
		}
		return resp.GetStatus()
	}
	addrs := []string{a.ExtProcAddr(), a.ExtAuthzAddr()}
	for _, addr := range addrs {
		if s := status(addr); s != healthpb.HealthCheckResponse_NOT_SERVING {
			t.Errorf("%s health before ready = %v, want NOT_SERVING", addr, s)
		}
	}
	healthy.Store(true)
	for _, addr := range addrs {
		eventually(t, "gRPC health SERVING", func() bool { return status(addr) == healthpb.HealthCheckResponse_SERVING })
	}
}

func TestEnvoyDowngradeMetric(t *testing.T) {
	cfg := testConfig("")
	cfg.InspectionMode = inspect.ModeStandard
	a := start(t, cfg, Options{Classifier: fake.Attacks()})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	authz := authv3.NewAuthorizationClient(dial(t, a.ExtAuthzAddr()))
	if _, err := authz.Check(ctx, &authv3.CheckRequest{}); err != nil {
		t.Fatal(err)
	}
	_, metrics := get(t, "http://"+a.AdminAddr()+"/metrics")
	if want := `ailuros_mode_downgrades_total{frontend="extauthz"} 1`; !strings.Contains(metrics, want) {
		t.Errorf("metrics missing %s", want)
	}
}

func TestMaxRecvMsgSize(t *testing.T) {
	for deep, want := range map[int]int{1 << 20: 4 << 20, 8 << 20: 8<<20 + 64<<10} {
		if got := maxRecvMsgSize(deep); got != want {
			t.Errorf("maxRecvMsgSize(%d) = %d, want %d", deep, got, want)
		}
	}
}

func TestDeepOversizeAllowWarning(t *testing.T) {
	var buf bytes.Buffer
	cfg := testConfig("")
	cfg.InspectionMode, cfg.DeepOversize = inspect.ModeDeep, inspect.OversizeAllow
	a, err := New(cfg, Options{Classifier: fake.Attacks(), Logger: slog.New(slog.NewTextHandler(&buf, nil))})
	if err != nil {
		t.Fatal(err)
	}
	a.closeListeners()
	signal.Stop(a.hup)
	if !strings.Contains(buf.String(), "AILUROS_DEEP_OVERSIZE=allow") {
		t.Errorf("missing oversize warning; log:\n%s", buf.String())
	}
}

func TestDisabledEnvoyListeners(t *testing.T) {
	cfg := testConfig("")
	cfg.ExtProcAddr, cfg.ExtAuthzAddr = "", ""
	a := start(t, cfg, Options{Classifier: fake.Attacks()})
	if a.ExtProcAddr() != "" || a.ExtAuthzAddr() != "" {
		t.Errorf("addrs = %q, %q; want disabled", a.ExtProcAddr(), a.ExtAuthzAddr())
	}
}
