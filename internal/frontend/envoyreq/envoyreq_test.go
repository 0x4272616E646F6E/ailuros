package envoyreq

import (
	"context"
	"reflect"
	"testing"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"

	"github.com/0x4272616E646F6E/decision-waf/internal/classifier"
	"github.com/0x4272616E646F6E/decision-waf/internal/decision"
	"github.com/0x4272616E646F6E/decision-waf/internal/frontend"
)

func TestHeaderValueReadsRawOrValue(t *testing.T) {
	cases := []struct {
		h    *corev3.HeaderValue
		want string
	}{
		{&corev3.HeaderValue{Key: "a", RawValue: []byte("raw")}, "raw"},
		{&corev3.HeaderValue{Key: "a", Value: "plain"}, "plain"},
		{&corev3.HeaderValue{Key: "a", Value: "plain", RawValue: []byte("raw")}, "raw"},
		{&corev3.HeaderValue{Key: "a"}, ""},
	}
	for _, c := range cases {
		if got := HeaderValue(c.h); got != c.want {
			t.Errorf("HeaderValue(%v) = %q, want %q", c.h, got, c.want)
		}
	}
}

func TestClientIP(t *testing.T) {
	xff := map[string][]string{"x-forwarded-for": {"6.6.6.6, 10.0.0.2"}}
	cases := []struct {
		name, source string
		headers      map[string][]string
		want         string
	}{
		{"ipv4 with port", "203.0.113.9:51234", xff, "203.0.113.9"},
		{"ipv6 with port", "[2001:db8::1]:443", nil, "2001:db8::1"},
		{"bare ip", "203.0.113.9", nil, "203.0.113.9"},
		{"invalid source falls to last XFF hop", "envoy-internal", xff, "10.0.0.2"},
		{"no source falls to last XFF hop", "", xff, "10.0.0.2"},
		{"invalid last hop", "", map[string][]string{"x-forwarded-for": {"1.2.3.4, junk"}}, ""},
		{"nothing", "", nil, ""},
	}
	for _, c := range cases {
		if got := ClientIP(c.source, c.headers); got != c.want {
			t.Errorf("%s: ClientIP = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestWithDeadlineMargin(t *testing.T) {
	parent, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	pdl, _ := parent.Deadline()
	ctx, cancel2 := WithDeadlineMargin(parent)
	defer cancel2()
	if dl, ok := ctx.Deadline(); !ok || pdl.Sub(dl) != DeadlineMargin {
		t.Errorf("deadline = %v (ok %v), want parent deadline - %v", dl, ok, DeadlineMargin)
	}
	ctx, cancel3 := WithDeadlineMargin(context.Background())
	defer cancel3()
	if _, ok := ctx.Deadline(); ok {
		t.Error("no incoming deadline should add none")
	}
}

func TestDecisionHeaders(t *testing.T) {
	d := decision.Decision{RequestID: "abc", Outcome: decision.Block, Classified: true, Verdict: classifier.Verdict{Benign: 0.045, Category: "injection", Confidence: 0.576}}
	h := DecisionHeaders(d, false)
	if len(h) != 1 || h[0].GetHeader().GetKey() != frontend.RequestIDHeader || h[0].GetHeader().GetValue() != "abc" ||
		h[0].GetAppendAction() != corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD {
		t.Errorf("headers = %v", h)
	}
	h = DecisionHeaders(d, true)
	if len(h) != 2 || h[1].GetHeader().GetKey() != frontend.DecisionHeader || h[1].GetHeader().GetValue() != "block; attack_score=0.955; category=injection; confidence=0.576" {
		t.Errorf("headers with expose = %v", h)
	}
}

func TestTraceContext(t *testing.T) {
	otel.SetTextMapPropagator(propagation.TraceContext{})
	t.Cleanup(func() { otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator()) })
	h := map[string][]string{"traceparent": {"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"}}
	sc := trace.SpanContextFromContext(TraceContext(context.Background(), h))
	if sc.TraceID().String() != "4bf92f3577b34da6a3ce929d0e0e4736" || !sc.IsRemote() {
		t.Errorf("span context = %+v, want the incoming trace", sc)
	}
}

func TestSetHeaderFillsValueAndRawValue(t *testing.T) {
	h := SetHeader("x-decision-waf-request-id", "4c0185a4576944a9")
	if got := h.GetHeader().GetValue(); got != "4c0185a4576944a9" {
		t.Errorf("value = %q", got)
	}
	if got := string(h.GetHeader().GetRawValue()); got != "4c0185a4576944a9" {
		t.Errorf("raw_value = %q, want the header value (ext_proc reads raw_value)", got)
	}
	if h.GetAppendAction() != corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD {
		t.Errorf("append action = %v", h.GetAppendAction())
	}
}

func TestHeadersAndHeadersFromMapAgree(t *testing.T) {
	m := map[string]string{"": "x", ":path": "/a", ":method": "GET", "Content-Type": "application/json", "x-a": "1"}
	var hvs []*corev3.HeaderValue
	for k, v := range m {
		hvs = append(hvs, &corev3.HeaderValue{Key: k, RawValue: []byte(v)})
	}
	want := map[string][]string{"content-type": {"application/json"}, "x-a": {"1"}}
	if got := Headers(hvs); !reflect.DeepEqual(got, want) {
		t.Errorf("Headers = %v, want %v", got, want)
	}
	if got := HeadersFromMap(m); !reflect.DeepEqual(got, want) {
		t.Errorf("HeadersFromMap = %v, want %v", got, want)
	}
}
