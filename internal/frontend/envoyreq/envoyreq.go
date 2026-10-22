package envoyreq

import (
	"context"
	"errors"
	"maps"
	"slices"
	"strings"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"

	"github.com/0x4272616E646F6E/decision-waf/internal/classifier"
	"github.com/0x4272616E646F6E/decision-waf/internal/decision"
	"github.com/0x4272616E646F6E/decision-waf/internal/frontend"
	"github.com/0x4272616E646F6E/decision-waf/internal/inspect"
)

const DeadlineMargin = 50 * time.Millisecond

func HeaderValue(h *corev3.HeaderValue) string {
	if raw := h.GetRawValue(); len(raw) > 0 {
		return string(raw)
	}
	return h.GetValue()
}

func ClientIP(source string, headers map[string][]string) string {
	if ip := frontend.HostIP(source); ip != "" {
		return ip
	}
	return frontend.LastForwardedHop(headers["x-forwarded-for"])
}

func WithDeadlineMargin(ctx context.Context) (context.Context, context.CancelFunc) {
	if dl, ok := ctx.Deadline(); ok {
		return context.WithDeadline(ctx, dl.Add(-DeadlineMargin))
	}
	return context.WithCancel(ctx)
}

func ExpiredReason(err error) classifier.Reason {
	if errors.Is(err, context.DeadlineExceeded) {
		return classifier.ReasonTimeout
	}
	return classifier.ReasonCanceled
}

func TraceContext(ctx context.Context, headers map[string][]string) context.Context {
	carrier := propagation.MapCarrier{}
	for k, v := range headers {
		if len(v) > 0 {
			carrier[k] = v[0]
		}
	}
	return otel.GetTextMapPropagator().Extract(ctx, carrier)
}

func SetHeader(key, value string) *corev3.HeaderValueOption {
	return &corev3.HeaderValueOption{
		Header:       &corev3.HeaderValue{Key: key, Value: value, RawValue: []byte(value)},
		AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
	}
}

func DecisionHeaders(d decision.Decision, exposeVerdict bool) []*corev3.HeaderValueOption {
	var h []*corev3.HeaderValueOption
	frontend.DecisionHeaders(d, exposeVerdict, func(k, v string) { h = append(h, SetHeader(k, v)) })
	return h
}

func DenyHeaders(d decision.Decision, exposeVerdict bool) []*corev3.HeaderValueOption {
	return append(DecisionHeaders(d, exposeVerdict), SetHeader("content-type", frontend.DenialContentType))
}

func Headers(hvs []*corev3.HeaderValue) map[string][]string {
	out := map[string][]string{}
	for _, hv := range hvs {
		if key, ok := headerKey(hv.GetKey()); ok {
			out[key] = append(out[key], HeaderValue(hv))
		}
	}
	return out
}

func HeadersFromMap(m map[string]string) map[string][]string {
	out := map[string][]string{}
	for _, name := range slices.Sorted(maps.Keys(m)) {
		if key, ok := headerKey(name); ok {
			out[key] = append(out[key], m[name])
		}
	}
	return out
}

func headerKey(name string) (key string, ok bool) {
	key = strings.ToLower(name)
	return key, key != "" && key[0] != ':'
}

func Decide(ctx context.Context, e *decision.Engine, r *inspect.Request, src decision.Source, note decision.Note) decision.Decision {
	ctx, cancel := WithDeadlineMargin(ctx)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return e.Fail(ctx, r, src, ExpiredReason(err))
	}
	return e.DecideNote(ctx, r, src, note)
}
