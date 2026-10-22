package frontend

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"

	"google.golang.org/grpc/codes"

	"github.com/0x4272616E646F6E/decision-waf/internal/classifier"
	"github.com/0x4272616E646F6E/decision-waf/internal/decision"
	"github.com/0x4272616E646F6E/decision-waf/internal/inspect"
	"github.com/0x4272616E646F6E/decision-waf/internal/policy"
)

const RequestIDHeader = "x-decision-waf-request-id"
const DecisionHeader = "x-decision-waf-decision"
const DenialContentType = "application/json"

func DecisionHeaders(d decision.Decision, exposeVerdict bool, set func(name, value string)) {
	set(RequestIDHeader, d.RequestID)
	if exposeVerdict {
		set(DecisionHeader, d.DebugHeader())
	}
}

func malformed(r *inspect.Request) bool {
	return r != nil && (r.MultipleContentTypes() || r.Method != "" && !inspect.IsToken(r.Method))
}

func staticFailure(e *decision.Engine, r *inspect.Request, src decision.Source) decision.Decision {
	d := decision.Decision{RequestID: decision.NewRequestID(), Outcome: decision.FailOpen, Reason: classifier.ReasonPanic, Source: src}
	if e.FailureModeFor(r) == policy.FailClosed {
		d.Outcome = decision.FailClosed
	}
	return d
}

type Denial struct {
	HTTPStatus int
	GRPCStatus codes.Code
	Message    string
}

func DenialFor(d decision.Decision) Denial {
	switch {
	case d.Outcome == decision.FailClosed:
		return Denial{HTTPStatus: http.StatusServiceUnavailable, GRPCStatus: codes.Unavailable, Message: "service unavailable"}
	case !d.Classified && d.Note == decision.NoteMalformed:
		return Denial{HTTPStatus: http.StatusBadRequest, GRPCStatus: codes.InvalidArgument, Message: "malformed request"}
	case d.Note == decision.NoteLimit:
		return Denial{HTTPStatus: http.StatusForbidden, GRPCStatus: codes.PermissionDenied, Message: "request blocked"}
	case !d.ClassifierCalled && d.Note != "":
		return Denial{HTTPStatus: http.StatusRequestEntityTooLarge, GRPCStatus: codes.ResourceExhausted, Message: "request too large"}
	}
	return Denial{HTTPStatus: http.StatusForbidden, GRPCStatus: codes.PermissionDenied, Message: "request blocked"}
}

func (dn Denial) Body(requestID string) []byte {
	b, _ := json.Marshal(map[string]string{"error": dn.Message, "request_id": requestID})
	return b
}

func LastForwardedHop(xff []string) string {
	if len(xff) == 0 {
		return ""
	}
	hops := strings.Split(xff[len(xff)-1], ",")
	return HostIP(hops[len(hops)-1])
}

func HostIP(addr string) string {
	addr = strings.TrimSpace(addr)
	if host, _, err := net.SplitHostPort(addr); err == nil {
		addr = host
	}
	ip, err := netip.ParseAddr(strings.TrimSuffix(strings.TrimPrefix(addr, "["), "]"))
	if err != nil {
		return ""
	}
	return ip.String()
}

func Decide(ctx context.Context, e *decision.Engine, src decision.Source, log *slog.Logger,
	build func() *inspect.Request, decide func(context.Context, *inspect.Request) decision.Decision) (d decision.Decision) {
	var computed decision.Decision
	var r *inspect.Request
	defer func() {
		if p := recover(); p != nil {
			d = AfterPanic(ctx, e, src, log, r, computed, p)
		}
	}()
	r = build()
	sctx := decision.WithSink(ctx, &computed)
	if d, ok := RefuseMalformed(sctx, e, src, r); ok {
		return d
	}
	return decide(sctx, r)
}

func RefuseMalformed(ctx context.Context, e *decision.Engine, src decision.Source, r *inspect.Request) (d decision.Decision, ok bool) {
	if !malformed(r) {
		return decision.Decision{}, false
	}
	return e.Bypass(ctx, r, src, decision.Block, decision.NoteMalformed), true
}

func AfterPanic(ctx context.Context, e *decision.Engine, src decision.Source, log *slog.Logger,
	r *inspect.Request, computed decision.Decision, p any) decision.Decision {
	log.Error("panic in frontend handler", "frontend", src.Frontend, "panic", fmt.Sprint(p))
	if computed.Outcome.Denied() {
		return computed
	}
	return fail(ctx, e, src, log, r)
}

func fail(ctx context.Context, e *decision.Engine, src decision.Source, log *slog.Logger, r *inspect.Request) (d decision.Decision) {
	defer func() {
		if p := recover(); p != nil {
			log.Error("panic while applying the failure mode", "frontend", src.Frontend, "panic", fmt.Sprint(p))
			d = staticFailure(e, r, src)
		}
	}()
	return e.Fail(ctx, r, src, classifier.ReasonPanic)
}

func LiteOnly(configured inspect.Mode, onDowngrade func(), log *slog.Logger, warn string) func() {
	if configured == inspect.ModeLite {
		return func() {}
	}
	log.Warn(warn, "configured_mode", configured)
	if onDowngrade == nil {
		return func() {}
	}
	return onDowngrade
}

func TakeJA4(headers map[string][]string, name string) string {
	if name == "" {
		return ""
	}
	v, ok := headers[name]
	if !ok {
		return ""
	}
	delete(headers, name)
	if len(v) != 1 || strings.TrimSpace(v[0]) == "-" {
		return ""
	}
	return strings.TrimSpace(v[0])
}
