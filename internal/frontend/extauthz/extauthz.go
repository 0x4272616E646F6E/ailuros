package extauthz

import (
	"context"
	"log/slog"
	"strings"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	rpcstatus "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/0x4272616E646F6E/decision-waf/internal/decision"
	"github.com/0x4272616E646F6E/decision-waf/internal/frontend"
	"github.com/0x4272616E646F6E/decision-waf/internal/frontend/envoyreq"
	"github.com/0x4272616E646F6E/decision-waf/internal/inspect"
)

const FrontendName = "extauthz"

type Server struct {
	authv3.UnimplementedAuthorizationServer
	engine        *decision.Engine
	exposeVerdict bool
	ja4Header     string
	downgraded    func()
	log           *slog.Logger
}

func New(e *decision.Engine, configured inspect.Mode, exposeVerdict bool, ja4Header string, onDowngrade func(), log *slog.Logger) *Server {
	downgraded := frontend.LiteOnly(configured, onDowngrade, log, "ext_authz cannot inspect request bodies; inspecting in lite mode")
	return &Server{engine: e, exposeVerdict: exposeVerdict, ja4Header: ja4Header, downgraded: downgraded, log: log}
}

func (s *Server) Check(ctx context.Context, req *authv3.CheckRequest) (*authv3.CheckResponse, error) {
	d := s.decide(ctx, req)
	if err := ctx.Err(); err != nil {
		return nil, status.FromContextError(err).Err()
	}
	return s.response(d), nil
}

func (s *Server) decide(ctx context.Context, req *authv3.CheckRequest) decision.Decision {
	src := decision.Source{Frontend: FrontendName, Mode: inspect.ModeLite}
	return frontend.Decide(ctx, s.engine, src, s.log,
		func() *inspect.Request {
			r := buildRequest(req, s.ja4Header)
			s.downgraded()
			return r
		},
		func(ctx context.Context, r *inspect.Request) decision.Decision {
			return envoyreq.Decide(envoyreq.TraceContext(ctx, r.Headers), s.engine, r, src, "")
		})
}

func (s *Server) response(d decision.Decision) *authv3.CheckResponse {
	if !d.Outcome.Denied() {
		return &authv3.CheckResponse{
			Status:       &rpcstatus.Status{Code: int32(codes.OK)},
			HttpResponse: &authv3.CheckResponse_OkResponse{OkResponse: &authv3.OkHttpResponse{Headers: envoyreq.DecisionHeaders(d, s.exposeVerdict)}},
		}
	}
	dn := frontend.DenialFor(d)
	return &authv3.CheckResponse{
		Status: &rpcstatus.Status{Code: int32(dn.GRPCStatus), Message: dn.Message}, //nolint:gosec // G115: Denial status codes are fixed constants (400/403/413/503, gRPC 3/7/8/14)
		HttpResponse: &authv3.CheckResponse_DeniedResponse{DeniedResponse: &authv3.DeniedHttpResponse{
			Status:  &typev3.HttpStatus{Code: typev3.StatusCode(dn.HTTPStatus)}, //nolint:gosec // G115: Denial status codes are fixed constants (400/403/413/503, gRPC 3/7/8/14)
			Headers: envoyreq.DenyHeaders(d, s.exposeVerdict),
			Body:    string(dn.Body(d.RequestID)),
		}},
	}
}

func buildRequest(req *authv3.CheckRequest, ja4Header string) *inspect.Request {
	attrs := req.GetAttributes()
	h := attrs.GetRequest().GetHttp()
	var headers map[string][]string
	if hm := h.GetHeaderMap().GetHeaders(); len(hm) > 0 {
		headers = envoyreq.Headers(hm)
	} else {
		headers = envoyreq.HeadersFromMap(h.GetHeaders())
	}
	target := h.GetPath()
	if q := h.GetQuery(); q != "" && !strings.Contains(target, "?") {
		target += "?" + q
	}
	r := inspect.NewRequest(h.GetMethod(), h.GetScheme(), h.GetHost(), target, headers)
	r.Protocol = h.GetProtocol()
	r.ClientIP = envoyreq.ClientIP(attrs.GetSource().GetAddress().GetSocketAddress().GetAddress(), headers)
	if sni := attrs.GetTlsSession().GetSni(); sni != "" {
		r.TLS = &inspect.TLSInfo{SNI: sni}
	}
	r.JA4 = frontend.TakeJA4(r.Headers, ja4Header)
	return r
}
