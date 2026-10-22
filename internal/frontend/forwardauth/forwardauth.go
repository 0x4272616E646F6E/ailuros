package forwardauth

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"

	"github.com/0x4272616E646F6E/decision-waf/internal/decision"
	"github.com/0x4272616E646F6E/decision-waf/internal/frontend"
	"github.com/0x4272616E646F6E/decision-waf/internal/inspect"
)

const FrontendName = "forwardauth"

var consumed = map[string]bool{
	"x-forwarded-method": true, "x-forwarded-uri": true,
	"x-original-method": true, "x-original-uri": true,
	"x-original-url": true, "x-auth-request-redirect": true,
}

var errBothHeaderSets = errors.New("both X-Forwarded-Uri (Traefik) and X-Original-URI (NGINX) are present")

type Server struct {
	engine        *decision.Engine
	exposeVerdict bool
	downgraded    func()
	log           *slog.Logger
}

func New(e *decision.Engine, configured inspect.Mode, exposeVerdict bool, onDowngrade func(), log *slog.Logger) *Server {
	downgraded := frontend.LiteOnly(configured, onDowngrade, log, "forward-auth cannot see request bodies; inspecting in lite mode")
	return &Server{engine: e, exposeVerdict: exposeVerdict, downgraded: downgraded, log: log}
}

func (s *Server) ServeHTTP(w http.ResponseWriter, hr *http.Request) {
	req, err := buildRequest(hr)
	if err != nil {
		switch {
		case errors.Is(err, errBothHeaderSets):
			s.log.Error("forward-auth request carries both the Traefik and NGINX header sets (forgery or proxy misconfiguration); refusing to classify", "error", err)
		default:
			s.log.Error("forward-auth request is missing original-request headers; check the proxy configuration", "error", err)
		}
		w.Header().Set("Content-Type", frontend.DenialContentType)
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"proxy misconfigured"}`))
		return
	}
	s.downgraded()
	src := decision.Source{Frontend: FrontendName, Mode: inspect.ModeLite}
	ctx := otel.GetTextMapPropagator().Extract(hr.Context(), propagation.HeaderCarrier(hr.Header))

	d := frontend.Decide(ctx, s.engine, src, s.log,
		func() *inspect.Request { return req },
		func(ctx context.Context, r *inspect.Request) decision.Decision { return s.engine.Decide(ctx, r, src) })
	s.write(w, d)
}

func (s *Server) write(w http.ResponseWriter, d decision.Decision) {
	frontend.DecisionHeaders(d, s.exposeVerdict, w.Header().Set)
	if !d.Outcome.Denied() {
		w.WriteHeader(http.StatusOK)
		return
	}
	dn := frontend.DenialFor(d)
	status := dn.HTTPStatus
	if d.Outcome == decision.Block {
		status = http.StatusForbidden
	}
	w.Header().Set("Content-Type", frontend.DenialContentType)
	w.WriteHeader(status)
	_, _ = w.Write(dn.Body(d.RequestID))
}

func buildRequest(hr *http.Request) (*inspect.Request, error) {
	h := hr.Header
	var method, uri string
	traefikURI, nginxURI := h.Get("X-Forwarded-Uri"), h.Get("X-Original-Uri")
	switch {
	case traefikURI != "" && nginxURI != "":
		return nil, errBothHeaderSets
	case traefikURI != "":
		method, uri = h.Get("X-Forwarded-Method"), traefikURI
	case nginxURI != "":
		method, uri = h.Get("X-Original-Method"), nginxURI
	}
	if method == "" || uri == "" {
		return nil, errors.New("need X-Forwarded-Method and X-Forwarded-Uri (Traefik) or X-Original-Method and X-Original-URI (NGINX)")
	}
	host := first(h, "X-Forwarded-Host")
	if host == "" {
		host = hr.Host
	}
	headers := make(map[string][]string, len(h))
	for name, values := range h {
		lower := strings.ToLower(name)
		if !consumed[lower] {
			headers[lower] = append([]string(nil), values...)
		}
	}
	r := inspect.NewRequest(method, first(h, "X-Forwarded-Proto"), host, uri, headers)
	r.ClientIP = clientIP(hr)
	return r, nil
}

func first(h http.Header, names ...string) string {
	for _, n := range names {
		if v := h.Get(n); v != "" {
			return v
		}
	}
	return ""
}

func clientIP(hr *http.Request) string {
	if hr.Header.Get("X-Original-Uri") != "" && len(hr.Header.Values("X-Forwarded-Uri")) == 0 {
		if ip := frontend.HostIP(hr.Header.Get("X-Real-Ip")); ip != "" {
			return ip
		}
	}
	if ip := frontend.LastForwardedHop(hr.Header.Values("X-Forwarded-For")); ip != "" {
		return ip
	}
	return frontend.HostIP(hr.RemoteAddr)
}
