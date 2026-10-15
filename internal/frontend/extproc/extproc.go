package extproc

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strconv"
	"sync"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	filterv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"google.golang.org/grpc/status"

	"github.com/0x4272616E646F6E/ailuros/internal/classifier"
	"github.com/0x4272616E646F6E/ailuros/internal/decision"
	"github.com/0x4272616E646F6E/ailuros/internal/frontend"
	"github.com/0x4272616E646F6E/ailuros/internal/frontend/envoyreq"
	"github.com/0x4272616E646F6E/ailuros/internal/inspect"
	"github.com/0x4272616E646F6E/ailuros/internal/signals"
)

const (
	FrontendName  = "extproc"
	attributesKey = "envoy.filters.http.ext_proc"
	maxChunk      = 64 << 10
)

type Config struct {
	Mode            inspect.Mode
	BodyMaxBytes    int
	DeepMaxBytes    int
	DeepOversize    inspect.Oversize
	DeepMaxMessages int
	ExposeVerdict   bool
	JA4Header       string
}

type Server struct {
	extprocv3.UnimplementedExternalProcessorServer
	engine      *decision.Engine
	cfg         Config
	onDowngrade func()
	log         *slog.Logger
	mismatch    sync.Once
	undecided   sync.Once
}

func New(e *decision.Engine, cfg Config, onDowngrade func(), log *slog.Logger) *Server {
	if onDowngrade == nil {
		onDowngrade = func() {}
	}
	return &Server{engine: e, cfg: cfg, onDowngrade: onDowngrade, log: log}
}

func (s *Server) Process(ps extprocv3.ExternalProcessor_ProcessServer) error {
	st := &stream{s: s, ctx: ps.Context(), src: decision.Source{Frontend: FrontendName, Mode: s.cfg.Mode}}
	defer st.checkUndecided()
	for {
		msg, err := ps.Recv()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		resps, done, herr := st.safeHandle(msg)
		if herr != nil {
			return herr
		}
		if err := st.ctx.Err(); err != nil {
			return status.FromContextError(err).Err()
		}
		for _, r := range resps {
			if err := ps.Send(r); err != nil {
				return err
			}
		}
		if done {
			return nil
		}
	}
}

func (st *stream) checkUndecided() {
	s := st.s
	if st.req == nil || st.decisions != 0 || st.modeStated || s.cfg.Mode == inspect.ModeLite {
		return
	}
	s.undecided.Do(func() {
		s.log.Warn("ext_proc stream ended before Ailuros saw the request body, so the request was not classified; set the Envoy ext_proc request_body_mode that matches AILUROS_INSPECTION_MODE (see deploy/envoy)",
			"mode", s.cfg.Mode)
	})
	s.onDowngrade()
}

type stream struct {
	s          *Server
	ctx        context.Context
	src        decision.Source
	req        *inspect.Request
	eos        bool
	fullDuplex bool
	pass       bool
	decisions  int
	absorbed   bool
	streamID   string
	held       []byte
	framer     *framer
	encoding   string
	out        []byte
	trailers   map[string][]string
	modeStated bool
	computed   decision.Decision
}

func (st *stream) handle(msg *extprocv3.ProcessingRequest) ([]*extprocv3.ProcessingResponse, bool) {
	switch m := msg.GetRequest().(type) {
	case *extprocv3.ProcessingRequest_RequestHeaders:
		return st.onHeaders(msg, m.RequestHeaders)
	case *extprocv3.ProcessingRequest_RequestBody:
		return st.onBody(msg, m.RequestBody)
	case *extprocv3.ProcessingRequest_RequestTrailers:
		return st.onTrailers(msg)
	case *extprocv3.ProcessingRequest_ResponseHeaders, *extprocv3.ProcessingRequest_ResponseBody, *extprocv3.ProcessingRequest_ResponseTrailers:
		return st.continueFor(msg, nil, nil), false
	}
	return nil, false
}

func (st *stream) onHeaders(msg *extprocv3.ProcessingRequest, h *extprocv3.HttpHeaders) ([]*extprocv3.ProcessingResponse, bool) {
	if st.req != nil {
		return nil, false
	}
	st.req = buildRequest(h, msg.GetAttributes(), st.s.cfg.JA4Header)
	st.ctx = envoyreq.TraceContext(st.ctx, st.req.Headers)
	st.eos = h.GetEndOfStream()
	if d, ok := frontend.RefuseMalformed(decision.WithSink(st.ctx, &st.computed), st.s.engine, st.src, st.req); ok {
		st.decisions++
		return []*extprocv3.ProcessingResponse{st.immediate(d)}, true
	}
	mode := st.s.cfg.Mode
	st.fullDuplex = mode == inspect.ModeDeep
	if pc := msg.GetProtocolConfig(); pc != nil {
		st.fullDuplex = pc.GetRequestBodyMode() == filterv3.ProcessingMode_FULL_DUPLEX_STREAMED
		st.modeStated = true
	}
	switch {
	case mode != inspect.ModeLite && st.bodyNotSent(msg, h):
		st.s.mismatch.Do(func() {
			st.s.log.Warn("Envoy is not sending request bodies in the body mode AILUROS_INSPECTION_MODE needs; classifying on headers only (see deploy/envoy)", "mode", mode)
		})
		st.s.onDowngrade()
		st.src.Mode = inspect.ModeLite
		return st.decideHeaders()
	case mode == inspect.ModeLite || st.eos:
		return st.decideHeaders()
	case signals.IsWebSocketHandshake(st.req):
		return st.decideHeaders()
	case mode == inspect.ModeDeep:
		st.streamID = decision.NewRequestID()
		st.ctx = decision.WithStreamID(st.ctx, st.streamID)
		if d := st.decide(st.req, "", st.streamID); d.Outcome.Denied() {
			return []*extprocv3.ProcessingResponse{st.immediate(d)}, true
		}
		return []*extprocv3.ProcessingResponse{headersResponse([]*corev3.HeaderValueOption{envoyreq.SetHeader(frontend.RequestIDHeader, st.streamID)})}, false
	}
	return []*extprocv3.ProcessingResponse{headersResponse(nil)}, false
}

func (st *stream) bodyNotSent(msg *extprocv3.ProcessingRequest, h *extprocv3.HttpHeaders) bool {
	if pc := msg.GetProtocolConfig(); pc != nil {
		switch bm := pc.GetRequestBodyMode(); st.s.cfg.Mode {
		case inspect.ModeStandard:
			return bm != filterv3.ProcessingMode_BUFFERED_PARTIAL && bm != filterv3.ProcessingMode_BUFFERED
		case inspect.ModeDeep:
			return bm != filterv3.ProcessingMode_FULL_DUPLEX_STREAMED
		}
	}
	if !h.GetEndOfStream() {
		return false
	}
	cl := st.req.Headers["content-length"]
	n, err := strconv.ParseInt(first(cl), 10, 64)
	return err == nil && n > 0
}

func (st *stream) decideHeaders() ([]*extprocv3.ProcessingResponse, bool) {
	d := st.decide(st.req, "", "")
	st.pass = true
	if d.Outcome.Denied() {
		return []*extprocv3.ProcessingResponse{st.immediate(d)}, true
	}
	return []*extprocv3.ProcessingResponse{headersResponse(envoyreq.DecisionHeaders(d, st.s.cfg.ExposeVerdict))}, false
}

func (st *stream) onBody(msg *extprocv3.ProcessingRequest, b *extprocv3.HttpBody) ([]*extprocv3.ProcessingResponse, bool) {
	if st.eos {
		return nil, false
	}
	st.eos = b.GetEndOfStream()
	switch {
	case st.req == nil:
		return st.fail(msg, classifier.ReasonProtocol)
	case st.pass || st.s.cfg.Mode == inspect.ModeLite:
		return st.continueFor(msg, nil, nil), false
	case st.s.cfg.Mode == inspect.ModeStandard:
		return st.standardBody(b)
	}
	st.absorbed = true
	return st.deepChunk(b.GetBody(), b.GetEndOfStream(), false)
}

func (st *stream) onTrailers(msg *extprocv3.ProcessingRequest) ([]*extprocv3.ProcessingResponse, bool) {
	switch {
	case st.req == nil:
		return st.fail(msg, classifier.ReasonProtocol)
	case st.pass || st.s.cfg.Mode == inspect.ModeLite:
		return st.continueFor(msg, nil, nil), false
	case st.s.cfg.Mode == inspect.ModeStandard:
		st.trailers = envoyreq.Headers(msg.GetRequestTrailers().GetTrailers().GetHeaders())
		d := st.decide(st.withTrailers(*st.req), "", "")
		st.pass = true
		if d.Outcome.Denied() {
			return []*extprocv3.ProcessingResponse{st.immediate(d)}, true
		}
		return []*extprocv3.ProcessingResponse{trailersResponse()}, false
	}
	st.eos = true
	st.trailers = envoyreq.Headers(msg.GetRequestTrailers().GetTrailers().GetHeaders())
	return st.deepChunk(nil, true, true)
}
