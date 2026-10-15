package extproc

import (
	"context"

	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"

	"github.com/0x4272616E646F6E/ailuros/internal/classifier"
	"github.com/0x4272616E646F6E/ailuros/internal/decision"
	"github.com/0x4272616E646F6E/ailuros/internal/frontend/envoyreq"
	"github.com/0x4272616E646F6E/ailuros/internal/inspect"
)

func (st *stream) decisionCtx(id string) context.Context {
	st.decisions++
	ctx := st.ctx
	if id != "" {
		ctx = decision.WithRequestID(ctx, id)
	}
	return decision.WithSink(ctx, &st.computed)
}

func (st *stream) decide(r *inspect.Request, note decision.Note, id string) decision.Decision {
	return envoyreq.Decide(st.decisionCtx(id), st.s.engine, r, st.src, note)
}

func (st *stream) bypass(o decision.Outcome, note decision.Note, id string) decision.Decision {
	return st.s.engine.Bypass(st.decisionCtx(id), st.req, st.src, o, note)
}

func (st *stream) fail(msg *extprocv3.ProcessingRequest, reason classifier.Reason) ([]*extprocv3.ProcessingResponse, bool) {
	return st.answer(msg, st.s.engine.Fail(st.decisionCtx(""), st.req, st.src, reason))
}

func (st *stream) answer(msg *extprocv3.ProcessingRequest, d decision.Decision) ([]*extprocv3.ProcessingResponse, bool) {
	if d.Outcome.Denied() {
		return []*extprocv3.ProcessingResponse{st.immediate(d)}, true
	}
	st.pass = true
	return st.continueFor(msg, st.takeHeld(), envoyreq.DecisionHeaders(d, st.s.cfg.ExposeVerdict)), false
}

func (st *stream) takeHeld() []byte {
	out := append(st.out, st.held...)
	if st.framer != nil {
		out = append(out, st.framer.flush()...)
	}
	st.out, st.held = nil, nil
	return out
}
