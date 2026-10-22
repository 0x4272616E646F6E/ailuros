package extproc

import (
	"fmt"

	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/0x4272616E646F6E/decision-waf/internal/decision"
	"github.com/0x4272616E646F6E/decision-waf/internal/frontend"
)

func (st *stream) safeHandle(msg *extprocv3.ProcessingRequest) (resps []*extprocv3.ProcessingResponse, done bool, err error) {
	st.absorbed = false
	st.computed = decision.Decision{}
	defer func() {
		if p := recover(); p != nil {
			resps, done, err = st.recoverFrom(msg, p)
		}
	}()
	resps, done = st.handle(msg)
	return resps, done, nil
}

func (st *stream) recoverFrom(msg *extprocv3.ProcessingRequest, p any) (resps []*extprocv3.ProcessingResponse, done bool, err error) {
	defer func() {
		if p := recover(); p != nil {
			st.s.log.Error("panic while answering after a panic; resetting the stream", "frontend", st.src.Frontend, "panic", fmt.Sprint(p))
			resps, done, err = nil, true, status.Error(codes.Internal, "ailuros: internal error")
		}
	}()
	st.decisions++
	resps, done = st.answer(msg, frontend.AfterPanic(st.ctx, st.s.engine, st.src, st.s.log, st.req, st.computed, p))
	return resps, done, nil
}
