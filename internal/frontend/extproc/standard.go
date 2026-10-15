package extproc

import (
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"

	"github.com/0x4272616E646F6E/ailuros/internal/decision"
	"github.com/0x4272616E646F6E/ailuros/internal/frontend/envoyreq"
)

func (st *stream) standardBody(b *extprocv3.HttpBody) ([]*extprocv3.ProcessingResponse, bool) {
	body := b.GetBody()
	max := st.s.cfg.BodyMaxBytes
	n := min(len(body), max)
	truncated := !b.GetEndOfStream() || len(body) > n
	plain, over, err := plaintext(st.req, body[:n], max, truncated)
	var d decision.Decision
	if err != nil {
		d = st.bypass(decision.Block, decision.NoteUninspectable, "")
	} else {
		st.req.Body, st.req.BodyTruncated = plain, truncated || over
		d = st.decide(st.req, "", "")
	}
	st.pass = true
	if d.Outcome.Denied() {
		return []*extprocv3.ProcessingResponse{st.immediate(d)}, true
	}
	return []*extprocv3.ProcessingResponse{bodyResponse(envoyreq.DecisionHeaders(d, st.s.cfg.ExposeVerdict))}, false
}
