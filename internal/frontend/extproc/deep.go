package extproc

import (
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"

	"github.com/0x4272616E646F6E/decision-waf/internal/decision"
	"github.com/0x4272616E646F6E/decision-waf/internal/inspect"
)

const defaultDeepMaxMessages = 100

func (c Config) overLimit() (o decision.Outcome, classify bool) {
	switch c.DeepOversize {
	case inspect.OversizeBlock:
		return decision.Block, false
	case inspect.OversizeAllow:
		return decision.Allow, false
	}
	return "", true
}

func (c Config) bypassOutcome() decision.Outcome {
	if c.DeepOversize == inspect.OversizeAllow {
		return decision.Allow
	}
	return decision.Block
}

func (c Config) deepMaxMessages() int {
	if c.DeepMaxMessages > 0 {
		return c.DeepMaxMessages
	}
	return defaultDeepMaxMessages
}

func (st *stream) deepChunk(chunk []byte, end, trailers bool) ([]*extprocv3.ProcessingResponse, bool) {
	if st.req.GRPCFramed() {
		return st.grpcChunk(chunk, end, trailers)
	}
	return st.httpChunk(chunk, end, trailers)
}

func (st *stream) httpChunk(chunk []byte, end, trailers bool) ([]*extprocv3.ProcessingResponse, bool) {
	st.held = append(st.held, chunk...)
	max := st.s.cfg.DeepMaxBytes
	var body []byte
	var truncated bool
	switch {
	case len(st.held) > max:
		body, truncated = st.held[:max], true
	case end:
		body = st.held
	default:
		return nil, false
	}
	var d decision.Decision
	plain, over, err := plaintext(st.req, body, max, truncated)
	switch {
	case err != nil && st.s.cfg.bypassOutcome() == decision.Allow:
		r := st.withTrailers(*st.req)
		r.Body, r.BodyTruncated = body, truncated
		d = st.decide(r, decision.NoteUninspectable, st.streamID)
	case err != nil:
		d = st.uninspectable(st.streamID)
	case truncated || over:
		if o, classify := st.s.cfg.overLimit(); !classify {
			d = st.bypass(o, decision.NoteOversize, st.streamID)
		} else {
			r := st.withTrailers(*st.req)
			r.Body, r.BodyTruncated = plain, true
			d = st.decide(r, decision.NoteOversize, st.streamID)
		}
	default:
		r := st.withTrailers(*st.req)
		r.Body = plain
		d = st.decide(r, "", st.streamID)
	}
	if d.Outcome.Denied() {
		return []*extprocv3.ProcessingResponse{st.immediate(d)}, true
	}
	st.pass = true
	return emit(st.takeHeld(), end, trailers), false
}

func (st *stream) grpcChunk(chunk []byte, end, trailers bool) ([]*extprocv3.ProcessingResponse, bool) {
	if st.framer == nil {
		_, classify := st.s.cfg.overLimit()
		st.framer = newFramer(st.s.cfg.DeepMaxBytes, classify)
		st.encoding = messageEncoding(st.req)
		st.framer.ignoreFlag = st.encoding == ""
	}
	st.framer.write(chunk)
	for !st.pass {
		pass, fr := st.framer.next()
		if pass == nil && fr == nil {
			break
		}
		st.out = append(st.out, pass...)
		if fr == nil {
			continue
		}
		if resps, done := st.grpcFrame(fr); done {
			return resps, true
		}
		if st.pass {
			st.out = append(st.out, st.framer.flush()...)
			break
		}
		st.framer.passRest(fr)
	}
	if end && !st.pass {
		if fr := st.framer.partialFrame(); fr != nil {
			if resps, done := st.grpcFrame(fr); done {
				return resps, true
			}
		}
	}
	if end && trailers && !st.pass && len(st.trailers) > 0 {
		if d := st.trailersDecision(); d.Outcome.Denied() {
			return []*extprocv3.ProcessingResponse{st.immediate(d)}, true
		}
	}
	out := st.out
	st.out = nil
	return emit(out, end, trailers), false
}

func (st *stream) grpcFrame(fr *frame) ([]*extprocv3.ProcessingResponse, bool) {
	mark := len(st.out)
	st.out = append(st.out, fr.raw...)
	if fr.kind == frameMessage && len(fr.payload) == 0 {
		return nil, false
	}
	var d decision.Decision
	if st.decisions >= st.s.cfg.deepMaxMessages() {
		d = st.messageLimit()
	} else {
		d = st.grpcMessage(fr)
	}
	if st.ctx.Err() != nil {
		return nil, true
	}
	if d.Outcome.Denied() {
		st.out = st.out[:mark]
		return []*extprocv3.ProcessingResponse{st.immediate(d)}, true
	}
	return nil, false
}

func (st *stream) trailersDecision() decision.Decision {
	if st.decisions >= st.s.cfg.deepMaxMessages() {
		return st.messageLimit()
	}
	r := st.withTrailers(*st.req)
	r.Body = nil
	return st.decide(r, "", "")
}

func (st *stream) messageLimit() decision.Decision {
	d := st.bypass(st.s.cfg.bypassOutcome(), decision.NoteMessageLimit, "")
	if !d.Outcome.Denied() {
		st.pass = true
	}
	return d
}

func (st *stream) grpcMessage(fr *frame) decision.Decision {
	payload, truncated := fr.payload, fr.kind == frameOversize || fr.partial
	note := decision.Note("")
	if fr.kind == frameOversize {
		note = decision.NoteOversize
	}
	if _, classify := st.s.cfg.overLimit(); fr.compressed && (note == "" || classify) {
		plain, over, err := decompress(st.encoding, payload, st.s.cfg.DeepMaxBytes, truncated)
		if err != nil {
			return st.uninspectable("")
		}
		payload = plain
		if over {
			truncated, note = true, decision.NoteOversize
		}
	}
	if note != "" {
		if o, classify := st.s.cfg.overLimit(); !classify {
			return st.bypass(o, note, "")
		}
	}
	r := *st.req
	r.Body, r.BodyTruncated = payload, truncated
	return st.decide(&r, note, "")
}

func (st *stream) uninspectable(id string) decision.Decision {
	return st.bypass(st.s.cfg.bypassOutcome(), decision.NoteUninspectable, id)
}
