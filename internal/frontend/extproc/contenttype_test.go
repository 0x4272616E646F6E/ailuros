package extproc

import (
	"testing"

	"github.com/0x4272616E646F6E/ailuros/internal/classifier/fake"
	"github.com/0x4272616E646F6E/ailuros/internal/decision"
	"github.com/0x4272616E646F6E/ailuros/internal/inspect"
	"github.com/0x4272616E646F6E/ailuros/internal/policy"
)

func TestSeveralContentTypesAreMalformed(t *testing.T) {
	for _, mode := range []inspect.Mode{inspect.ModeLite, inspect.ModeStandard, inspect.ModeDeep} {
		t.Run(string(mode), func(t *testing.T) {
			f := fake.Attacks()
			cfg := deep(1024, inspect.OversizeClassifyPrefix)
			cfg.Mode = mode
			h := newHarness(t, f, cfg, policy.FailOpen)
			s := h.open()
			hdrs := []string{":method", "POST", ":scheme", "http", ":authority", "api.internal", ":path", "/payments.v1.Payments/Charge",
				"content-type", "text/plain", "content-type", "application/grpc"}
			send(t, s, headersMsg(false, hdrs...))
			expectImmediate(t, recv(t, s), 400, 0, "malformed request")
			if f.Calls() != 0 {
				t.Errorf("classifier calls = %d, want none", f.Calls())
			}
			if d := h.obs.All(); len(d) != 1 || d[0].Note != decision.NoteMalformed || d[0].Outcome != decision.Block {
				t.Errorf("decisions = %+v, want one block with note malformed", d)
			}
		})
	}
}

func TestDeepGRPCFramingWithoutServicePath(t *testing.T) {
	f := fake.Attacks()
	h := newHarness(t, f, deep(1024, inspect.OversizeClassifyPrefix), policy.FailOpen)
	s := h.open()
	send(t, s, headersMsg(false, ":method", "POST", ":scheme", "http", ":authority", "api.internal", ":path", "/anything",
		"content-type", "application/grpc"))
	recv(t, s)
	padding := grpcMsg(false, randomBytes(2000))
	send(t, s, bodyMsg(append(padding, grpcMsg(false, []byte("an attack in message two"))...), true))
	for {
		r := recv(t, s)
		if r.GetImmediateResponse() != nil {
			expectImmediate(t, r, 403, 7, "request blocked")
			break
		}
		if r.GetRequestBody().GetResponse().GetBodyMutation().GetStreamedResponse().GetEndOfStream() {
			t.Fatal("the second message reached the upstream unclassified")
		}
	}
}
