package extproc

import (
	"bytes"
	"context"
	"errors"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/0x4272616E646F6E/decision-waf/internal/classifier"
	"github.com/0x4272616E646F6E/decision-waf/internal/classifier/fake"
	"github.com/0x4272616E646F6E/decision-waf/internal/decision"
	"github.com/0x4272616E646F6E/decision-waf/internal/frontend/frontendtest"
	"github.com/0x4272616E646F6E/decision-waf/internal/inspect"
	"github.com/0x4272616E646F6E/decision-waf/internal/policy"
)

func deep(max int, oversize inspect.Oversize) Config {
	return Config{Mode: inspect.ModeDeep, BodyMaxBytes: 65536, DeepMaxBytes: max, DeepOversize: oversize}
}

func randomBytes(n int) []byte {
	r := rand.New(rand.NewPCG(1, 2))
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(r.IntN(26))
	}
	return b
}

type payloads struct {
	mu   sync.Mutex
	reqs []*inspect.Request
}

func (p *payloads) classifier() *fake.Classifier {
	inner := fake.Attacks()
	return fake.New(func(ctx context.Context, r *inspect.Request, cats []policy.Category) (classifier.Verdict, error) {
		p.mu.Lock()
		p.reqs = append(p.reqs, r)
		p.mu.Unlock()
		return inner.Classify(ctx, r, cats)
	})
}

func (p *payloads) all() []*inspect.Request {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]*inspect.Request(nil), p.reqs...)
}

func TestDeepHTTPHoldsAndStreamsBackExactly(t *testing.T) {
	f := fake.Attacks()
	h := newHarness(t, f, deep(1<<20, inspect.OversizeClassifyPrefix), policy.FailOpen)
	s := h.open()
	send(t, s, headersMsg(false, httpHeaders...))
	streamID := mutationHeaders(t, recv(t, s))["x-ailuros-request-id"]
	if !hex16.MatchString(streamID) {
		t.Fatalf("stream request id = %q", streamID)
	}
	body := randomBytes(150_000)
	send(t, s, bodyMsg(body[:70_000], false), bodyMsg(body[70_000:140_000], false), bodyMsg(body[140_000:], true))
	got, eos := streamed(t, s, 0)
	if !bytes.Equal(got, body) || !eos {
		t.Fatalf("streamed back %d bytes (eos %v), want the original %d bytes", len(got), eos, len(body))
	}
	if r := f.Last(); f.Calls() != 2 || !bytes.Equal(r.Body, body) || r.BodyTruncated {
		t.Errorf("classifier calls = %d (want headers + body), saw %d bytes truncated=%v", f.Calls(), len(r.Body), r.BodyTruncated)
	}
	if d := h.obs.All(); len(d) != 2 || d[0].RequestID != streamID || d[1].RequestID != streamID {
		t.Errorf("decisions = %+v, want headers and body under the stream id %q", d, streamID)
	}
	expectEnd(t, s)
}

func TestDeepHTTPBlock(t *testing.T) {
	h := newHarness(t, fake.Attacks(), deep(1<<20, inspect.OversizeClassifyPrefix), policy.FailOpen)
	s := h.open()
	send(t, s, headersMsg(false, httpHeaders...))
	streamID := mutationHeaders(t, recv(t, s))["x-ailuros-request-id"]
	send(t, s, bodyMsg([]byte("q=att"), false), bodyMsg([]byte("ack"), true))
	if id := expectImmediate(t, recv(t, s), 403, 0, "request blocked"); id != streamID {
		t.Errorf("denial request id = %q, want the stream id %q", id, streamID)
	}
}

func TestDeepHTTPDuplicateFinalChunkIgnored(t *testing.T) {
	h := newHarness(t, fake.Attacks(), deep(1<<20, inspect.OversizeClassifyPrefix), policy.FailOpen)
	s := h.open()
	send(t, s, headersMsg(false, httpHeaders...))
	recv(t, s)
	send(t, s, bodyMsg([]byte("abc"), true))
	if got, _ := streamed(t, s, 0); string(got) != "abc" {
		t.Fatalf("streamed %q", got)
	}
	send(t, s, bodyMsg([]byte("abc"), true))
	expectEnd(t, s)
}

func TestDeepHTTPTrailersEndTheBody(t *testing.T) {
	h := newHarness(t, fake.Attacks(), deep(1<<20, inspect.OversizeClassifyPrefix), policy.FailOpen)
	s := h.open()
	send(t, s, headersMsg(false, httpHeaders...))
	recv(t, s)
	send(t, s, bodyMsg([]byte("abc"), false), trailersMsg())
	if got, eos := streamed(t, s, 1); string(got) != "abc" || eos {
		t.Fatalf("streamed %q eos=%v; want abc without end_of_stream", got, eos)
	}
	if r := recv(t, s); r.GetRequestTrailers() == nil {
		t.Errorf("response = %v, want a trailers response", r)
	}
}

func TestDeepHTTPOversizePolicies(t *testing.T) {
	body := randomBytes(1800)
	cases := []struct {
		policy      inspect.Oversize
		calls       int
		denied      bool
		wantOutcome decision.Outcome
	}{
		{inspect.OversizeClassifyPrefix, 1, false, decision.Allow},
		{inspect.OversizeAllow, 0, false, decision.Allow},
		{inspect.OversizeBlock, 0, true, decision.Block},
	}
	for _, c := range cases {
		t.Run(string(c.policy), func(t *testing.T) {
			f := fake.Attacks()
			h := newHarness(t, f, deep(1000, c.policy), policy.FailOpen)
			s := h.open()
			send(t, s, headersMsg(false, httpHeaders...))
			recv(t, s)
			send(t, s, bodyMsg(body[:600], false), bodyMsg(body[600:1200], false))
			if c.denied {
				expectImmediate(t, recv(t, s), 413, 0, "request too large")
			} else {
				got, eos := streamed(t, s, 1)
				if !bytes.Equal(got, body[:1200]) || eos {
					t.Fatalf("released %d held bytes (eos %v), want 1200", len(got), eos)
				}
				send(t, s, bodyMsg(body[1200:], true))
				rest, eos := streamed(t, s, 0)
				if !bytes.Equal(rest, body[1200:]) || !eos {
					t.Fatalf("passed through %d bytes (eos %v), want 600", len(rest), eos)
				}
			}
			if f.Calls() != c.calls+1 {
				t.Errorf("classifier calls = %d, want %d (headers + body)", f.Calls(), c.calls+1)
			}
			if c.calls == 1 {
				if r := f.Last(); len(r.Body) != 1000 || !r.BodyTruncated {
					t.Errorf("classified %d bytes truncated=%v, want the first 1000 truncated", len(r.Body), r.BodyTruncated)
				}
			}
			d := h.obs.All()
			if len(d) != 2 || d[1].Outcome != c.wantOutcome || d[1].Note != decision.NoteOversize {
				t.Errorf("decisions = %+v, want one %s with note oversize", d, c.wantOutcome)
			}
		})
	}
}

func TestDeepGRPCPerMessageBlockingMidStream(t *testing.T) {
	p := &payloads{}
	h := newHarness(t, p.classifier(), deep(1<<20, inspect.OversizeClassifyPrefix), policy.FailOpen)
	s := h.open()
	send(t, s, headersMsg(false, grpcHeaders...))
	streamID := mutationHeaders(t, recv(t, s))["x-ailuros-request-id"]
	m1, m2 := grpcMsg(false, []byte("benign one")), grpcMsg(false, []byte("then an attack"))
	send(t, s, bodyMsg(append(append([]byte{}, m1...), m2[:6]...), false))
	if got, _ := streamed(t, s, 1); !bytes.Equal(got, m1) {
		t.Fatalf("forwarded %q, want exactly message 1", got)
	}
	send(t, s, bodyMsg(m2[6:], true))
	id := expectImmediate(t, recv(t, s), 403, 7, "request blocked")
	reqs := p.all()
	if len(reqs) != 3 || reqs[0].Body != nil || string(reqs[1].Body) != "benign one" || string(reqs[2].Body) != "then an attack" {
		t.Fatalf("classified %d requests, want headers then 2 messages", len(reqs))
	}
	d := h.obs.All()
	if len(d) != 3 || d[0].RequestID != streamID || d[1].RequestID == d[2].RequestID || id != d[2].RequestID || d[1].RequestID == streamID {
		t.Errorf("each message decision needs its own request id: %+v (stream %s)", d, streamID)
	}
}

func TestDeepGRPCReassemblyIsByteExact(t *testing.T) {
	p := &payloads{}
	h := newHarness(t, p.classifier(), deep(1<<20, inspect.OversizeClassifyPrefix), policy.FailOpen)
	s := h.open()
	send(t, s, headersMsg(false, grpcHeaders...))
	recv(t, s)
	var stream []byte
	var want []string
	for i, n := range []int{3, 0, 70_000, 9, 1} {
		payload := randomBytes(n)
		if n > 0 {
			payload[0] = byte(i)
		}
		if n > 0 {
			want = append(want, string(payload))
		}
		stream = append(stream, grpcMsg(false, payload)...)
	}
	cuts := []int{2, 9, 13, 40_000, len(stream) - 4, len(stream)}
	prev := 0
	var got []byte
	for i, c := range cuts {
		send(t, s, bodyMsg(stream[prev:c], i == len(cuts)-1))
		prev = c
	}
	got, eos := streamed(t, s, 0)
	if !bytes.Equal(got, stream) || !eos {
		t.Fatalf("forwarded %d bytes (eos %v), want the original %d", len(got), eos, len(stream))
	}
	reqs := p.all()[1:]
	if len(reqs) != len(want) {
		t.Fatalf("classified %d messages, want %d", len(reqs), len(want))
	}
	for i, r := range reqs {
		if string(r.Body) != want[i] || r.GRPCService != "payments.v1.Payments" {
			t.Errorf("message %d: classified %d bytes for %s", i, len(r.Body), r.GRPCService)
		}
	}
}

func TestDeepGRPCDecompressesGzipAndDeflate(t *testing.T) {
	for _, enc := range []string{"gzip", "deflate"} {
		for _, c := range []struct {
			payload string
			denied  bool
		}{{"an attack hidden by compression", true}, {"hello there", false}} {
			t.Run(enc+"/"+c.payload, func(t *testing.T) {
				msg := grpcMsg(true, compress(t, enc, []byte(c.payload)))
				f := fake.Attacks()
				h := newHarness(t, f, deep(1<<20, inspect.OversizeClassifyPrefix), policy.FailOpen)
				s := h.open()
				send(t, s, headersMsg(false, with(grpcHeaders, "grpc-encoding", enc)...))
				recv(t, s)
				send(t, s, bodyMsg(msg, true))
				if c.denied {
					expectImmediate(t, recv(t, s), 403, 7, "request blocked")
				} else if got, _ := streamed(t, s, 0); !bytes.Equal(got, msg) {
					t.Errorf("forwarded %q, want the original compressed message byte for byte", got)
				}
				if r := f.Last(); string(r.Body) != c.payload || r.BodyTruncated {
					t.Errorf("classifier saw %q (truncated=%v), want the decompressed payload", r.Body, r.BodyTruncated)
				}
			})
		}
	}
}

func TestDeepGRPCDecompressionBombIsBounded(t *testing.T) {
	msg := grpcMsg(true, compress(t, "gzip", make([]byte, 8<<20)))
	cases := []struct {
		policy inspect.Oversize
		calls  int
		denied bool
	}{
		{inspect.OversizeClassifyPrefix, 1, false},
		{inspect.OversizeAllow, 0, false},
		{inspect.OversizeBlock, 0, true},
	}
	for _, c := range cases {
		t.Run(string(c.policy), func(t *testing.T) {
			f := fake.Attacks()
			h := newHarness(t, f, deep(4096, c.policy), policy.FailOpen)
			s := h.open()
			send(t, s, headersMsg(false, with(grpcHeaders, "grpc-encoding", "gzip")...))
			recv(t, s)
			send(t, s, bodyMsg(msg, true))
			if c.denied {
				expectImmediate(t, recv(t, s), 413, 8, "request too large")
			} else if got, _ := streamed(t, s, 0); !bytes.Equal(got, msg) {
				t.Errorf("forwarded %d bytes, want the original %d", len(got), len(msg))
			}
			if f.Calls() != c.calls+1 {
				t.Errorf("classifier calls = %d, want %d", f.Calls(), c.calls+1)
			}
			if c.calls == 1 {
				if r := f.Last(); len(r.Body) != 4096 || !r.BodyTruncated {
					t.Errorf("classified %d bytes (truncated=%v), want the 4096-byte decompressed prefix", len(r.Body), r.BodyTruncated)
				}
			}
			if d := h.obs.All(); d[len(d)-1].Note != decision.NoteOversize {
				t.Errorf("last decision %+v, want note oversize", d[len(d)-1])
			}
		})
	}
}

func TestDeepGRPCOversizeMessageClassifiesPrefix(t *testing.T) {
	f := fake.Attacks()
	h := newHarness(t, f, deep(10, inspect.OversizeClassifyPrefix), policy.FailOpen)
	s := h.open()
	send(t, s, headersMsg(false, grpcHeaders...))
	recv(t, s)
	msg := grpcMsg(false, randomBytes(100))
	send(t, s, bodyMsg(msg[:30], false), bodyMsg(msg[30:], true))
	got, eos := streamed(t, s, 0)
	if !bytes.Equal(got, msg) || !eos {
		t.Fatalf("forwarded %d bytes, want %d", len(got), len(msg))
	}
	if r := f.Last(); len(r.Body) != 10 || !r.BodyTruncated {
		t.Errorf("classified %d bytes truncated=%v, want the first 10", len(r.Body), r.BodyTruncated)
	}
}

func TestDeepGRPCEndOfStreamMidMessage(t *testing.T) {
	partial := grpcMsg(false, []byte("cut short"))[:8]
	for _, mode := range []policy.FailureMode{policy.FailClosed, policy.FailOpen} {
		t.Run("benign "+string(mode), func(t *testing.T) {
			f := fake.Attacks()
			h := newHarness(t, f, deep(1<<20, inspect.OversizeClassifyPrefix), mode)
			s := h.open()
			send(t, s, headersMsg(false, grpcHeaders...))
			recv(t, s)
			send(t, s, bodyMsg(partial, true))
			if got, eos := streamed(t, s, 0); !bytes.Equal(got, partial) || !eos {
				t.Errorf("forwarded %q eos=%v, want the partial bytes unchanged", got, eos)
			}
			if r := f.Last(); string(r.Body) != "cut" || !r.BodyTruncated {
				t.Errorf("classified %q truncated=%v", r.Body, r.BodyTruncated)
			}
		})
	}
	t.Run("classifier down, fail closed", func(t *testing.T) {
		var calls atomic.Int32
		c := fake.New(func(context.Context, *inspect.Request, []policy.Category) (classifier.Verdict, error) {
			if calls.Add(1) == 1 {
				return classifier.Verdict{Benign: 1}, nil
			}
			return classifier.Verdict{}, errors.New("down")
		})
		h := newHarness(t, c, deep(1<<20, inspect.OversizeClassifyPrefix), policy.FailClosed)
		s := h.open()
		send(t, s, headersMsg(false, grpcHeaders...))
		recv(t, s)
		send(t, s, bodyMsg(partial, true))
		expectImmediate(t, recv(t, s), 503, 14, "service unavailable")
	})
}

func TestDeepGRPCWithoutMessagesClassifiesHeaders(t *testing.T) {
	f := fake.Attacks()
	h := newHarness(t, f, deep(1<<20, inspect.OversizeClassifyPrefix), policy.FailOpen)
	s := h.open()
	send(t, s, headersMsg(false, grpcHeaders...))
	recv(t, s)
	send(t, s, bodyMsg(nil, true))
	if got, eos := streamed(t, s, 0); len(got) != 0 || !eos {
		t.Errorf("streamed %q eos=%v, want an empty end_of_stream chunk", got, eos)
	}
	if f.Calls() != 1 {
		t.Errorf("classifier calls = %d, want 1 (headers)", f.Calls())
	}
}

func TestDeepClassifierFailureMidStream(t *testing.T) {
	calls := 0
	c := fake.New(func(context.Context, *inspect.Request, []policy.Category) (classifier.Verdict, error) {
		calls++
		if calls == 3 {
			return classifier.Verdict{}, errors.New("down")
		}
		return classifier.Verdict{Benign: 1}, nil
	})
	h := newHarness(t, c, deep(1<<20, inspect.OversizeClassifyPrefix), policy.FailClosed)
	s := h.open()
	send(t, s, headersMsg(false, grpcHeaders...))
	recv(t, s)
	send(t, s, bodyMsg(append(grpcMsg(false, []byte("one")), grpcMsg(false, []byte("two"))...), false))
	expectImmediate(t, recv(t, s), 503, 14, "service unavailable")
}

func TestDeepGRPCEndOfStreamMidMessageClassifiesHeldBytes(t *testing.T) {
	hdr := []byte{0, 0xff, 0xff, 0xff, 0xff}
	t.Run("attack blocked", func(t *testing.T) {
		f := fake.Attacks()
		h := newHarness(t, f, deep(1<<20, inspect.OversizeClassifyPrefix), policy.FailOpen)
		s := h.open()
		send(t, s, headersMsg(false, grpcHeaders...))
		recv(t, s)
		send(t, s, bodyMsg(append(append([]byte{}, hdr...), []byte("an attack")...), true))
		expectImmediate(t, recv(t, s), 403, 7, "request blocked")
		if r := f.Last(); string(r.Body) != "an attack" || !r.BodyTruncated {
			t.Errorf("classified %q truncated=%v", r.Body, r.BodyTruncated)
		}
	})
	t.Run("benign released exactly", func(t *testing.T) {
		f := fake.Attacks()
		h := newHarness(t, f, deep(1<<20, inspect.OversizeClassifyPrefix), policy.FailOpen)
		s := h.open()
		send(t, s, headersMsg(false, grpcHeaders...))
		recv(t, s)
		raw := append(append([]byte{}, hdr...), []byte("fine")...)
		send(t, s, bodyMsg(raw, true))
		if got, eos := streamed(t, s, 0); !bytes.Equal(got, raw) || !eos {
			t.Errorf("forwarded %q eos=%v", got, eos)
		}
		if r := f.Last(); string(r.Body) != "fine" || !r.BodyTruncated {
			t.Errorf("classified %q truncated=%v", r.Body, r.BodyTruncated)
		}
	})
}

func TestDeepGRPCSpoofedCompressedFlag(t *testing.T) {
	for _, flag := range []byte{1, 0x80, 0x81} {
		msg := grpcMsg(false, []byte("an attack"))
		msg[0] = flag
		f := fake.Attacks()
		h := newHarness(t, f, deep(1<<20, inspect.OversizeClassifyPrefix), policy.FailOpen)
		s := h.open()
		send(t, s, headersMsg(false, grpcHeaders...))
		recv(t, s)
		send(t, s, bodyMsg(msg, true))
		expectImmediate(t, recv(t, s), 403, 7, "request blocked")
		if r := f.Last(); f.Calls() != 2 || string(r.Body) != "an attack" {
			t.Errorf("flag %#x: classifier calls=%d, must see the payload", flag, f.Calls())
		}
	}
	for _, enc := range []string{"identity", ""} {
		f := fake.Attacks()
		h := newHarness(t, f, deep(1<<20, inspect.OversizeClassifyPrefix), policy.FailOpen)
		s := h.open()
		send(t, s, headersMsg(false, with(grpcHeaders, "grpc-encoding", enc)...))
		recv(t, s)
		send(t, s, bodyMsg(grpcMsg(true, []byte("an attack")), true))
		expectImmediate(t, recv(t, s), 403, 7, "request blocked")
	}
}

func TestDeepGRPCUninspectableBlocksUnlessAllowed(t *testing.T) {
	inputs := []struct {
		name, enc string
		payload   []byte
	}{
		{"unsupported snappy", "snappy", []byte("snappy-framed attack")},
		{"unsupported zstd", "zstd", []byte("zstd-framed attack")},
		{"corrupt gzip", "gzip", []byte("not gzip at all")},
	}
	cases := []struct {
		policy inspect.Oversize
		denied bool
	}{
		{inspect.OversizeClassifyPrefix, true},
		{inspect.OversizeBlock, true},
		{inspect.OversizeAllow, false},
	}
	for _, in := range inputs {
		for _, c := range cases {
			t.Run(in.name+"/"+string(c.policy), func(t *testing.T) {
				msg := grpcMsg(true, in.payload)
				f := fake.Attacks()
				h := newHarness(t, f, deep(1<<20, c.policy), policy.FailOpen)
				s := h.open()
				send(t, s, headersMsg(false, with(grpcHeaders, "grpc-encoding", in.enc)...))
				recv(t, s)
				send(t, s, bodyMsg(msg, true))
				if c.denied {
					expectImmediate(t, recv(t, s), 413, 8, "request too large")
				} else if got, _ := streamed(t, s, 0); !bytes.Equal(got, msg) {
					t.Errorf("forwarded %q", got)
				}
				if f.Calls() != 1 {
					t.Errorf("classifier calls = %d, want only the headers decision", f.Calls())
				}
				if d := h.obs.All(); len(d) != 2 || d[1].Note != decision.NoteUninspectable {
					t.Errorf("decisions = %+v, want note uninspectable", d)
				}
			})
		}
	}
}

func TestDeepGRPCWebIsHeldAsHTTP(t *testing.T) {
	f := fake.Attacks()
	h := newHarness(t, f, deep(1<<20, inspect.OversizeClassifyPrefix), policy.FailOpen)
	for _, ct := range []string{"application/grpc-web-text", "application/grpc-web+proto"} {
		s := h.open()
		hdrs := append(append([]string{}, grpcHeaders[:len(grpcHeaders)-2]...), "content-type", ct)
		send(t, s, headersMsg(false, hdrs...))
		recv(t, s)
		before := f.Calls()
		first := grpcMsg(false, []byte("hello"))
		send(t, s, bodyMsg(first, false))
		send(t, s, bodyMsg([]byte("attack"), true))
		expectImmediate(t, recv(t, s), 403, 7, "request blocked")
		if f.Calls() != before+1 || !bytes.Equal(f.Last().Body, append(first, "attack"...)) {
			t.Errorf("%s: %d calls, last body %q; want one call with the whole body", ct, f.Calls()-before, f.Last().Body)
		}
	}
}

func TestDeepGRPCPanicForwardsEveryMessageInOrder(t *testing.T) {
	h := newHarness(t, fake.Attacks(), deep(1<<20, inspect.OversizeClassifyPrefix), policy.FailOpen)
	s := h.open()
	send(t, s, headersMsg(false, grpcHeaders...))
	recv(t, s)
	m1, m2, m3 := grpcMsg(false, []byte("one")), grpcMsg(false, []byte("two")), grpcMsg(false, []byte("three"))
	send(t, s, bodyMsg(m1, false))
	if got, _ := streamed(t, s, 1); !bytes.Equal(got, m1) {
		t.Fatalf("forwarded %q", got)
	}
	h.obs.PanicNext.Store(true)
	send(t, s, bodyMsg(append(append([]byte{}, m2...), m3...), false))
	got, _ := streamed(t, s, 1)
	if want := append(append([]byte{}, m2...), m3...); !bytes.Equal(got, want) {
		t.Errorf("after the panic upstream got %q, want messages 2 and 3 in order", got)
	}
}

func TestDeepGRPCEndingInTrailers(t *testing.T) {
	h := newHarness(t, fake.Attacks(), deep(1<<20, inspect.OversizeClassifyPrefix), policy.FailOpen)
	s := h.open()
	send(t, s, headersMsg(false, grpcHeaders...))
	recv(t, s)
	m := grpcMsg(false, []byte("hello"))
	send(t, s, bodyMsg(m, false), trailersMsg())
	if got, eos := streamed(t, s, 1); !bytes.Equal(got, m) || eos {
		t.Fatalf("streamed %q eos=%v", got, eos)
	}
	if r := recv(t, s); r.GetRequestTrailers() == nil {
		t.Errorf("response = %v, want trailers response", r)
	}
}

func TestDeepGRPCMessageAfterAllowedOversizeIsClassified(t *testing.T) {
	f := fake.Attacks()
	h := newHarness(t, f, deep(10, inspect.OversizeClassifyPrefix), policy.FailOpen)
	s := h.open()
	send(t, s, headersMsg(false, grpcHeaders...))
	recv(t, s)
	big, next := grpcMsg(false, randomBytes(100)), grpcMsg(false, []byte("attack"))
	send(t, s, bodyMsg(append(append([]byte{}, big...), next...), true))
	expectImmediate(t, recv(t, s), 403, 7, "request blocked")
	if r := f.Last(); string(r.Body) != "attack" {
		t.Errorf("last classified %q, want the message after the oversize one", r.Body)
	}
}

func TestDeepClassifiesHeadersBeforeContinue(t *testing.T) {
	attackPath := with(httpHeaders[:6], ":path", "/attack?q=1", "content-type", "application/json")
	attackGRPC := with(grpcHeaders[:6], ":path", "/attack.v1.Svc/Run", "content-type", "application/grpc")
	for name, hdrs := range map[string][]string{"http": attackPath, "grpc": attackGRPC} {
		t.Run(name+" attack in headers is denied with no CONTINUE", func(t *testing.T) {
			f := fake.Attacks()
			h := newHarness(t, f, deep(1<<20, inspect.OversizeClassifyPrefix), policy.FailOpen)
			s := h.open()
			send(t, s, headersMsg(false, hdrs...))
			grpcStatus := uint32(0)
			if name == "grpc" {
				grpcStatus = 7
			}
			expectImmediate(t, recv(t, s), 403, grpcStatus, "request blocked")
			if f.Calls() != 1 {
				t.Errorf("classifier calls = %d, want 1 (headers)", f.Calls())
			}
			expectEnd(t, s)
		})
	}
	t.Run("benign headers continue, malicious body still blocked", func(t *testing.T) {
		f := fake.Attacks()
		h := newHarness(t, f, deep(1<<20, inspect.OversizeClassifyPrefix), policy.FailOpen)
		s := h.open()
		send(t, s, headersMsg(false, httpHeaders...))
		streamID := mutationHeaders(t, recv(t, s))["x-ailuros-request-id"]
		if !hex16.MatchString(streamID) || f.Calls() != 1 {
			t.Fatalf("stream id = %q, classifier calls = %d; want headers classified before CONTINUE", streamID, f.Calls())
		}
		send(t, s, bodyMsg([]byte("an attack"), true))
		if id := expectImmediate(t, recv(t, s), 403, 0, "request blocked"); id != streamID {
			t.Errorf("denial id = %q, want stream id %q", id, streamID)
		}
		if f.Calls() != 2 {
			t.Errorf("classifier calls = %d, want 2 (headers, body)", f.Calls())
		}
	})
	t.Run("grpc benign headers continue, malicious message still blocked", func(t *testing.T) {
		f := fake.Attacks()
		h := newHarness(t, f, deep(1<<20, inspect.OversizeClassifyPrefix), policy.FailOpen)
		s := h.open()
		send(t, s, headersMsg(false, grpcHeaders...))
		if id := mutationHeaders(t, recv(t, s))["x-ailuros-request-id"]; !hex16.MatchString(id) || f.Calls() != 1 {
			t.Fatalf("stream id = %q, classifier calls = %d", id, f.Calls())
		}
		send(t, s, bodyMsg(grpcMsg(false, []byte("an attack")), true))
		expectImmediate(t, recv(t, s), 403, 7, "request blocked")
	})
	t.Run("classifier down on headers, fail closed", func(t *testing.T) {
		c := fake.New(func(context.Context, *inspect.Request, []policy.Category) (classifier.Verdict, error) {
			return classifier.Verdict{}, errors.New("down")
		})
		h := newHarness(t, c, deep(1<<20, inspect.OversizeClassifyPrefix), policy.FailClosed)
		s := h.open()
		send(t, s, headersMsg(false, httpHeaders...))
		expectImmediate(t, recv(t, s), 503, 0, "service unavailable")
	})
}

func TestDeepGRPCZeroLengthMessageNotClassified(t *testing.T) {
	p := &payloads{}
	h := newHarness(t, p.classifier(), deep(1<<20, inspect.OversizeClassifyPrefix), policy.FailOpen)
	s := h.open()
	send(t, s, headersMsg(false, grpcHeaders...))
	recv(t, s)
	stream := append(append(grpcMsg(false, nil), grpcMsg(false, []byte("x"))...), grpcMsg(false, nil)...)
	send(t, s, bodyMsg(stream, true))
	if got, eos := streamed(t, s, 0); !bytes.Equal(got, stream) || !eos {
		t.Fatalf("forwarded %q eos=%v, want every message unchanged", got, eos)
	}
	reqs := p.all()
	if len(reqs) != 2 || reqs[0].Body != nil || string(reqs[1].Body) != "x" {
		t.Errorf("classified %d requests, want headers and the one non-empty message", len(reqs))
	}
}

func TestDeepGRPCDecisionCap(t *testing.T) {
	var benign []byte
	for i := 0; i < defaultDeepMaxMessages-1; i++ {
		benign = append(benign, grpcMsg(false, []byte("fine"))...)
	}
	over := grpcMsg(false, []byte("an attack"))
	after := grpcMsg(false, []byte("more"))
	cases := []struct {
		policy inspect.Oversize
		denied bool
		want   decision.Outcome
	}{
		{inspect.OversizeClassifyPrefix, true, decision.Block},
		{inspect.OversizeAllow, false, decision.Allow},
		{inspect.OversizeBlock, true, decision.Block},
	}
	for _, c := range cases {
		t.Run(string(c.policy), func(t *testing.T) {
			f := fake.Attacks()
			h := newHarness(t, f, deep(1<<20, c.policy), policy.FailOpen)
			s := h.open()
			send(t, s, headersMsg(false, grpcHeaders...))
			recv(t, s)
			send(t, s, bodyMsg(benign, false))
			if got, _ := streamed(t, s, 1); !bytes.Equal(got, benign) {
				t.Fatalf("forwarded %d bytes, want the %d benign bytes", len(got), len(benign))
			}
			send(t, s, bodyMsg(append(append([]byte{}, over...), after...), true))
			if c.denied {
				expectImmediate(t, recv(t, s), 413, 8, "request too large")
			} else if got, eos := streamed(t, s, 0); !bytes.Equal(got, append(append([]byte{}, over...), after...)) || !eos {
				t.Errorf("forwarded %q eos=%v, want the rest of the stream unchanged", got, eos)
			}
			if f.Calls() != defaultDeepMaxMessages {
				t.Errorf("classifier calls = %d, want the cap %d", f.Calls(), defaultDeepMaxMessages)
			}
			d := h.obs.All()
			if last := d[len(d)-1]; len(d) != defaultDeepMaxMessages+1 || last.Note != decision.NoteMessageLimit || last.Outcome != c.want {
				t.Errorf("%d decisions, last %+v; want one %s with note message_limit after the cap", len(d), last, c.want)
			}
		})
	}
}

func TestDeepGRPCConfiguredMessageCap(t *testing.T) {
	f := fake.Attacks()
	cfg := deep(1<<20, inspect.OversizeClassifyPrefix)
	cfg.DeepMaxMessages = 3
	h := newHarness(t, f, cfg, policy.FailOpen)
	s := h.open()
	send(t, s, headersMsg(false, grpcHeaders...))
	recv(t, s)
	two := append(grpcMsg(false, []byte("one")), grpcMsg(false, []byte("two"))...)
	send(t, s, bodyMsg(two, false))
	if got, _ := streamed(t, s, 1); !bytes.Equal(got, two) {
		t.Fatalf("forwarded %q, want the two messages under the cap", got)
	}
	send(t, s, bodyMsg(grpcMsg(false, []byte("three")), true))
	expectImmediate(t, recv(t, s), 413, 8, "request too large")
	if f.Calls() != 3 {
		t.Errorf("classifier calls = %d, want 3 (headers + two messages)", f.Calls())
	}
}

func TestOversizePolicy(t *testing.T) {
	for _, c := range []struct {
		policy   inspect.Oversize
		outcome  decision.Outcome
		classify bool
		bypass   decision.Outcome
	}{
		{inspect.OversizeClassifyPrefix, "", true, decision.Block},
		{inspect.OversizeBlock, decision.Block, false, decision.Block},
		{inspect.OversizeAllow, decision.Allow, false, decision.Allow},
	} {
		cfg := Config{DeepOversize: c.policy}
		if o, classify := cfg.overLimit(); o != c.outcome || classify != c.classify || cfg.bypassOutcome() != c.bypass {
			t.Errorf("%s: overLimit = %q, %v; bypassOutcome = %q", c.policy, o, classify, cfg.bypassOutcome())
		}
	}
}

func TestDeepOversizeAllowStillEnforcesLimits(t *testing.T) {
	pol, err := policy.Parse([]byte("limits:\n  smuggling: block\n"))
	if err != nil {
		t.Fatal(err)
	}
	obs := &frontendtest.Recorder{}
	guard := classifier.NewGuard(fake.Returning(classifier.Verdict{Benign: 1}), 2*time.Second, classifier.NewBreaker(classifier.DefaultBreakerSettings, time.Now))
	e := decision.NewEngine(guard, pol, policy.Defaults{Threshold: 0.8, FailureMode: policy.FailOpen}, obs)
	h := newHarnessEngine(t, e, obs, deep(1000, inspect.OversizeAllow))
	s := h.open()
	send(t, s, headersMsg(false, with(httpHeaders, "transfer-encoding", "chunked", "content-length", "1800")...))
	expectImmediate(t, recv(t, s), 403, 0, "request blocked")
	if d := h.obs.All(); len(d) == 0 || d[len(d)-1].Note != decision.NoteLimit || d[len(d)-1].Limit != "smuggling" {
		t.Errorf("decisions = %+v, want a smuggling limit block", d)
	}
}
