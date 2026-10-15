package extproc

import (
	"bytes"
	"compress/flate"
	"testing"

	"github.com/0x4272616E646F6E/ailuros/internal/classifier/fake"
	"github.com/0x4272616E646F6E/ailuros/internal/decision"
	"github.com/0x4272616E646F6E/ailuros/internal/inspect"
	"github.com/0x4272616E646F6E/ailuros/internal/policy"
)

func rawDeflate(t *testing.T, data []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	w, err := flate.NewWriter(&b, flate.DefaultCompression)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func TestContentEncodedBodiesAreDecompressed(t *testing.T) {
	encodings := []struct {
		header string
		encode func(*testing.T, []byte) []byte
	}{
		{"gzip", func(t *testing.T, b []byte) []byte { return compress(t, "gzip", b) }},
		{"x-gzip", func(t *testing.T, b []byte) []byte { return compress(t, "gzip", b) }},
		{"deflate", func(t *testing.T, b []byte) []byte { return compress(t, "deflate", b) }},
		{"deflate", rawDeflate},
		{"identity, gzip", func(t *testing.T, b []byte) []byte { return compress(t, "gzip", b) }},
	}
	for _, mode := range []inspect.Mode{inspect.ModeStandard, inspect.ModeDeep} {
		for _, enc := range encodings {
			for _, payload := range []string{`{"q":"an attack, compressed"}`, `{"q":"hello"}`} {
				t.Run(string(mode)+"/"+enc.header+"/"+payload, func(t *testing.T) {
					body := enc.encode(t, []byte(payload))
					cfg := standard
					if mode == inspect.ModeDeep {
						cfg = deep(1<<20, inspect.OversizeClassifyPrefix)
					}
					f := fake.Attacks()
					h := newHarness(t, f, cfg, policy.FailOpen)
					s := h.open()
					send(t, s, headersMsg(false, with(httpHeaders, "content-encoding", enc.header)...))
					recv(t, s)
					send(t, s, bodyMsg(body, true))
					r := recv(t, s)
					attack := bytes.Contains([]byte(payload), []byte("attack"))
					switch {
					case attack:
						expectImmediate(t, r, 403, 0, "request blocked")
					case mode == inspect.ModeDeep:
						if got := r.GetRequestBody().GetResponse().GetBodyMutation().GetStreamedResponse().GetBody(); !bytes.Equal(got, body) {
							t.Errorf("forwarded %q, want the compressed body byte for byte", got)
						}
					default:
						mutationHeaders(t, r)
					}
					if got := f.Last(); string(got.Body) != payload {
						t.Errorf("classifier saw %q, want the decompressed body", got.Body)
					}
				})
			}
		}
	}
}

func TestDeepContentEncodedBombIsOversize(t *testing.T) {
	body := compress(t, "gzip", append([]byte("attack "), make([]byte, 1<<20)...))
	for _, c := range []struct {
		policy inspect.Oversize
		status int
		msg    string
	}{{inspect.OversizeClassifyPrefix, 403, "request blocked"}, {inspect.OversizeBlock, 413, "request too large"}} {
		t.Run(string(c.policy), func(t *testing.T) {
			f := fake.Attacks()
			h := newHarness(t, f, deep(4096, c.policy), policy.FailOpen)
			s := h.open()
			send(t, s, headersMsg(false, with(httpHeaders, "content-encoding", "gzip")...))
			recv(t, s)
			send(t, s, bodyMsg(body, true))
			expectImmediate(t, recv(t, s), c.status, 0, c.msg)
			if c.policy == inspect.OversizeClassifyPrefix {
				if got := f.Last(); len(got.Body) != 4096 || !got.BodyTruncated {
					t.Errorf("classifier saw %d bytes (truncated %v), want the 4096-byte decompressed prefix", len(got.Body), got.BodyTruncated)
				}
			}
		})
	}
}

func TestUninspectableBodyEncodings(t *testing.T) {
	inputs := []struct {
		name    string
		headers []string
		body    []byte
	}{
		{"brotli", with(httpHeaders, "content-encoding", "br"), []byte("an attack in brotli")},
		{"stacked codings", with(httpHeaders, "content-encoding", "gzip, gzip"), []byte("an attack")},
		{"corrupt gzip", with(httpHeaders, "content-encoding", "gzip"), []byte("an attack, not gzip")},
		{"compressed gRPC-Web", []string{":method", "POST", ":scheme", "http", ":authority", "api.internal", ":path", "/payments.v1.Payments/Charge",
			"content-type", "application/grpc-web+proto", "grpc-encoding", "gzip"}, []byte("\x01\x00\x00\x00\x09an attack")},
	}
	cases := []struct {
		name   string
		cfg    Config
		denied bool
	}{
		{"standard", standard, true},
		{"deep/classify_prefix", deep(1<<20, inspect.OversizeClassifyPrefix), true},
		{"deep/allow", deep(1<<20, inspect.OversizeAllow), false},
	}
	for _, in := range inputs {
		for _, c := range cases {
			t.Run(in.name+"/"+c.name, func(t *testing.T) {
				f := fake.Attacks()
				h := newHarness(t, f, c.cfg, policy.FailOpen)
				s := h.open()
				send(t, s, headersMsg(false, in.headers...))
				recv(t, s)
				before := f.Calls()
				send(t, s, bodyMsg(in.body, true))
				r := recv(t, s)
				grpc := func(code uint32) uint32 {
					if in.name == "compressed gRPC-Web" {
						return code
					}
					return 0
				}
				d := h.obs.All()
				switch {
				case c.denied:
					expectImmediate(t, r, 413, grpc(8), "request too large")
					if f.Calls() != before {
						t.Errorf("the classifier saw the undecodable body")
					}
				default:
					expectImmediate(t, r, 403, grpc(7), "request blocked")
					if f.Calls() != before+1 || !bytes.Equal(f.Last().Body, in.body) {
						t.Errorf("classifier calls %d, last body %q; want the body classified as sent", f.Calls()-before, f.Last().Body)
					}
					d = h.obs.All()
				}
				if d[len(d)-1].Note != decision.NoteUninspectable {
					t.Errorf("last decision = %+v, want note uninspectable", d[len(d)-1])
				}
			})
		}
	}
}

func TestStandardGRPCCompressedMessage(t *testing.T) {
	f := fake.Attacks()
	h := newHarness(t, f, standard, policy.FailOpen)
	s := h.open()
	send(t, s, headersMsg(false, with(grpcHeaders, "grpc-encoding", "gzip")...))
	recv(t, s)
	body := append(grpcMsg(false, []byte("hello ")), grpcMsg(true, compress(t, "gzip", []byte("an attack")))...)
	send(t, s, bodyMsg(body, true))
	expectImmediate(t, recv(t, s), 403, 7, "request blocked")
	if got := f.Last(); string(got.Body) != "hello an attack" {
		t.Errorf("classifier saw %q, want both payloads in plaintext", got.Body)
	}
}

func TestGRPCPlaintextTruncated(t *testing.T) {
	plain := randomBytes(8192)
	msg := grpcMsg(true, compress(t, "gzip", plain))
	cut := msg[:len(msg)/2]
	if _, _, err := grpcPlaintext("gzip", cut, 1<<20, false); err == nil {
		t.Error("a whole body with a cut-off message: want an error")
	}
	out, _, err := grpcPlaintext("gzip", cut, 1<<20, true)
	if err != nil || len(out) == 0 || !bytes.HasPrefix(plain, out) {
		t.Errorf("truncated prefix: out %d bytes, err %v; want a plaintext prefix", len(out), err)
	}
}

func TestEmptyEncodedBodyIsNotDecoded(t *testing.T) {
	for _, cfg := range []Config{standard, deep(1<<20, inspect.OversizeClassifyPrefix)} {
		h := newHarness(t, fake.Attacks(), cfg, policy.FailOpen)
		s := h.open()
		send(t, s, headersMsg(false, with(httpHeaders, "content-encoding", "gzip")...))
		recv(t, s)
		send(t, s, bodyMsg(nil, true))
		if r := recv(t, s); r.GetImmediateResponse() != nil {
			t.Errorf("%s: empty gzip body denied: %v", cfg.Mode, r)
		}
	}
}

func TestStandardGRPCOddCompressedFlag(t *testing.T) {
	f := fake.Attacks()
	h := newHarness(t, f, standard, policy.FailOpen)
	s := h.open()
	send(t, s, headersMsg(false, with(grpcHeaders, "grpc-encoding", "gzip")...))
	recv(t, s)
	msg := grpcMsg(false, []byte("an attack in plaintext"))
	msg[0] = 2
	send(t, s, bodyMsg(msg, true))
	expectImmediate(t, recv(t, s), 413, 8, "request too large")
}
