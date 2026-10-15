package extproc

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func grpcMsg(compressed bool, payload []byte) []byte {
	b := make([]byte, frameHeaderLen, frameHeaderLen+len(payload))
	if compressed {
		b[0] = 1
	}
	binary.BigEndian.PutUint32(b[1:], uint32(len(payload)))
	return append(b, payload...)
}

func holding(f *framer) bool { return len(f.buf) > 0 || f.passing > 0 }

func drain(f *framer) (passed []byte, frames []*frame) {
	for {
		p, fr := f.next()
		switch {
		case p != nil:
			passed = append(passed, p...)
		case fr != nil:
			frames = append(frames, fr)
			f.passRest(fr)
		default:
			return passed, frames
		}
	}
}

func TestFramerMessageSplitAcrossChunks(t *testing.T) {
	msg := grpcMsg(false, []byte("hello world"))
	f := newFramer(1024, true)
	var frames []*frame
	for i := range msg {
		f.write(msg[i : i+1])
		_, got := drain(f)
		frames = append(frames, got...)
		if i < len(msg)-1 && len(frames) != 0 {
			t.Fatalf("frame yielded after %d of %d bytes", i+1, len(msg))
		}
	}
	if len(frames) != 1 || frames[0].kind != frameMessage || string(frames[0].payload) != "hello world" || !bytes.Equal(frames[0].raw, msg) {
		t.Fatalf("frames = %+v", frames)
	}
	if holding(f) {
		t.Error("holding after a complete message")
	}
}

func TestFramerSeveralMessagesPerChunk(t *testing.T) {
	a, b, c := grpcMsg(false, []byte("a")), grpcMsg(false, nil), grpcMsg(false, []byte("ccc"))
	half := grpcMsg(false, []byte("dddd"))
	f := newFramer(1024, true)
	f.write(append(append(append(append([]byte{}, a...), b...), c...), half[:3]...))
	_, frames := drain(f)
	if len(frames) != 3 || string(frames[0].payload) != "a" || len(frames[1].payload) != 0 || string(frames[2].payload) != "ccc" {
		t.Fatalf("frames = %+v", frames)
	}
	if !holding(f) {
		t.Error("partial fourth message not reported as holding")
	}
	f.write(half[3:])
	if _, frames = drain(f); len(frames) != 1 || string(frames[0].payload) != "dddd" || holding(f) {
		t.Errorf("fourth message = %+v, holding %v", frames, holding(f))
	}
}

func TestFramerBuffersCompressedMessages(t *testing.T) {
	msg := grpcMsg(true, []byte("compressed-bytes"))
	f := newFramer(1024, true)
	f.write(msg[:7])
	if p, fr := f.next(); p != nil || fr != nil {
		t.Fatalf("yielded a compressed message before it was complete: %q %+v", p, fr)
	}
	f.write(append(msg[7:], grpcMsg(false, []byte("next"))...))
	_, frames := drain(f)
	if len(frames) != 2 || frames[0].kind != frameMessage || !frames[0].compressed ||
		string(frames[0].payload) != "compressed-bytes" || !bytes.Equal(frames[0].raw, msg) ||
		frames[1].compressed || string(frames[1].payload) != "next" {
		t.Errorf("frames = %+v", frames)
	}

	big := grpcMsg(true, bytes.Repeat([]byte("z"), 100))
	f = newFramer(10, true)
	f.write(big)
	_, fr := f.next()
	if fr == nil || fr.kind != frameOversize || !fr.compressed || len(fr.payload) != 10 {
		t.Errorf("oversize compressed frame = %+v", fr)
	}
}

func TestFramerOversizeClassifyPrefix(t *testing.T) {
	payload := bytes.Repeat([]byte("x"), 100)
	msg := grpcMsg(false, payload)
	f := newFramer(10, true)
	f.write(msg[:12])
	if p, fr := f.next(); p != nil || fr != nil {
		t.Fatalf("yielded before the 10-byte prefix arrived: %q %+v", p, fr)
	}
	f.write(msg[12:40])
	_, fr := f.next()
	if fr == nil || fr.kind != frameOversize || len(fr.payload) != 10 || fr.length != 100 || !bytes.Equal(fr.raw, msg[:40]) || fr.rest != len(msg)-40 {
		t.Fatalf("frame = %+v", fr)
	}
	f.passRest(fr)
	f.write(msg[40:])
	if passed, frames := drain(f); !bytes.Equal(passed, msg[40:]) || len(frames) != 0 || holding(f) {
		t.Errorf("passed %d bytes, frames %+v, holding %v", len(passed), frames, holding(f))
	}
}

func TestFramerOversizeWithoutPrefixYieldsAtHeader(t *testing.T) {
	msg := grpcMsg(false, bytes.Repeat([]byte("x"), 100))
	f := newFramer(10, false)
	f.write(msg[:5])
	_, fr := f.next()
	if fr == nil || fr.kind != frameOversize || fr.payload != nil || fr.rest != 100 {
		t.Fatalf("frame = %+v", fr)
	}
}

func TestFramerEndOfStreamMidMessage(t *testing.T) {
	msg := grpcMsg(false, []byte("truncated"))
	f := newFramer(1024, true)
	f.write(msg[:8])
	if _, frames := drain(f); len(frames) != 0 || !holding(f) {
		t.Errorf("frames = %+v, holding = %v; want none and true", frames, holding(f))
	}
	g := newFramer(1024, true)
	g.write(msg[:3])
	if !holding(g) {
		t.Error("partial header not reported as holding")
	}
	if got := f.flush(); !bytes.Equal(got, msg[:8]) || holding(f) {
		t.Errorf("flush = %q, holding after flush = %v", got, holding(f))
	}
}

func TestFramerReproducesStreamExactly(t *testing.T) {
	var stream []byte
	stream = append(stream, grpcMsg(false, []byte("one"))...)
	stream = append(stream, grpcMsg(true, []byte("two-compressed"))...)
	stream = append(stream, grpcMsg(false, bytes.Repeat([]byte("3"), 50))...)
	stream = append(stream, grpcMsg(false, []byte("four"))...)
	f := newFramer(20, true)
	var out []byte
	for i := 0; i < len(stream); i += 7 {
		f.write(stream[i:min(i+7, len(stream))])
		for {
			p, fr := f.next()
			if p == nil && fr == nil {
				break
			}
			out = append(out, p...)
			if fr != nil {
				out = append(out, fr.raw...)
				f.passRest(fr)
			}
		}
	}
	if !bytes.Equal(out, stream) || holding(f) {
		t.Errorf("forwarded bytes differ from the stream (got %d of %d bytes)", len(out), len(stream))
	}
}
