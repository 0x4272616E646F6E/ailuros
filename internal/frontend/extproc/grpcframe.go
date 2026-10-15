package extproc

import "encoding/binary"

const frameHeaderLen = 5

func compressedFlag(b byte) bool { return b != 0 }

type frameKind int

const (
	frameMessage frameKind = iota
	frameOversize
)

type frame struct {
	kind       frameKind
	compressed bool
	length     int
	raw        []byte
	payload    []byte
	partial    bool
	rest       int
}

type framer struct {
	max        int
	waitPrefix bool
	buf        []byte
	ignoreFlag bool
	passing    int
}

func newFramer(max int, waitPrefix bool) *framer {
	return &framer{max: max, waitPrefix: waitPrefix}
}

func (f *framer) write(b []byte) { f.buf = append(f.buf, b...) }

func (f *framer) next() (pass []byte, fr *frame) {
	if f.passing > 0 {
		n := min(f.passing, len(f.buf))
		if n == 0 {
			return nil, nil
		}
		f.passing -= n
		return f.take(n), nil
	}
	if len(f.buf) < frameHeaderLen {
		return nil, nil
	}
	compressed := compressedFlag(f.buf[0]) && !f.ignoreFlag
	length := int(binary.BigEndian.Uint32(f.buf[1:frameHeaderLen]))
	total := frameHeaderLen + length
	switch {
	case length > f.max:
		if f.waitPrefix && len(f.buf) < frameHeaderLen+f.max {
			return nil, nil
		}
		raw := f.take(min(total, len(f.buf)))
		fr := &frame{kind: frameOversize, compressed: compressed, length: length, raw: raw, rest: total - len(raw)}
		if f.waitPrefix {
			fr.payload = raw[frameHeaderLen : frameHeaderLen+f.max]
		}
		return nil, fr
	case len(f.buf) < total:
		return nil, nil
	}
	raw := f.take(total)
	return nil, &frame{kind: frameMessage, compressed: compressed, length: length, raw: raw, payload: raw[frameHeaderLen:]}
}

func (f *framer) passRest(fr *frame) { f.passing = fr.rest }

func (f *framer) flush() []byte {
	out := f.buf
	f.buf, f.passing = nil, 0
	return out
}

func (f *framer) take(n int) []byte {
	out := append([]byte(nil), f.buf[:n]...)
	f.buf = f.buf[n:]
	if len(f.buf) == 0 {
		f.buf = nil
	}
	return out
}

func (f *framer) partialFrame() *frame {
	if len(f.buf) == 0 {
		return nil
	}
	raw := f.take(len(f.buf))
	fr := &frame{kind: frameMessage, raw: raw, partial: true, compressed: compressedFlag(raw[0]) && !f.ignoreFlag}
	if len(raw) > frameHeaderLen {
		fr.payload = raw[frameHeaderLen:]
	}
	return fr
}
