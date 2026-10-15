package extproc

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"errors"
	"io"
	"testing"
)

func compress(t *testing.T, enc string, data []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	var w io.WriteCloser
	switch enc {
	case "gzip":
		w = gzip.NewWriter(&b)
	case "deflate":
		w = zlib.NewWriter(&b)
	default:
		t.Fatalf("no encoder for %q", enc)
	}
	if _, err := w.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func TestDecompressRoundTrips(t *testing.T) {
	cases := []struct{ header, encoder string }{
		{"gzip", "gzip"}, {"deflate", "deflate"}, {"GZip", "gzip"},
	}
	for _, c := range cases {
		out, over, err := decompress(c.header, compress(t, c.encoder, []byte("an attack payload")), 1024, false)
		if err != nil || over || string(out) != "an attack payload" {
			t.Errorf("%s: out=%q over=%v err=%v", c.header, out, over, err)
		}
	}
}

func TestDecompressBombIsBounded(t *testing.T) {
	bomb := compress(t, "gzip", make([]byte, 8<<20))
	if len(bomb) > 64<<10 {
		t.Fatalf("bomb is %d bytes; expected a small compressed message", len(bomb))
	}
	out, over, err := decompress("gzip", bomb, 4096, false)
	if err != nil || !over || len(out) != 4096 {
		t.Errorf("len(out)=%d over=%v err=%v; want exactly the 4096-byte cap, over", len(out), over, err)
	}
}

func TestDecompressTruncatedInputYieldsPrefix(t *testing.T) {
	data := bytes.Repeat([]byte("abcdefgh"), 4096)
	z := compress(t, "gzip", data)
	out, _, err := decompress("gzip", z[:len(z)/2], 1<<20, true)
	if err != nil || len(out) == 0 || !bytes.HasPrefix(data, out) {
		t.Errorf("len(out)=%d err=%v; want a non-empty prefix of the plaintext", len(out), err)
	}
	if _, _, err := decompress("gzip", z[:len(z)/2], 1<<20, false); err == nil {
		t.Error("a truncated message that is not marked truncated must be an error")
	}
}

func TestDecompressRejectsUnsupportedAndCorrupt(t *testing.T) {
	if _, _, err := decompress("snappy", []byte("whatever"), 1024, false); !errors.Is(err, errUnsupportedEncoding) {
		t.Errorf("snappy: err = %v, want errUnsupportedEncoding", err)
	}
	if _, _, err := decompress("zstd", []byte("whatever"), 1024, false); !errors.Is(err, errUnsupportedEncoding) {
		t.Errorf("zstd: err = %v, want errUnsupportedEncoding", err)
	}
	for _, enc := range []string{"gzip", "deflate"} {
		if _, _, err := decompress(enc, []byte("not compressed at all"), 1024, false); err == nil {
			t.Errorf("%s: corrupt data accepted", enc)
		}
	}
}
