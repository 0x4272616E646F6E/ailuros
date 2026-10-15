package extproc

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"errors"
	"fmt"
	"io"
	"strings"
)

var errUnsupportedEncoding = errors.New("unsupported encoding")

func decompress(enc string, data []byte, max int, truncated bool) (out []byte, over bool, err error) {
	var r io.ReadCloser
	switch strings.ToLower(strings.TrimSpace(enc)) {
	case "gzip":
		r, err = gzip.NewReader(bytes.NewReader(data))
	case "deflate":
		r, err = zlib.NewReader(bytes.NewReader(data))
		if errors.Is(err, zlib.ErrHeader) {
			r, err = flate.NewReader(bytes.NewReader(data)), nil
		}
	default:
		return nil, false, fmt.Errorf("%w %q", errUnsupportedEncoding, enc)
	}
	if err != nil {
		return nil, false, err
	}
	defer r.Close()
	out, err = io.ReadAll(io.LimitReader(r, int64(max)+1))
	if len(out) > max {
		return out[:max], true, nil
	}
	if err != nil {
		if truncated && errors.Is(err, io.ErrUnexpectedEOF) && len(out) > 0 {
			return out, false, nil
		}
		return nil, false, err
	}
	return out, false, nil
}
