package extproc

import (
	"encoding/binary"
	"errors"
	"strings"

	"github.com/0x4272616E646F6E/decision-waf/internal/inspect"
)

var errUninspectable = errors.New("uninspectable body encoding")

func plaintext(r *inspect.Request, body []byte, max int, truncated bool) (out []byte, over bool, err error) {
	switch {
	case len(body) == 0:
		return body, false, nil
	case r.GRPCWeb():
		if messageEncoding(r) != "" {
			return nil, false, errUninspectable
		}
	case r.GRPCFramed():
		if enc := messageEncoding(r); enc != "" {
			return grpcPlaintext(enc, body, max, truncated)
		}
		return clip(body, max)
	}
	enc, ok := contentEncoding(r)
	if !ok {
		return nil, false, errUninspectable
	}
	if enc == "" {
		return clip(body, max)
	}
	out, over, err = decompress(enc, body, max, truncated)
	if err != nil {
		return nil, false, errUninspectable
	}
	return out, over, nil
}

func clip(b []byte, max int) ([]byte, bool, error) {
	if len(b) > max {
		return b[:max], true, nil
	}
	return b, false, nil
}

func contentEncoding(r *inspect.Request) (enc string, ok bool) {
	var codings []string
	for c := range inspect.ListElements(r.Headers["content-encoding"]) {
		if c = strings.ToLower(c); c != "identity" {
			codings = append(codings, c)
		}
	}
	switch {
	case len(codings) == 0:
		return "", true
	case len(codings) > 1:
		return "", false
	}
	switch codings[0] {
	case "gzip", "x-gzip":
		return "gzip", true
	case "deflate":
		return "deflate", true
	}
	return "", false
}

func messageEncoding(r *inspect.Request) string {
	for _, v := range r.Headers["grpc-encoding"] {
		if v = strings.ToLower(strings.TrimSpace(v)); v != "" && v != "identity" {
			return v
		}
	}
	return ""
}

func grpcPlaintext(enc string, body []byte, max int, truncated bool) (out []byte, over bool, err error) {
	for len(body) > 0 && len(out) <= max {
		if len(body) < frameHeaderLen {
			break
		}
		compressed := compressedFlag(body[0])
		n := int(binary.BigEndian.Uint32(body[1:frameHeaderLen]))
		body = body[frameHeaderLen:]
		cut := n > len(body)
		if cut {
			if !truncated {
				return nil, false, errUninspectable
			}
			n = len(body)
		}
		payload := body[:n]
		body = body[n:]
		if compressed {
			plain, more, err := decompress(enc, payload, max-len(out), truncated && cut)
			if err != nil {
				return nil, false, errUninspectable
			}
			payload, over = plain, more
		}
		out = append(out, payload...)
		if over {
			break
		}
	}
	if len(out) > max {
		return out[:max], true, nil
	}
	return out, over, nil
}
