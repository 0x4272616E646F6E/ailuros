package inspect

import "encoding/base64"

func DecodeGRPCWebText(b []byte, truncated bool) ([]byte, bool) {
	s := make([]byte, 0, len(b))
	for _, c := range b {
		switch c {
		case '\r', '\n', '\t', ' ':
		default:
			s = append(s, c)
		}
	}
	if rem := len(s) % 4; rem != 0 {
		if !truncated {
			return nil, false
		}
		s = s[:len(s)-rem]
	}
	out := make([]byte, 0, len(s)/4*3)
	var q [3]byte
	for i := 0; i < len(s); i += 4 {
		n, err := base64.StdEncoding.Decode(q[:], s[i:i+4])
		if err != nil {
			return nil, false
		}
		out = append(out, q[:n]...)
	}
	return out, true
}
