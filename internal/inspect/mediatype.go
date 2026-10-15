package inspect

import "strings"

func (r *Request) MediaType() string {
	v := r.Headers["content-type"]
	if len(v) == 0 {
		return ""
	}
	mt, _, _ := strings.Cut(v[0], ";")
	return strings.ToLower(strings.TrimSpace(mt))
}

func (r *Request) MultipleContentTypes() bool {
	v := r.Headers["content-type"]
	if len(v) > 1 {
		return true
	}
	return len(v) == 1 && commaOutsideQuotes(v[0])
}

func commaOutsideQuotes(s string) bool {
	quoted := false
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\':
			if quoted {
				i++
			}
		case '"':
			quoted = !quoted
		case ',':
			if !quoted {
				return true
			}
		}
	}
	return false
}

func (r *Request) GRPCContent() bool { return r.GRPCFramed() || r.GRPCWeb() }

func (r *Request) GRPCFramed() bool {
	mt := r.MediaType()
	return mt == "application/grpc" || strings.HasPrefix(mt, "application/grpc+")
}

func (r *Request) GRPCWeb() bool {
	mt := r.MediaType()
	return mt == "application/grpc-web" || strings.HasPrefix(mt, "application/grpc-web+") || r.GRPCWebText()
}

func (r *Request) GRPCWebText() bool {
	mt := r.MediaType()
	return mt == "application/grpc-web-text" || strings.HasPrefix(mt, "application/grpc-web-text+")
}
