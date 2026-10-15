package extproc

import (
	"strings"

	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/0x4272616E646F6E/ailuros/internal/frontend"
	"github.com/0x4272616E646F6E/ailuros/internal/frontend/envoyreq"
	"github.com/0x4272616E646F6E/ailuros/internal/inspect"
)

const (
	attrSourceAddress = "source.address"
	attrSNI           = "connection.requested_server_name"
	attrTLSVersion    = "connection.tls_version"
	attrProtocol      = "request.protocol"
)

var RequestAttributes = []string{attrSourceAddress, attrSNI, attrTLSVersion, attrProtocol}

func buildRequest(h *extprocv3.HttpHeaders, attrs map[string]*structpb.Struct, ja4Header string) *inspect.Request {
	headers := envoyreq.Headers(h.GetHeaders().GetHeaders())
	var method, scheme, authority, target string
	for _, hv := range h.GetHeaders().GetHeaders() {
		switch value := envoyreq.HeaderValue(hv); strings.ToLower(hv.GetKey()) {
		case ":method":
			method = value
		case ":scheme":
			scheme = value
		case ":authority":
			authority = value
		case ":path":
			target = value
		}
	}
	r := inspect.NewRequest(method, scheme, authority, target, headers)
	fields := attrs[attributesKey].GetFields()
	r.ClientIP = envoyreq.ClientIP(fields[attrSourceAddress].GetStringValue(), headers)
	sni, version := fields[attrSNI].GetStringValue(), fields[attrTLSVersion].GetStringValue()
	if sni != "" || version != "" {
		r.TLS = &inspect.TLSInfo{SNI: sni, Version: version}
	}
	r.Protocol = fields[attrProtocol].GetStringValue()
	r.JA4 = frontend.TakeJA4(r.Headers, ja4Header)
	return r
}

func first(v []string) string {
	if len(v) > 0 {
		return v[0]
	}
	return ""
}

func (st *stream) withTrailers(r inspect.Request) *inspect.Request {
	if len(st.trailers) == 0 {
		return &r
	}
	h := make(map[string][]string, len(r.Headers)+len(st.trailers))
	for k, v := range r.Headers {
		h[k] = v
	}
	for k, v := range st.trailers {
		h[k] = append(append([]string(nil), h[k]...), v...)
	}
	r.Headers = h
	return &r
}
