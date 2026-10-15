package inspect

import (
	"fmt"
	"strings"
)

type Mode string

const (
	ModeLite     Mode = "lite"
	ModeStandard Mode = "standard"
	ModeDeep     Mode = "deep"
)

func ParseMode(s string) (Mode, error) {
	switch m := Mode(s); m {
	case ModeLite, ModeStandard, ModeDeep:
		return m, nil
	}
	return "", fmt.Errorf("invalid inspection mode %q (want lite, standard, or deep)", s)
}

type Oversize string

const (
	OversizeClassifyPrefix Oversize = "classify_prefix"
	OversizeBlock          Oversize = "block"
	OversizeAllow          Oversize = "allow"
)

func ParseOversize(s string) (Oversize, error) {
	switch o := Oversize(s); o {
	case OversizeClassifyPrefix, OversizeBlock, OversizeAllow:
		return o, nil
	}
	return "", fmt.Errorf("invalid oversize policy %q (want classify_prefix, block, or allow)", s)
}

type TLSInfo struct {
	SNI     string
	Version string
}

type Request struct {
	Method        string
	Scheme        string
	Host          string
	Path          string
	Query         string
	Headers       map[string][]string
	ClientIP      string
	TLS           *TLSInfo
	Protocol      string
	JA4           string
	Signals       []string
	GRPCService   string
	GRPCMethod    string
	Body          []byte
	BodyTruncated bool
}

func (r *Request) IsGRPC() bool { return r.GRPCService != "" }

func (r *Request) Clone() *Request {
	c := *r
	if r.Headers != nil {
		c.Headers = make(map[string][]string, len(r.Headers))
		for k, v := range r.Headers {
			c.Headers[k] = append([]string(nil), v...)
		}
	}
	if r.TLS != nil {
		tls := *r.TLS
		c.TLS = &tls
	}
	if r.Body != nil {
		c.Body = append([]byte(nil), r.Body...)
	}
	if r.Signals != nil {
		c.Signals = append([]string(nil), r.Signals...)
	}
	return &c
}

func ParseGRPCPath(path string) (service, method string, ok bool) {
	service, method, ok = strings.Cut(strings.TrimPrefix(path, "/"), "/")
	if !ok || service == "" || method == "" || strings.Contains(method, "/") {
		return "", "", false
	}
	return service, method, true
}

func NewRequest(method, scheme, authority, target string, headers map[string][]string) *Request {
	path, query, _ := strings.Cut(target, "?")
	r := &Request{Method: method, Scheme: scheme, Host: authority, Path: path, Query: query, Headers: headers}
	if r.GRPCContent() {
		if svc, m, ok := ParseGRPCPath(path); ok {
			r.GRPCService, r.GRPCMethod = svc, m
		}
	}
	return r
}
