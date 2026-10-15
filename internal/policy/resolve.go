package policy

import (
	"net"
	"path"
	"slices"
	"strconv"
	"strings"

	"github.com/0x4272616E646F6E/ailuros/internal/inspect"
)

type Defaults struct {
	Threshold   float64
	FailureMode FailureMode
	BadOutput   BadOutput
}

type Resolved struct {
	Route       string
	FailureMode FailureMode
	Limits      Limits

	routeThreshold   *float64
	defaultThreshold float64
}

func (p *Policy) Resolve(r *inspect.Request, d Defaults) Resolved {
	host := normalizeHost(r.Host)
	type reading struct {
		path string
		fold bool
	}
	var readings []reading
	for _, path := range []string{
		normalizePath(r.Path, true),
		normalizePath(r.Path, false),
		normalizePath(strings.ReplaceAll(r.Path, `\`, "/"), true),
		normalizePath(strings.ReplaceAll(r.Path, `\`, "/"), false),
		withoutParams(r.Path),
	} {
		for _, rd := range []reading{{path, false}, {strings.ToLower(path), true}} {
			if !slices.Contains(readings, rd) {
				readings = append(readings, rd)
			}
		}
	}
	var res Resolved
	for i, rd := range readings {
		for j, segments := range []bool{true, false} {
			one := p.resolve(host, rd.path, r.GRPCService, segments, rd.fold, d)
			if i == 0 && j == 0 {
				res = one
			} else {
				res = stricter(res, one)
			}
		}
	}
	return res
}

func (p *Policy) resolve(host, reqPath, grpcService string, segments, fold bool, d Defaults) Resolved {
	res := Resolved{Route: "default", FailureMode: d.FailureMode, defaultThreshold: d.Threshold, Limits: p.Limits}
	for i, rt := range p.Routes {
		m := rt.Match
		if fold {
			m.PathPrefix = strings.ToLower(m.PathPrefix)
		}
		if !m.matches(host, reqPath, grpcService, segments) {
			continue
		}
		res.Route = strconv.Itoa(i)
		if rt.FailureMode != "" {
			res.FailureMode = rt.FailureMode
		}
		res.routeThreshold = rt.Threshold
		res.Limits = p.Limits.overriddenBy(rt.Limits)
		break
	}
	return res
}

func stricter(a, b Resolved) Resolved {
	out, other := a, b
	if b.Threshold() < a.Threshold() {
		out, other = b, a
	}
	if out.FailureMode != FailClosed && other.FailureMode == FailClosed {
		out.FailureMode = FailClosed
		if !slices.Contains(strings.Split(out.Route, "+"), other.Route) {
			out.Route += "+" + other.Route
		}
	}
	if merged := out.Limits.stricter(other.Limits); !merged.equal(out.Limits) {
		if !slices.Contains(strings.Split(out.Route, "+"), other.Route) {
			out.Route += "+" + other.Route
		}
		out.Limits = merged
	}
	return out
}

const scoreEpsilon = 1e-9

func Blocks(score, threshold float64) bool { return score >= threshold-scoreEpsilon }

func (r Resolved) Threshold() float64 {
	if r.routeThreshold != nil {
		return *r.routeThreshold
	}
	return r.defaultThreshold
}

func (m Match) matches(host, reqPath, grpcService string, segments bool) bool {
	if m.Host != "" && !strings.EqualFold(m.Host, host) {
		return false
	}
	if m.PathPrefix != "" && !underPrefix(reqPath, m.PathPrefix, segments) {
		return false
	}
	if m.GRPCService != "" && m.GRPCService != grpcService {
		return false
	}
	return true
}

func underPrefix(reqPath, prefix string, segments bool) bool {
	if prefix == "/" {
		return true
	}
	rest, ok := strings.CutPrefix(reqPath, prefix)
	return ok && (!segments || rest == "" || rest[0] == '/')
}

func normalizeHost(h string) string {
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	h = strings.TrimSuffix(strings.TrimPrefix(h, "["), "]")
	return strings.TrimSuffix(strings.ToLower(h), ".")
}

func normalizePath(p string, decodeSlashes bool) string {
	return cleanPath(unescapeLenient(p, decodeSlashes))
}

func withoutParams(p string) string {
	segs := strings.Split(unescapeLenient(p, true), "/")
	for i, s := range segs {
		segs[i], _, _ = strings.Cut(s, ";")
	}
	return cleanPath(strings.Join(segs, "/"))
}

func cleanPath(p string) string {
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	cleaned := path.Clean(p)
	if strings.HasSuffix(p, "/") && cleaned != "/" {
		cleaned += "/"
	}
	return cleaned
}

func unescapeLenient(s string, decodeSlashes bool) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) && inspect.IsHex(s[i+1]) && inspect.IsHex(s[i+2]) {
			c := inspect.Unhex(s[i+1])<<4 | inspect.Unhex(s[i+2])
			switch {
			case !decodeSlashes && (c == '/' || c == '\\'):
				b.WriteString(s[i : i+3])
			case c == '\\':
				b.WriteByte('/')
			default:
				b.WriteByte(c)
			}
			i += 2
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
