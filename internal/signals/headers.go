package signals

import (
	"net/url"
	"strings"

	"github.com/0x4272616E646F6E/decision-waf/internal/inspect"
)

func smugglingOf(r *inspect.Request) []string {
	te, cl := r.Headers["transfer-encoding"], r.Headers["content-length"]
	var flags []string
	add := func(cond bool, flag string) {
		if cond {
			flags = append(flags, flag)
		}
	}
	add(len(te) > 0 && len(cl) > 0, "te_with_cl")
	add(len(te) > 0 && (r.Protocol == "HTTP/2" || r.Protocol == "HTTP/3"), "te_on_h2")
	add(len(te) > 1 || len(te) == 1 && !strings.EqualFold(te[0], "chunked"), "te_not_chunked")
	add(len(cl) > 1 || len(cl) == 1 && strings.Contains(cl[0], ","), "multiple_content_length")
	add(len(r.Headers["host"]) > 1, "multiple_host")
	bad := false
	for name := range r.Headers {
		bad = bad || !inspect.IsToken(name) || name != strings.ToLower(name)
	}
	add(bad, "bad_header_name")
	return flags
}

type WebSocket struct {
	CrossOrigin      bool
	BadVersion       bool
	Subprotocols     []string
	MoreSubprotocols int
}

const maxSubprotocols = 8

const maxSubprotocolLen = 64

func listHas(values []string, token string) bool {
	for e := range inspect.ListElements(values) {
		if strings.EqualFold(e, token) {
			return true
		}
	}
	return false
}

func IsWebSocketHandshake(r *inspect.Request) bool {
	if r == nil || r.Method != "GET" || websocketOf(r) == nil || len(r.Headers["sec-websocket-key"]) == 0 || len(r.Headers["transfer-encoding"]) > 0 {
		return false
	}
	cl := r.Headers["content-length"]
	return len(cl) == 0 || len(cl) == 1 && strings.TrimSpace(cl[0]) == "0"
}

func websocketOf(r *inspect.Request) *WebSocket {
	if !listHas(r.Headers["upgrade"], "websocket") || !listHas(r.Headers["connection"], "upgrade") {
		return nil
	}
	ws := &WebSocket{CrossOrigin: !sameOrigin(r.Headers["origin"], r.Host)}
	if v := r.Headers["sec-websocket-version"]; len(v) != 1 || strings.TrimSpace(v[0]) != "13" {
		ws.BadVersion = true
	}
	for p := range inspect.ListElements(r.Headers["sec-websocket-protocol"]) {
		if len(p) <= maxSubprotocolLen && inspect.IsToken(p) && len(ws.Subprotocols) < maxSubprotocols {
			ws.Subprotocols = append(ws.Subprotocols, p)
		} else {
			ws.MoreSubprotocols++
		}
	}
	return ws
}

func sameOrigin(origin []string, host string) bool {
	if len(origin) != 1 || host == "" {
		return false
	}
	u, err := url.Parse(strings.TrimSpace(origin[0]))
	if err != nil || u.Host == "" {
		return false
	}
	return withoutDefaultPort(u.Host) == withoutDefaultPort(host)
}

func withoutDefaultPort(h string) string {
	h = strings.ToLower(h)
	for _, p := range []string{":80", ":443"} {
		h = strings.TrimSuffix(h, p)
	}
	return h
}
