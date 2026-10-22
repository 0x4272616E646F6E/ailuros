package signals

import (
	"slices"
	"strings"
	"testing"

	"github.com/0x4272616E646F6E/decision-waf/internal/inspect"
)

func TestSmugglingFlags(t *testing.T) {
	cases := []struct {
		name     string
		protocol string
		headers  map[string][]string
		want     []string
	}{
		{"clean", "HTTP/1.1", map[string][]string{"content-length": {"10"}}, nil},
		{"chunked on HTTP/1.1", "HTTP/1.1", map[string][]string{"transfer-encoding": {"chunked"}}, nil},
		{"te and cl", "HTTP/1.1", map[string][]string{"transfer-encoding": {"chunked"}, "content-length": {"5"}}, []string{"te_with_cl"}},
		{"te on h2", "HTTP/2", map[string][]string{"transfer-encoding": {"chunked"}}, []string{"te_on_h2"}},
		{"te on h3", "HTTP/3", map[string][]string{"transfer-encoding": {"chunked"}}, []string{"te_on_h2"}},
		{"te not chunked", "", map[string][]string{"transfer-encoding": {"chunked, identity"}}, []string{"te_not_chunked"}},
		{"two te", "", map[string][]string{"transfer-encoding": {"chunked", "chunked"}}, []string{"te_not_chunked"}},
		{"two cl", "", map[string][]string{"content-length": {"5", "6"}}, []string{"multiple_content_length"}},
		{"cl list", "", map[string][]string{"content-length": {"5, 5"}}, []string{"multiple_content_length"}},
		{"two equal cl", "", map[string][]string{"content-length": {"5", "5"}}, []string{"multiple_content_length"}},
		{"two hosts", "", map[string][]string{"host": {"a", "b"}}, []string{"multiple_host"}},
		{"bad name", "", map[string][]string{"x y": {"1"}}, []string{"bad_header_name"}},
	}
	for _, c := range cases {
		got := smugglingOf(&inspect.Request{Protocol: c.protocol, Headers: c.headers})
		if !slices.Equal(got, c.want) {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func handshake(host string, extra ...string) *inspect.Request {
	h := map[string][]string{
		"upgrade": {"websocket"}, "connection": {"Upgrade"},
		"sec-websocket-version": {"13"}, "sec-websocket-key": {"dGhlIHNhbXBsZSBub25jZQ=="},
	}
	for i := 0; i+1 < len(extra); i += 2 {
		h[extra[i]] = []string{extra[i+1]}
	}
	return &inspect.Request{Method: "GET", Host: host, Path: "/ws", Headers: h}
}

func TestWebSocketOrigin(t *testing.T) {
	cases := []struct {
		r     *inspect.Request
		cross bool
	}{
		{handshake("shop.example.com", "origin", "https://shop.example.com"), false},
		{handshake("shop.example.com:443", "origin", "https://shop.example.com"), false},
		{handshake("shop.example.com", "origin", "http://shop.example.com:80"), false},
		{handshake("SHOP.example.com", "origin", "https://shop.EXAMPLE.com"), false},
		{handshake("shop.example.com", "origin", "https://evil.example"), true},
		{handshake("shop.example.com", "origin", "https://shop.example.com:8443"), true},
		{handshake("shop.example.com", "origin", "null"), true},
		{handshake("shop.example.com"), true},
	}
	for _, c := range cases {
		ws := websocketOf(c.r)
		if ws == nil || ws.CrossOrigin != c.cross {
			t.Errorf("host %s origin %v: got %+v, want cross_origin %v", c.r.Host, c.r.Headers["origin"], ws, c.cross)
		}
	}
}

func TestWebSocketDetails(t *testing.T) {
	ws := websocketOf(handshake("a", "origin", "https://a", "sec-websocket-protocol", "graphql-ws, chat", "sec-websocket-version", "8"))
	if ws == nil || !ws.BadVersion || !slices.Equal(ws.Subprotocols, []string{"graphql-ws", "chat"}) {
		t.Errorf("got %+v", ws)
	}
	notHandshake := handshake("a")
	delete(notHandshake.Headers, "connection")
	if ws := websocketOf(notHandshake); ws != nil {
		t.Errorf("Upgrade without Connection: upgrade detected as a handshake: %+v", ws)
	}
	if ws := websocketOf(&inspect.Request{Method: "GET", Headers: map[string][]string{"upgrade": {"h2c"}, "connection": {"upgrade"}}}); ws != nil {
		t.Errorf("h2c upgrade detected as WebSocket: %+v", ws)
	}
}

func TestIsWebSocketHandshake(t *testing.T) {
	base := func(mod func(h map[string][]string, r *inspect.Request)) *inspect.Request {
		r := &inspect.Request{Method: "GET", Host: "a.example", Headers: map[string][]string{
			"upgrade": {"websocket"}, "connection": {"Upgrade"}, "sec-websocket-key": {"dGhlIHNhbXBsZSBub25jZQ=="},
		}}
		if mod != nil {
			mod(r.Headers, r)
		}
		return r
	}
	cases := []struct {
		name string
		r    *inspect.Request
		want bool
	}{
		{"plain handshake", base(nil), true},
		{"content-length 0", base(func(h map[string][]string, _ *inspect.Request) { h["content-length"] = []string{"0"} }), true},
		{"nil", nil, false},
		{"POST", base(func(_ map[string][]string, r *inspect.Request) { r.Method = "POST" }), false},
		{"content-length 5", base(func(h map[string][]string, _ *inspect.Request) { h["content-length"] = []string{"5"} }), false},
		{"transfer-encoding", base(func(h map[string][]string, _ *inspect.Request) { h["transfer-encoding"] = []string{"chunked"} }), false},
		{"no key", base(func(h map[string][]string, _ *inspect.Request) { delete(h, "sec-websocket-key") }), false},
		{"no connection upgrade", base(func(h map[string][]string, _ *inspect.Request) { delete(h, "connection") }), false},
		{"no upgrade", base(func(h map[string][]string, _ *inspect.Request) { delete(h, "upgrade") }), false},
	}
	for _, c := range cases {
		if got := IsWebSocketHandshake(c.r); got != c.want {
			t.Errorf("%s: = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestWebSocketSubprotocolsAreTokens(t *testing.T) {
	long := strings.Repeat("p", 64)
	cases := []struct{ offered, want string }{
		{"graphql-ws, chat", "subprotocols=graphql-ws,chat"},
		{"x depth=1 introspection=no", "subprotocols=+1"},
		{"ok, a b, " + long + ", " + long + "q", "subprotocols=ok," + long + ",+2"},
		{"p1,p2,p3,p4,p5,p6,p7,p8,p9,p10", "subprotocols=p1,p2,p3,p4,p5,p6,p7,p8,+2"},
	}
	for _, c := range cases {
		lines := Extract(handshake("a", "origin", "https://a", "sec-websocket-protocol", c.offered)).Lines()
		want := []string{"websocket: " + c.want}
		if !slices.Equal(lines, want) {
			t.Errorf("%q: got %q, want %q", c.offered, lines, want)
		}
	}
}
