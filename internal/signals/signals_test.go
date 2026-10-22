package signals

import (
	"slices"
	"testing"

	"github.com/0x4272616E646F6E/decision-waf/internal/inspect"
)

func TestExtractLines(t *testing.T) {
	r := handshake("a", "origin", "https://b", "transfer-encoding", "chunked")
	r.Protocol, r.JA4 = "HTTP/2", "t13d1516h2_8daaf6152771_b186095e22b6"
	r.Query = "query=%7B+a+%7D"
	got := Extract(r).Lines()
	want := []string{
		"protocol: HTTP/2",
		"ja4: t13d1516h2_8daaf6152771_b186095e22b6",
		"graphql: op=query operations=1 depth=1 fields=1 aliases=0 introspection=no",
		"smuggling: te_on_h2",
		"websocket: cross_origin",
	}
	if !slices.Equal(got, want) {
		t.Errorf("got  %q\nwant %q", got, want)
	}
	if lines := Extract(&inspect.Request{Method: "GET", Path: "/"}).Lines(); len(lines) != 0 {
		t.Errorf("plain request has signals %q", lines)
	}
	if lines := Extract(nil).Lines(); len(lines) != 0 {
		t.Errorf("nil request has signals %q", lines)
	}
}
