package signals

import (
	"fmt"
	"slices"
	"strings"

	"github.com/0x4272616E646F6E/ailuros/internal/inspect"
)

type Signals struct {
	Protocol  string
	JA4       string
	GraphQL   *GraphQL
	Smuggling []string
	WebSocket *WebSocket
}

func Extract(r *inspect.Request) Signals {
	if r == nil {
		return Signals{}
	}
	return Signals{
		Protocol:  r.Protocol,
		JA4:       r.JA4,
		GraphQL:   graphQLOf(r),
		Smuggling: smugglingOf(r),
		WebSocket: websocketOf(r),
	}
}

func (s Signals) Lines() []string {
	var lines []string
	add := func(name, value string) {
		if value != "" {
			lines = append(lines, name+": "+value)
		}
	}
	add("protocol", s.Protocol)
	add("ja4", s.JA4)
	if s.GraphQL != nil {
		add("graphql", s.GraphQL.line())
	}
	add("smuggling", strings.Join(s.Smuggling, " "))
	if ws := s.WebSocket; ws != nil {
		var parts []string
		if ws.CrossOrigin {
			parts = append(parts, "cross_origin")
		}
		if ws.BadVersion {
			parts = append(parts, "bad_version")
		}
		if protos := ws.Subprotocols; len(protos) > 0 || ws.MoreSubprotocols > 0 {
			if ws.MoreSubprotocols > 0 {
				protos = append(slices.Clip(protos), fmt.Sprintf("+%d", ws.MoreSubprotocols))
			}
			parts = append(parts, "subprotocols="+strings.Join(protos, ","))
		}
		if len(parts) == 0 {
			parts = []string{"handshake"}
		}
		add("websocket", strings.Join(parts, " "))
	}
	return lines
}
