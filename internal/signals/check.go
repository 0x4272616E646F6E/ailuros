package signals

import "github.com/0x4272616E646F6E/decision-waf/internal/policy"

func Check(s Signals, l policy.Limits) (limit string, hit bool) {
	if l.Smuggling.Blocks() && len(s.Smuggling) > 0 {
		return "smuggling", true
	}
	if ws := s.WebSocket; ws != nil {
		if l.WebSocket.CrossOrigin.Blocks() && ws.CrossOrigin {
			return "websocket_cross_origin", true
		}
		if l.WebSocket.BadVersion.Blocks() && ws.BadVersion {
			return "websocket_bad_version", true
		}
	}
	if l.JA4Blocked(s.JA4) {
		return "ja4", true
	}
	g, gl := s.GraphQL, l.GraphQL
	if g == nil {
		return "", false
	}
	over := func(max, got int) bool { return max > 0 && got > max }
	switch {
	case over(gl.MaxBatch, g.Batch):
		return "graphql_batch", true
	case over(gl.MaxOperations, g.Operations):
		return "graphql_operations", true
	case gl.Introspection.Blocks() && g.Introspection:
		return "graphql_introspection", true
	case over(gl.MaxDepth, g.Depth):
		return "graphql_depth", true
	case over(gl.MaxAliases, g.Aliases):
		return "graphql_aliases", true
	case over(gl.MaxFields, g.Fields):
		return "graphql_fields", true
	}
	return "", false
}
