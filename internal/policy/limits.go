package policy

import (
	"regexp"
	"slices"
	"strings"
)

type Action string

const (
	ActionAllow Action = "allow"
	ActionBlock Action = "block"
)

func (a Action) Blocks() bool { return a == ActionBlock }

type GraphQLLimits struct {
	MaxDepth, MaxAliases, MaxFields, MaxOperations, MaxBatch int
	Introspection                                            Action
}

type WebSocketLimits struct {
	CrossOrigin, BadVersion Action
}

type Limits struct {
	GraphQL   GraphQLLimits
	Smuggling Action
	WebSocket WebSocketLimits
	JA4Block  []string
}

var ja4Pattern = regexp.MustCompile(`^[0-9a-z_]+\*?$`)

func (l Limits) JA4Blocked(fp string) bool {
	if fp == "" {
		return false
	}
	for _, p := range l.JA4Block {
		if pre, ok := strings.CutSuffix(p, "*"); ok && strings.HasPrefix(fp, pre) || p == fp {
			return true
		}
	}
	return false
}

func orInt(a, b int) int {
	if b != 0 {
		return b
	}
	return a
}

func orAction(a, b Action) Action {
	if b != "" {
		return b
	}
	return a
}

func (l Limits) combine(o Limits, n func(a, b int) int, a func(a, b Action) Action) Limits {
	g, og := l.GraphQL, o.GraphQL
	return Limits{
		GraphQL: GraphQLLimits{
			MaxDepth: n(g.MaxDepth, og.MaxDepth), MaxAliases: n(g.MaxAliases, og.MaxAliases),
			MaxFields: n(g.MaxFields, og.MaxFields), MaxOperations: n(g.MaxOperations, og.MaxOperations),
			MaxBatch: n(g.MaxBatch, og.MaxBatch), Introspection: a(g.Introspection, og.Introspection),
		},
		Smuggling: a(l.Smuggling, o.Smuggling),
		WebSocket: WebSocketLimits{
			CrossOrigin: a(l.WebSocket.CrossOrigin, o.WebSocket.CrossOrigin),
			BadVersion:  a(l.WebSocket.BadVersion, o.WebSocket.BadVersion),
		},
	}
}

func (l Limits) overriddenBy(o Limits) Limits {
	out := l.combine(o, orInt, orAction)
	out.JA4Block = l.JA4Block
	if o.JA4Block != nil {
		out.JA4Block = o.JA4Block
	}
	return out
}

func minLimit(a, b int) int {
	switch {
	case a == 0:
		return b
	case b == 0:
		return a
	}
	return min(a, b)
}

func stricterAction(a, b Action) Action {
	if a.Blocks() || b.Blocks() {
		return ActionBlock
	}
	return orAction(a, b)
}

func (l Limits) stricter(o Limits) Limits {
	out := l.combine(o, minLimit, stricterAction)
	out.JA4Block = slices.Clone(l.JA4Block)
	for _, p := range o.JA4Block {
		if !slices.Contains(out.JA4Block, p) {
			out.JA4Block = append(out.JA4Block, p)
		}
	}
	return out
}

func (l Limits) equal(o Limits) bool {
	return l.GraphQL == o.GraphQL && l.Smuggling == o.Smuggling && l.WebSocket == o.WebSocket && slices.Equal(l.JA4Block, o.JA4Block)
}
