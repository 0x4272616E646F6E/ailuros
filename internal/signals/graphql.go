package signals

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/0x4272616E646F6E/decision-waf/internal/inspect"
	"github.com/0x4272616E646F6E/decision-waf/internal/policy"
)

type GraphQL struct {
	OpTypes       []string
	Operations    int
	Batch         int
	Depth         int
	Fields        int
	Aliases       int
	Fragments     int
	Introspection bool
	OperationName string
	Truncated     bool
	FragmentCycle bool
}

const cycleDepth = policy.MaxLimit

func (g *GraphQL) addOp(op string) {
	g.Operations++
	if !slices.Contains(g.OpTypes, op) {
		g.OpTypes = append(g.OpTypes, op)
	}
}

func (g *GraphQL) merge(o GraphQL) {
	for _, op := range o.OpTypes {
		if !slices.Contains(g.OpTypes, op) {
			g.OpTypes = append(g.OpTypes, op)
		}
	}
	g.Operations = max(g.Operations, o.Operations)
	g.Depth = max(g.Depth, o.Depth)
	g.Fields += o.Fields
	g.Aliases += o.Aliases
	g.Fragments += o.Fragments
	g.Introspection = g.Introspection || o.Introspection
	g.FragmentCycle = g.FragmentCycle || o.FragmentCycle
	if g.OperationName == "" {
		g.OperationName = o.OperationName
	}
}

type readings []string

func measure(rs readings) (g GraphQL, ok bool) {
	for _, r := range rs {
		one, isDoc := parseDocument(r)
		if !isDoc {
			continue
		}
		if !ok {
			g, ok = one, true
			continue
		}
		g.widen(one)
	}
	return g, ok
}

func (g *GraphQL) widen(o GraphQL) {
	for _, op := range o.OpTypes {
		if !slices.Contains(g.OpTypes, op) {
			g.OpTypes = append(g.OpTypes, op)
		}
	}
	g.Operations = max(g.Operations, o.Operations)
	g.Depth = max(g.Depth, o.Depth)
	g.Fields = max(g.Fields, o.Fields)
	g.Aliases = max(g.Aliases, o.Aliases)
	g.Fragments = max(g.Fragments, o.Fragments)
	g.Introspection = g.Introspection || o.Introspection
	g.FragmentCycle = g.FragmentCycle || o.FragmentCycle
	if g.OperationName == "" {
		g.OperationName = o.OperationName
	}
}

func (g *GraphQL) line() string {
	parts := []string{"op=" + strings.Join(g.OpTypes, ","), fmt.Sprintf("operations=%d", g.Operations)}
	if g.Batch > 0 {
		parts = append(parts, fmt.Sprintf("batch=%d", g.Batch))
	}
	parts = append(parts, fmt.Sprintf("depth=%d fields=%d aliases=%d", g.Depth, g.Fields, g.Aliases))
	if g.Fragments > 0 {
		parts = append(parts, fmt.Sprintf("fragments=%d", g.Fragments))
	}
	parts = append(parts, "introspection="+map[bool]string{true: "yes", false: "no"}[g.Introspection])
	if g.OperationName != "" {
		parts = append(parts, "name="+g.OperationName)
	}
	if g.Truncated {
		parts = append(parts, "truncated")
	}
	if g.FragmentCycle {
		parts = append(parts, "fragment_cycle")
	}
	return strings.Join(parts, " ")
}

var graphQLName = regexp.MustCompile(`^[_A-Za-z][_0-9A-Za-z]{0,63}$`)

func graphQLOf(r *inspect.Request) *GraphQL {
	var bodyDocs []readings
	var name string
	batch := 0
	switch mt := r.MediaType(); {
	case len(r.Body) == 0:
	case mt == "application/graphql":
		bodyDocs = []readings{{string(r.Body)}}
	case mt == "application/json" || strings.HasSuffix(mt, "+json"):
		bodyDocs, name, batch = jsonDocuments(r.Body)
	}
	var urlDocs []readings
	if r.Query != "" {
		var urlName string
		urlDocs, urlName = queryParams(r.Query)
		if name == "" {
			name = urlName
		}
	}
	var g *GraphQL
	fromBody := false
	for i, d := range append(bodyDocs, urlDocs...) {
		one, ok := measure(d)
		if !ok {
			continue
		}
		if g == nil {
			g = &GraphQL{}
		}
		g.merge(one)
		fromBody = fromBody || i < len(bodyDocs)
	}
	if g == nil {
		return nil
	}
	g.Batch = batch
	if name != "" {
		g.OperationName = name
	}
	if !graphQLName.MatchString(g.OperationName) {
		g.OperationName = ""
	}
	g.Truncated = fromBody && r.BodyTruncated
	return g
}
