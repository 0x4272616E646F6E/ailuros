package signals

import "slices"

func parseDocument(doc string) (g GraphQL, ok bool) {
	l := &lexer{s: doc}
	t := l.next()
	switch {
	case t.kind == tokPunct && t.text == "{":
	case t.kind == tokName && slices.Contains([]string{"query", "mutation", "subscription", "fragment"}, t.text):
	default:
		return GraphQL{}, false
	}
	var (
		depth, parens int
		pendingOp     string
		nameNext      bool
		inFragment    bool
		skip          int
		onOK          bool
		prevField     bool
		fragNameNext  bool
		cur           *fragmentShape
		top           fragmentShape
		frags         = map[string]*fragmentShape{}
	)
	for ; t.kind != tokEOF; t = l.next() {
		wasField := prevField
		prevField = false
		if t.kind == tokPunct && t.text != "@" && t.text != "..." {
			skip, onOK, fragNameNext = 0, false, false
		}
		switch {
		case t.kind == tokPunct && t.text == "(":
			parens++
		case t.kind == tokPunct && t.text == ")":
			parens = max(parens-1, 0)
		case parens > 0:
		case t.kind == tokPunct && t.text == "{":
			if depth == 0 {
				switch {
				case pendingOp != "":
					g.addOp(pendingOp)
				case !inFragment:
					g.addOp("query")
				}
				pendingOp, nameNext = "", false
				if !inFragment {
					cur = &top
				} else if cur == nil {
					cur = &fragmentShape{}
				}
			}
			depth++
			g.Depth = max(g.Depth, depth)
			if cur != nil {
				cur.depth = max(cur.depth, depth)
			}
		case t.kind == tokPunct && t.text == "}":
			if depth = max(depth-1, 0); depth == 0 {
				inFragment, cur = false, nil
			}
		case t.kind == tokPunct && t.text == "...":
			skip, onOK = 1, true
		case t.kind == tokPunct && t.text == "@":
			skip, onOK = 1, false
		case t.kind == tokPunct && t.text == ":" && wasField:
			g.Aliases++
			g.Fields--
			if cur != nil {
				cur.aliases++
				cur.fields--
			}
		case t.kind != tokName:
		case skip > 0:
			switch {
			case onOK && t.text == "on":
				skip = 1
			case onOK:
				if cur != nil {
					cur.spreads = append(cur.spreads, spread{depth, t.text})
				}
				skip--
			case fragNameNext:
				if frags[t.text] == nil {
					frags[t.text] = &fragmentShape{}
				}
				cur = frags[t.text]
				skip--
			default:
				skip--
			}
			onOK, fragNameNext = false, false
		case depth == 0:
			switch t.text {
			case "query", "mutation", "subscription":
				pendingOp, nameNext = t.text, true
			case "fragment":
				g.Fragments++
				inFragment, skip, onOK, fragNameNext, cur = true, 1, false, true, nil
			case "on":
				if inFragment {
					skip = 1
				}
			default:
				if nameNext && g.OperationName == "" {
					g.OperationName = t.text
				}
				nameNext = false
			}
		default:
			g.Fields++
			if cur != nil {
				cur.fields++
			}
			prevField = true
			if t.text == "__schema" || t.text == "__type" {
				g.Introspection = true
			}
		}
	}
	expandSpreads(&g, &top, frags)
	return g, g.Operations > 0 || g.Fragments > 0
}

type spread struct {
	depth int
	name  string
}

type fragmentShape struct {
	depth   int
	fields  int
	aliases int
	spreads []spread
}

type extent struct{ depth, fields, aliases int }

func satAdd(a, b int) int { return min(a+b, cycleDepth) }

func expandSpreads(g *GraphQL, top *fragmentShape, frags map[string]*fragmentShape) {
	const (
		visiting = iota + 1
		done
	)
	state := map[string]int{}
	memo := map[string]extent{}
	var expand func(f *fragmentShape) extent
	reach := func(name string) extent {
		f := frags[name]
		if f == nil {
			return extent{}
		}
		switch state[name] {
		case visiting:
			g.FragmentCycle = true
			return extent{cycleDepth, cycleDepth, cycleDepth}
		case done:
			return memo[name]
		}
		state[name] = visiting
		memo[name] = expand(f)
		state[name] = done
		return memo[name]
	}
	expand = func(f *fragmentShape) extent {
		x := extent{f.depth, max(f.fields, 0), max(f.aliases, 0)}
		for _, s := range f.spreads {
			e := reach(s.name)
			if e.depth > 0 {
				x.depth = min(max(x.depth, s.depth-1+e.depth), cycleDepth)
			}
			x.fields = satAdd(x.fields, e.fields)
			x.aliases = satAdd(x.aliases, e.aliases)
		}
		return x
	}
	x := expand(top)
	g.Depth = max(g.Depth, x.depth)
	g.Fields = max(g.Fields, x.fields)
	g.Aliases = max(g.Aliases, x.aliases)
	for name := range frags {
		g.Depth = max(g.Depth, reach(name).depth)
	}
	if g.FragmentCycle {
		g.Depth, g.Fields, g.Aliases = cycleDepth, cycleDepth, cycleDepth
	}
}
