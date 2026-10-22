package signals

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/0x4272616E646F6E/decision-waf/internal/inspect"
	"github.com/0x4272616E646F6E/decision-waf/internal/policy"
)

func doc(t *testing.T, s string) GraphQL {
	t.Helper()
	g, ok := parseDocument(s)
	if !ok {
		t.Fatalf("%q not recognised as GraphQL", s)
	}
	return g
}

func TestGraphQLShapes(t *testing.T) {
	cases := []struct {
		doc  string
		want GraphQL
	}{
		{`{ a }`, GraphQL{OpTypes: []string{"query"}, Operations: 1, Depth: 1, Fields: 1}},
		{`query Q($id: ID = 1) { user(id: $id) { name friends { name } } }`,
			GraphQL{OpTypes: []string{"query"}, Operations: 1, Depth: 3, Fields: 4, OperationName: "Q"}},
		{`{ a: user { n: name } b: user { name } }`, GraphQL{OpTypes: []string{"query"}, Operations: 1, Depth: 2, Fields: 4, Aliases: 3}},
		{`query A { a } mutation B { b }`, GraphQL{OpTypes: []string{"query", "mutation"}, Operations: 2, Depth: 1, Fields: 2, OperationName: "A"}},
		{`{ ...F ... on User { id } } fragment F on Query @dir { x { y } }`,
			GraphQL{OpTypes: []string{"query"}, Operations: 1, Depth: 2, Fields: 3, Fragments: 1}},
		{`{ __schema { types { name } } }`, GraphQL{OpTypes: []string{"query"}, Operations: 1, Depth: 3, Fields: 3, Introspection: true}},
		{`{ __typename user { __typename } }`, GraphQL{OpTypes: []string{"query"}, Operations: 1, Depth: 2, Fields: 3}},
		{`{ a @include(if: true) { b } }`, GraphQL{OpTypes: []string{"query"}, Operations: 1, Depth: 2, Fields: 2}},
	}
	for _, c := range cases {
		got := doc(t, c.doc)
		if got.line() != c.want.line() {
			t.Errorf("%s\n got %s\nwant %s", c.doc, got.line(), c.want.line())
		}
	}
}

func TestGraphQLNotADocument(t *testing.T) {
	for _, s := range []string{"shoes", "", "   ", "SELECT * FROM t", "querystring", "[1,2]", `"query"`} {
		if _, ok := parseDocument(s); ok {
			t.Errorf("%q recognised as GraphQL", s)
		}
	}
}

func TestGraphQLArgumentsDoNotAddDepth(t *testing.T) {
	g := doc(t, `{ f(where: {a: {b: {c: 1}}}, list: [{x: 1}]) { x } }`)
	if g.Depth != 2 || g.Fields != 2 {
		t.Errorf("depth %d fields %d, want 2 and 2", g.Depth, g.Fields)
	}
}

func TestGraphQLStringsAndComments(t *testing.T) {
	g := doc(t, "{ a(s: \"}{\\\"}\") # } { {\n b(t: \"\"\"} { \\\"\"\" #\"\"\") }")
	if g.Depth != 1 || g.Fields != 2 {
		t.Errorf("depth %d fields %d, want 1 and 2", g.Depth, g.Fields)
	}
	g = doc(t, `{ a(t: """a " b""") { b } }`)
	if g.Depth != 2 || g.Fields != 2 {
		t.Errorf("block string: depth %d fields %d, want 2 and 2", g.Depth, g.Fields)
	}
}

func TestGraphQLTruncatedKeepsDepth(t *testing.T) {
	g := doc(t, `{ a { b { c { d { e`)
	if g.Depth != 5 || g.Fields != 5 {
		t.Errorf("depth %d fields %d, want 5 and 5", g.Depth, g.Fields)
	}
	g = doc(t, `{ a(s: "unterminated`)
	if g.Depth != 1 {
		t.Errorf("depth %d, want 1", g.Depth)
	}
}

func req(method, ct, query, body string, truncated bool) *inspect.Request {
	h := map[string][]string{}
	if ct != "" {
		h["content-type"] = []string{ct}
	}
	return &inspect.Request{Method: method, Path: "/graphql", Query: query, Headers: h, Body: []byte(body), BodyTruncated: truncated}
}

func TestGraphQLFromRequests(t *testing.T) {
	cases := []struct {
		name string
		r    *inspect.Request
		want string
	}{
		{"json", req("POST", "application/json", "", `{"query":"{ a { b } }","operationName":"Op"}`, false),
			"op=query operations=1 depth=2 fields=2 aliases=0 introspection=no name=Op"},
		{"batch", req("POST", "application/json", "", `[{"query":"{ a }"},{"query":"{ b { c } }"}]`, false),
			"op=query operations=1 batch=2 depth=2 fields=3 aliases=0 introspection=no"},
		{"graphql body", req("POST", "application/graphql", "", `{ __type(name: "X") { name } }`, false),
			"op=query operations=1 depth=2 fields=2 aliases=0 introspection=yes"},
		{"get", req("GET", "", "query=%7B+a+%7B+b+%7D+%7D&operationName=G", "", false),
			"op=query operations=1 depth=2 fields=2 aliases=0 introspection=no name=G"},
		{"truncated json", req("POST", "application/json", "", `{"query":"{ a { b { c`, true),
			"op=query operations=1 depth=3 fields=3 aliases=0 introspection=no truncated"},
		{"search api", req("GET", "", "query=shoes", "", false), ""},
		{"post with query param", req("POST", "", "query=%7B+a+%7D", "", false), "op=query operations=1 depth=1 fields=1 aliases=0 introspection=no"},
		{"json without query", req("POST", "application/json", "", `{"q":"{ a }"}`, false), ""},
	}
	for _, c := range cases {
		g := graphQLOf(c.r)
		got := ""
		if g != nil {
			got = g.line()
		}
		if got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

func TestGraphQLJSONNonStringQuery(t *testing.T) {
	for _, body := range []string{`{"query":null}`, `{"query":1e999}`, `{"query":{"a":1}}`, `[1,"x",null]`, `{}`, `[]`, `null`} {
		if g := graphQLOf(req("POST", "application/json", "", body, false)); g != nil {
			t.Errorf("%s: got %s, want no GraphQL", body, g.line())
		}
	}
}

func FuzzParseDocument(f *testing.F) {
	for _, s := range []string{`{ a }`, `query Q { a: b(c: {d: 1}) { ...F } } fragment F on T { e }`, "{ a(s: \"\"\"x", "{{{{", "}}}", `...on`, `a:::`} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		g, _ := parseDocument(s)
		if g.Depth < 0 || g.Fields < 0 || g.Aliases < 0 || g.Operations < 0 || g.Depth > cycleDepth {
			t.Errorf("negative count for %q: %+v", s, g)
		}
		if strings.ContainsAny(g.line(), "\n\r") {
			t.Errorf("line has a line break for %q", s)
		}
	})
}

func TestGraphQLInlineFragmentWithoutTypeCondition(t *testing.T) {
	cases := []struct {
		doc                    string
		depth, fields, aliases int
	}{
		{`{ ...{ a } }`, 2, 1, 0},
		{`{ ... @include(if: $x) { a } }`, 2, 1, 0},
		{`{ ...{ a1: f } ...{ a2: f } }`, 2, 2, 2},
	}
	for _, c := range cases {
		g := doc(t, c.doc)
		if g.Depth != c.depth || g.Fields != c.fields || g.Aliases != c.aliases {
			t.Errorf("%s: depth %d fields %d aliases %d, want %d %d %d", c.doc, g.Depth, g.Fields, g.Aliases, c.depth, c.fields, c.aliases)
		}
	}
}

func TestGraphQLBOMInsideDocument(t *testing.T) {
	g := doc(t, "{ a1\uFEFF: f a2\uFEFF: f }")
	if g.Aliases != 2 || g.Fields != 2 {
		t.Errorf("aliases %d fields %d, want 2 and 2", g.Aliases, g.Fields)
	}
	if g := doc(t, "\uFEFF\uFEFFquery { a { b } }"); g.Depth != 2 || g.Fields != 2 {
		t.Errorf("leading BOMs: depth %d fields %d, want 2 and 2", g.Depth, g.Fields)
	}
}

func TestGraphQLDirectiveNamedOn(t *testing.T) {
	g := doc(t, `{ a @on b c }`)
	if g.Fields != 3 {
		t.Errorf("fields %d, want 3", g.Fields)
	}
}

func TestGraphQLNeedsAnOperation(t *testing.T) {
	for _, s := range []string{"query languages", "subscription box", "query"} {
		if _, ok := parseDocument(s); ok {
			t.Errorf("%q recognised as GraphQL", s)
		}
	}
	if g := doc(t, `{ a { b`); g.Depth != 2 {
		t.Errorf("truncated `{ a { b`: depth %d, want 2", g.Depth)
	}
}

func TestGraphQLGETParsing(t *testing.T) {
	cases := []struct{ name, query, want string }{
		{"semicolon and comment", "query=%7B__schema%7Btypes%7Bname%7D%7D%7D%23;",
			"op=query operations=1 depth=3 fields=3 aliases=0 introspection=yes"},
		{"bad escape", "query=%7Ba%7Bb%7D%7D%23%zz",
			"op=query operations=1 depth=2 fields=2 aliases=0 introspection=no"},
		{"second query value", "query=x&query=%7Ba%7Bb%7Bc%7D%7D%7D",
			"op=query operations=1 depth=3 fields=3 aliases=0 introspection=no"},
		{"all query values", "query=%7Ba%7D&query=%7Bb%7D",
			"op=query operations=1 depth=1 fields=2 aliases=0 introspection=no"},
		{"search words", "query=query+languages", ""},
		{"search words", "query=subscription+box", ""},
	}
	for _, c := range cases {
		got := ""
		if g := graphQLOf(req("GET", "", c.query, "", false)); g != nil {
			got = g.line()
		}
		if got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

func TestGraphQLTruncatedJSON(t *testing.T) {
	cases := []struct{ name, body, want string }{
		{"escaped key", `{"\u0071uery":"{ a { b { c { d`,
			"op=query operations=1 depth=4 fields=4 aliases=0 introspection=no truncated"},
		{"nested query key is data", `{"variables":{"query":"{ x }"},"query":"{ a }"`,
			"op=query operations=1 depth=1 fields=1 aliases=0 introspection=no truncated"},
		{"truncated batch", `[{"query":"{ a }"},{"query":"{ b { c`,
			"op=query operations=1 batch=2 depth=2 fields=3 aliases=0 introspection=no truncated"},
	}
	for _, c := range cases {
		g := graphQLOf(req("POST", "application/json", "", c.body, true))
		got := ""
		if g != nil {
			got = g.line()
		}
		if got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

func TestGraphQLURLQueryOnAnyMethod(t *testing.T) {
	introspect := "query=%7B__schema%7Btypes%7Bname%7D%7D%7D"
	cases := []struct {
		name string
		r    *inspect.Request
		want string
	}{
		{"GET with empty JSON body", req("GET", "application/json", introspect, `{}`, false),
			"op=query operations=1 depth=3 fields=3 aliases=0 introspection=yes"},
		{"POST with JSON body and URL query", req("POST", "application/json", introspect+"&operationName=U", `{"query":"{ a }","operationName":"B"}`, false),
			"op=query operations=1 depth=3 fields=4 aliases=0 introspection=yes name=B"},
		{"POST with graphql body and URL query", req("POST", "application/graphql", introspect, `{ a }`, false),
			"op=query operations=1 depth=3 fields=4 aliases=0 introspection=yes"},
		{"truncated non-GraphQL body, URL query", req("POST", "application/json", introspect, `{"x":"aaaa`, true),
			"op=query operations=1 depth=3 fields=3 aliases=0 introspection=yes"},
		{"truncated body with GraphQL", req("PUT", "application/json", "", `{"query":"{ a { b`, true),
			"op=query operations=1 depth=2 fields=2 aliases=0 introspection=no truncated"},
	}
	for _, c := range cases {
		got := ""
		if g := graphQLOf(c.r); g != nil {
			got = g.line()
		}
		if got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

func TestGraphQLJSONLenient(t *testing.T) {
	cases := []struct{ name, body, want string }{
		{"capitalised key", `{"Query":"{__schema{a}}"}`,
			"op=query operations=1 depth=2 fields=2 aliases=0 introspection=yes"},
		{"capitalised name", `{"query":"{a}","OperationName":"Op"}`,
			"op=query operations=1 depth=1 fields=1 aliases=0 introspection=no name=Op"},
		{"NaN before query", `{"variables":{"x":NaN},"query":"{__schema{a}}"}`,
			"op=query operations=1 depth=2 fields=2 aliases=0 introspection=yes"},
		{"Infinity, spaced colon, upper case", `{"variables":{"x":-Infinity},"QUERY" :	"{__schema{a}}","operationName":"N"}`,
			"op=query operations=1 depth=2 fields=2 aliases=0 introspection=yes name=N"},
		{"escaped key after NaN", `{"v":NaN,"query":"{__schema{a}}"}`,
			"op=query operations=1 depth=2 fields=2 aliases=0 introspection=yes"},
		{"escaped key before NaN", `{"query":"{__schema{a}}","v":NaN}`,
			"op=query operations=1 depth=2 fields=2 aliases=0 introspection=yes"},
		{"NaN in batch", `[{"query":"{a}","variables":{"x":NaN}},{"query":"{__schema{b}}"}]`,
			"op=query operations=1 batch=2 depth=2 fields=3 aliases=0 introspection=yes"},
		{"value string looks like a key", `{"v":NaN,"x":"\"query\":","query":"{a}"}`,
			"op=query operations=1 depth=1 fields=1 aliases=0 introspection=no"},
		{"well-formed nested query is data", `{"variables":{"query":"{ x { y } }"},"query":"{ a }"}`,
			"op=query operations=1 depth=1 fields=1 aliases=0 introspection=no"},
	}
	for _, c := range cases {
		got := ""
		if g := graphQLOf(req("POST", "application/json", "", c.body, false)); g != nil {
			got = g.line()
		}
		if got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

func TestGraphQLJSONLenientTruncated(t *testing.T) {
	g := graphQLOf(req("POST", "application/json", "", `{"v":NaN,"query":"{ a { b { c`, true))
	want := "op=query operations=1 depth=3 fields=3 aliases=0 introspection=no truncated"
	if g == nil || g.line() != want {
		t.Errorf("got %+v, want %s", g, want)
	}
}

func FuzzJSONDocuments(f *testing.F) {
	for _, s := range []string{`{"query":"{a}"}`, `[{"Query":"{a}"},{"v":NaN}]`, `{"v":NaN,"query":"{a`, `{"query" : "x"`, `["`, `"\`} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		docs, _, batch := jsonDocuments([]byte(s))
		if batch < 0 || len(docs) > len(s) {
			t.Errorf("%q: batch %d, %d docs", s, batch, len(docs))
		}
	})
}

func TestGraphQLFragmentDepth(t *testing.T) {
	cases := []struct {
		name, doc     string
		depth, fields int
		cycle         bool
	}{
		{"chain", `{a{...F1}} fragment F1 on T{b{...F2}} fragment F2 on T{c{...F3}} fragment F3 on T{d{...F4}} fragment F4 on T{e{f}}`, 6, 6, false},
		{"defined before use", `fragment F on T{b{c}} query Q{a{x{...F}}}`, 4, 4, false},
		{"spread at top level", `{...F} fragment F on T{a{b}}`, 2, 2, false},
		{"undefined fragment", `{a{b{...Missing}}}`, 3, 2, false},
		{"truncated before definition", `{a{...F}} fragment F on T{b{c{d`, 4, 4, false},
		{"used twice", `{a{...F} b{c{...F}}} fragment F on T{x{...G}} fragment G on T{y{z}}`, 5, 9, false},
		{"diamond", `{...A ...B} fragment A on T{a{...C}} fragment B on T{b{...C}} fragment C on T{c}`, 2, 4, false},
		{"inline fragment unchanged", `{a{... on T{b{c}}}}`, 4, 3, false},
		{"cycle", `{a{...F1}} fragment F1 on T{b{...F2}} fragment F2 on T{c{...F1}}`, cycleDepth, cycleDepth, true},
		{"self spread", `{...F} fragment F on T{a{...F}}`, cycleDepth, cycleDepth, true},
		{"unreachable cycle", `{a} fragment F on T{...F}`, cycleDepth, cycleDepth, true},
	}
	for _, c := range cases {
		g := doc(t, c.doc)
		if g.Depth != c.depth || g.Fields != c.fields || g.FragmentCycle != c.cycle {
			t.Errorf("%s: depth %d fields %d cycle %v, want %d %d %v", c.name, g.Depth, g.Fields, g.FragmentCycle, c.depth, c.fields, c.cycle)
		}
	}
	cg := doc(t, `{...F} fragment F on T{...F}`)
	if line := cg.line(); !strings.Contains(line, "depth=1048576 ") || !strings.HasSuffix(line, " fragment_cycle") {
		t.Errorf("cycle line %q", line)
	}
}

func TestGraphQLFragmentCycleTripsDepthLimit(t *testing.T) {
	g := doc(t, `{a{...F1}} fragment F1 on T{b{...F2}} fragment F2 on T{c{...F1}}`)
	if lim, hit := Check(Signals{GraphQL: &g}, policy.Limits{GraphQL: policy.GraphQLLimits{MaxDepth: 1000000}}); !hit || lim != "graphql_depth" {
		t.Errorf("cycle: got %q %v, want graphql_depth", lim, hit)
	}
}

func TestGraphQLFragmentExpansionIsMemoised(t *testing.T) {
	var b strings.Builder
	b.WriteString("{...F0}")
	for i := range 64 {
		fmt.Fprintf(&b, " fragment F%d on T{a{...F%d} b{...F%d}}", i, i+1, i+1)
	}
	b.WriteString(" fragment F64 on T{z}")
	done := make(chan GraphQL, 1)
	go func() { g, _ := parseDocument(b.String()); done <- g }()
	select {
	case g := <-done:
		if g.Depth != 65 {
			t.Errorf("depth %d, want 65", g.Depth)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("fragment expansion is not memoised")
	}
}

func TestGraphQLOperationsPerDocument(t *testing.T) {
	limits := policy.Limits{GraphQL: policy.GraphQLLimits{MaxOperations: 1, MaxBatch: 10}}
	cases := []struct {
		name, ct, body, want string
	}{
		{"batch of two single-operation documents", "application/json", `[{"query":"{a}"},{"query":"{b}"}]`, ""},
		{"one document with two operations", "application/json", `{"query":"query A {a} query B {b}"}`, "graphql_operations"},
		{"batch with one two-operation document", "application/json", `[{"query":"{a}"},{"query":"query A {a} query B {b}"}]`, "graphql_operations"},
		{"graphql body with two operations", "application/graphql", `query A {a} mutation B {b}`, "graphql_operations"},
	}
	for _, c := range cases {
		g := graphQLOf(req("POST", c.ct, "", c.body, false))
		if g == nil {
			t.Fatalf("%s: no GraphQL", c.name)
		}
		if got, _ := Check(Signals{GraphQL: g}, limits); got != c.want {
			t.Errorf("%s: limit %q, want %q (%s)", c.name, got, c.want, g.line())
		}
	}
}

func TestGraphQLOperationNameIsAName(t *testing.T) {
	long := strings.Repeat("a", 64)
	cases := []struct{ name, r, want string }{
		{"forged pairs", `{"query":"{a}","operationName":"x depth=1 introspection=no"}`, ""},
		{"64 characters", `{"query":"{a}","operationName":"` + long + `"}`, long},
		{"65 characters", `{"query":"{a}","operationName":"` + long + `b"}`, ""},
		{"leading digit", `{"query":"{a}","operationName":"1a"}`, ""},
		{"underscore", `{"query":"{a}","operationName":"_a1"}`, "_a1"},
		{"document name too long", `{"query":"query ` + long + `b {a}"}`, ""},
	}
	for _, c := range cases {
		g := graphQLOf(req("POST", "application/json", "", c.r, false))
		if g == nil {
			t.Fatalf("%s: no GraphQL", c.name)
		}
		line := g.line()
		got := ""
		if _, after, ok := strings.Cut(line, " name="); ok {
			got = after
		}
		if got != c.want || g.OperationName != c.want || strings.Count(line, "depth=") != 1 {
			t.Errorf("%s: line %q, name %q, want %q", c.name, line, g.OperationName, c.want)
		}
	}
	g := graphQLOf(req("GET", "", "query=%7Ba%7D&operationName=x+introspection%3Dno", "", false))
	if g == nil || g.OperationName != "" || strings.Contains(g.line(), "name=") {
		t.Errorf("URL operationName with a space: %+v", g)
	}
}

func TestGraphQLFragmentFanOutCounts(t *testing.T) {
	repeat := func(s string, n int) string { return strings.TrimSpace(strings.Repeat(s+" ", n)) }
	cases := []struct {
		name, doc       string
		fields, aliases int
	}{
		{"spread three times", `{ op ` + repeat("...F", 3) + ` } fragment F on T { x y z }`, 10, 0},
		{"nested fan-out", `{ ` + repeat("...F2", 10) + ` } fragment F2 on T { ` + repeat("...F1", 10) + ` } fragment F1 on T { x y z }`, 300, 0},
		{"aliases in a fragment", `{ ` + repeat("...F", 3) + ` } fragment F on T { a: x b: y z }`, 9, 6},
		{"nested aliases", `{ ` + repeat("...F2", 10) + ` } fragment F2 on T { ` + repeat("...F1", 10) + ` } fragment F1 on T { a: x y }`, 200, 100},
		{"unused fragment still counts", `{ a } fragment F on T { x y }`, 3, 0},
		{"undefined fragment adds nothing", `{ a ...Missing ...Missing }`, 1, 0},
		{"cycle saturates", `{ ...F } fragment F on T { a ...F }`, cycleDepth, cycleDepth},
	}
	for _, c := range cases {
		g := doc(t, c.doc)
		if g.Fields != c.fields || g.Aliases != c.aliases {
			t.Errorf("%s: fields %d aliases %d, want %d and %d", c.name, g.Fields, g.Aliases, c.fields, c.aliases)
		}
	}
}

func TestGraphQLFragmentFanOutSaturates(t *testing.T) {
	var deep strings.Builder
	deep.WriteString("{ ...F0 }")
	for i := range 70 {
		fmt.Fprintf(&deep, " fragment F%d on T { %s }", i, strings.Repeat(fmt.Sprintf("...F%d ", i+1), 10))
	}
	deep.WriteString(" fragment F70 on T { x }")
	cases := []struct {
		name, doc string
		fields    int
	}{
		{"100000 spreads", "{ " + strings.Repeat("...F ", 100000) + "} fragment F on T { x y z }", 300000},
		{"overflowing fan-out", deep.String(), cycleDepth},
	}
	for _, c := range cases {
		start := time.Now()
		g := doc(t, c.doc)
		if el := time.Since(start); el > time.Second {
			t.Errorf("%s: took %v", c.name, el)
		}
		if g.Fields != c.fields {
			t.Errorf("%s: fields %d, want %d", c.name, g.Fields, c.fields)
		}
	}
}

func TestGraphQLFragmentFanOutTripsLimits(t *testing.T) {
	g := doc(t, `{ ...F ...F ...F } fragment F on T { a: x b: y z }`)
	if lim, hit := Check(Signals{GraphQL: &g}, policy.Limits{GraphQL: policy.GraphQLLimits{MaxFields: 8}}); !hit || lim != "graphql_fields" {
		t.Errorf("fields: got %q %v", lim, hit)
	}
	if lim, hit := Check(Signals{GraphQL: &g}, policy.Limits{GraphQL: policy.GraphQLLimits{MaxAliases: 5}}); !hit || lim != "graphql_aliases" {
		t.Errorf("aliases: got %q %v", lim, hit)
	}
}

func TestGraphQLJSONLeadingBOM(t *testing.T) {
	const bomPrefix = "\xEF\xBB\xBF"
	b := graphQLOf(req("POST", "application/json", "", bomPrefix+`[{"query":"{a}"},{"query":"{b}"},{"query":"{c}"}]`, false))
	if b == nil || b.Batch != 3 {
		t.Fatalf("BOM batch: got %+v, want batch 3", b)
	}
	if lim, hit := Check(Signals{GraphQL: b}, policy.Limits{GraphQL: policy.GraphQLLimits{MaxBatch: 2}}); !hit || lim != "graphql_batch" {
		t.Errorf("BOM batch limit: got %q %v, want graphql_batch", lim, hit)
	}
	o := graphQLOf(req("POST", "application/json", "", bomPrefix+`{"query":"{ a { b } }","operationName":"Op"}`, false))
	if o == nil || o.Depth != 2 || o.Fields != 2 || o.OperationName != "Op" {
		t.Errorf("BOM object: got %+v", o)
	}
}

func TestGraphQLJSONUndecodableStringIsMeasured(t *testing.T) {
	cases := []struct {
		name, body string
		truncated  bool
	}{
		{"raw newline", "{\"query\":\"query\n{__schema{a}}\"}", false},
		{"raw tab", "{\"query\":\"{\t__schema{a}}\"}", false},
		{"invalid escape", `{"query":"{__schema{a\x}}"}`, false},
		{"short unicode escape mid-string", `{"query":"{__schema{a\u12}}"}`, false},
		{"short unicode escape before the quote", `{"query":"{__schema{a}}\u12"}`, false},
		{"raw newline, truncated", "{\"query\":\"{\n__schema{a", true},
		{"invalid escape after NaN", `{"v":NaN,"query":"{__schema{a\x}}"}`, false},
	}
	limits := policy.Limits{GraphQL: policy.GraphQLLimits{Introspection: policy.ActionBlock}}
	for _, c := range cases {
		g := graphQLOf(req("POST", "application/json", "", c.body, c.truncated))
		if g == nil || !g.Introspection {
			t.Errorf("%s: got %+v, want an introspection query", c.name, g)
			continue
		}
		if lim, hit := Check(Signals{GraphQL: g}, limits); !hit || lim != "graphql_introspection" {
			t.Errorf("%s: Check got %q %v, want graphql_introspection", c.name, lim, hit)
		}
	}
}

func TestJSONStringFirstReadingLenient(t *testing.T) {
	cases := []struct{ in, want string }{
		{`plain"`, "plain"},
		{`a\nb\"c\\d\/e\u0041"`, "a\nb\"c\\d/eA"},
		{"a\nb\tc\"", "a\nb\tc"},
		{`a\xb"`, "axb"},
		{`a\u12z"`, "az"},
		{`a\u12"`, "a"},
		{"\\ud83d\\ude00\n\"", "\U0001F600\n"},
		{"a\n\\u00", "a\n"},
		{"a\n\\", "a\n"},
		{`a\u0041`, "aA"},
		{"a\n\\u004", "a\n"},
	}
	for _, c := range cases {
		if got := jsonStringReadings([]byte(c.in))[0]; got != c.want {
			t.Errorf("jsonStringReadings(%q)[0] = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestLenientJSONStringAgreesWithEncodingJSON(t *testing.T) {
	for _, s := range []string{`plain`, `a\nb\"c\\d\/e\u0041\b\f\r\t`, `\ud83d\ude00`, `\ud83dx`, `\ude00`, `\ud83d\u0041`, `\u00e9\u20AC`} {
		var want string
		if err := json.Unmarshal([]byte(`"`+s+`"`), &want); err != nil {
			t.Fatalf("%q: %v", s, err)
		}
		if got := lenientJSONString([]byte(s), false); got != want {
			t.Errorf("lenientJSONString(%q) = %q, want %q", s, got, want)
		}
	}
}

func TestGraphQLURLQuerySemicolons(t *testing.T) {
	deep := "%7Ba%7Bb%7Bc%7Bd%7Be%7Bf%7D%7D%7D%7D%7D%7D"
	cases := []struct{ name, query string }{
		{"after a semicolon", "x=1;query=" + deep},
		{"semicolon in a GraphQL string", `query=%7Ba(x:";")%7Bb%7Bc%7Bd%7Be%7Bf%7D%7D%7D%7D%7D%7D`},
		{"semicolon in a GraphQL comment", "query=%7Ba%23;%0A%7Bb%7Bc%7Bd%7Be%7Bf%7D%7D%7D%7D%7D%7D"},
	}
	limits := policy.Limits{GraphQL: policy.GraphQLLimits{MaxDepth: 5}}
	for _, c := range cases {
		g := graphQLOf(req("GET", "", c.query, "", false))
		if g == nil || g.Depth != 6 {
			t.Errorf("%s: got %+v, want depth 6", c.name, g)
			continue
		}
		if lim, hit := Check(Signals{GraphQL: g}, limits); !hit || lim != "graphql_depth" {
			t.Errorf("%s: Check got %q %v, want graphql_depth", c.name, lim, hit)
		}
	}
	g := graphQLOf(req("GET", "", "x=1;operationName=Op;query=%7Ba%7D", "", false))
	if g == nil || g.OperationName != "Op" || g.Fields != 1 {
		t.Errorf("operationName after ';': got %+v", g)
	}
}

func TestGraphQLJSONBadEscapeAtStartIsMeasured(t *testing.T) {
	bs := `\`
	bodies := []string{
		`{"query":"` + bs + `{__schema{a}}"}`,
		`{"query":"` + bs + `q{__schema{a}}"}`,
		`{"query":" ` + bs + `x{__schema{a}}"}`,
		`{"query":"` + bs + `u12{__schema{a}}"}`,
		`{"quer` + bs + `y":"{__schema{a}}"}`,
	}
	limits := policy.Limits{GraphQL: policy.GraphQLLimits{Introspection: policy.ActionBlock}}
	for _, b := range bodies {
		g := graphQLOf(req("POST", "application/json", "", b, false))
		if g == nil || !g.Introspection {
			t.Errorf("%s: got %+v, want an introspection query", b, g)
			continue
		}
		if lim, hit := Check(Signals{GraphQL: g}, limits); !hit || lim != "graphql_introspection" {
			t.Errorf("%s: Check got %q %v, want graphql_introspection", b, lim, hit)
		}
	}
}

func TestJSONStringReadings(t *testing.T) {
	bs := `\`
	cases := []struct {
		in   string
		want readings
	}{
		{`ok"`, readings{"ok"}},
		{"a" + bs + "xb\"", readings{"axb", "ab"}},
		{bs + "{a}\"", readings{"{a}", "a}"}},
		{"q" + bs + "\u00e9z\"", readings{"q\u00e9z", "qz"}},
		{bs + "u12{a}\"", readings{"{a}"}},
		{"raw\ttab" + bs + "u1\"", readings{"raw\ttab"}},
	}
	for _, c := range cases {
		if got := jsonStringReadings([]byte(c.in)); !slices.Equal(got, c.want) {
			t.Errorf("jsonStringReadings(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestMeasureReadingsWidens(t *testing.T) {
	g, ok := measure(readings{"{a b}", "{a{b{c}}}", "not graphql"})
	if !ok || g.Depth != 3 || g.Fields != 3 {
		t.Errorf("got %+v, want depth 3 fields 3", g)
	}
	if _, ok := measure(readings{"shoes"}); ok {
		t.Error("no reading lexes, but measure reported a document")
	}
}

func TestGraphQLURLQueryFirstSubPairIsAReading(t *testing.T) {
	g := graphQLOf(req("GET", "", "query=%7Ba+b+c+%23;%0A:", "", false))
	if g == nil || g.Fields != 3 || g.Aliases != 1 {
		t.Fatalf("got %+v, want fields 3 (the cut reading) and aliases 1 (the whole one)", g)
	}
	if lim, hit := Check(Signals{GraphQL: g}, policy.Limits{GraphQL: policy.GraphQLLimits{MaxFields: 2}}); !hit || lim != "graphql_fields" {
		t.Errorf("Check got %q %v, want graphql_fields", lim, hit)
	}
	if g := graphQLOf(req("GET", "", "query;x=%7Ba%7D", "", false)); g != nil {
		t.Errorf("query;x=: got %+v, want none", g)
	}
	if g := graphQLOf(req("GET", "", "query=%7Ba+b%7D", "", false)); g == nil || g.Fields != 2 {
		t.Errorf("plain: got %+v, want fields 2", g)
	}
}
