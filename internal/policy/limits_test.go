package policy

import (
	"reflect"
	"slices"
	"testing"

	"github.com/0x4272616E646F6E/decision-waf/internal/inspect"
)

func TestJA4Blocked(t *testing.T) {
	l := Limits{JA4Block: []string{"t13d1516h2_8daaf6152771_b186095e22b6", "t12i*"}}
	for fp, want := range map[string]bool{
		"t13d1516h2_8daaf6152771_b186095e22b6": true,
		"t13d1516h2_8daaf6152771_b186095e22b7": false,
		"t12i0607_aaa_bbb":                     true,
		"t13i0607_aaa_bbb":                     false,
		"":                                     false,
	} {
		if got := l.JA4Blocked(fp); got != want {
			t.Errorf("%q: %v, want %v", fp, got, want)
		}
	}
}

func TestLimitsMerge(t *testing.T) {
	global := Limits{GraphQL: GraphQLLimits{MaxDepth: 12, Introspection: ActionBlock}, Smuggling: ActionBlock}
	route := Limits{GraphQL: GraphQLLimits{MaxDepth: 30, Introspection: ActionAllow}}
	over := global.overriddenBy(route)
	if over.GraphQL.MaxDepth != 30 || over.GraphQL.Introspection != ActionAllow || over.Smuggling != ActionBlock {
		t.Errorf("override = %+v", over)
	}
	s := over.stricter(global)
	if s.GraphQL.MaxDepth != 12 || s.GraphQL.Introspection != ActionBlock {
		t.Errorf("stricter = %+v", s)
	}
	if s := (Limits{GraphQL: GraphQLLimits{MaxFields: 5}}).stricter(Limits{}); s.GraphQL.MaxFields != 5 {
		t.Errorf("an unset limit loosened a set one: %+v", s)
	}
	if s := (Limits{JA4Block: []string{"a"}}).stricter(Limits{JA4Block: []string{"b", "a"}}); len(s.JA4Block) != 2 {
		t.Errorf("JA4 union = %v", s.JA4Block)
	}
}

func TestRouteLoosensLimit(t *testing.T) {
	p, err := Parse([]byte(`
limits:
  graphql: { introspection: block, max_depth: 12 }
routes:
  - match: { path_prefix: /internal/graphql }
    limits:
      graphql: { introspection: allow, max_depth: 30 }
`))
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/internal/graphql", "/internal/graphql/", "/internal/graphql/v1", "/internal//graphql", "/internal/./graphql"} {
		res := p.Resolve(&inspect.Request{Path: path}, defaults)
		if res.Limits.GraphQL.Introspection != ActionAllow || res.Limits.GraphQL.MaxDepth != 30 {
			t.Errorf("%s: limits %+v, want the route's", path, res.Limits.GraphQL)
		}
	}
	for _, path := range []string{"/graphql", "/INTERNAL/graphql", `/internal\graphql`} {
		if res := p.Resolve(&inspect.Request{Path: path}, defaults); res.Limits.GraphQL.Introspection != ActionBlock || res.Limits.GraphQL.MaxDepth != 12 {
			t.Errorf("%s: limits %+v, want the global ones", path, res.Limits.GraphQL)
		}
	}
}

func TestLimitsStricterAcrossReadings(t *testing.T) {
	p, err := Parse([]byte(`
routes:
  - match: { path_prefix: /public }
    threshold: 0.5
  - match: { path_prefix: /api }
    limits: { smuggling: block }
`))
	if err != nil {
		t.Fatal(err)
	}
	res := p.Resolve(&inspect.Request{Path: "/public%2F..%2Fapi"}, defaults)
	if res.Limits.Smuggling != ActionBlock || res.Route != "0+1" || res.Threshold() != 0.5 {
		t.Errorf("route %q limits %+v", res.Route, res.Limits)
	}
}

func TestLimitsMergeHandlesEveryField(t *testing.T) {
	var cases []Limits
	var walk func(index []int, typ reflect.Type)
	walk = func(index []int, typ reflect.Type) {
		for i := range typ.NumField() {
			at := append(slices.Clone(index), i)
			if typ.Field(i).Type.Kind() == reflect.Struct {
				walk(at, typ.Field(i).Type)
				continue
			}
			var l Limits
			f := reflect.ValueOf(&l).Elem().FieldByIndex(at)
			switch {
			case f.Kind() == reflect.Int:
				f.SetInt(7)
			case f.Type() == reflect.TypeFor[Action]():
				f.Set(reflect.ValueOf(ActionBlock))
			case f.Type() == reflect.TypeFor[[]string]():
				f.Set(reflect.ValueOf([]string{"t13*"}))
			default:
				t.Fatalf("Limits field %s: no test value for a %s; extend this test", typ.Field(i).Name, f.Type())
			}
			cases = append(cases, l)
		}
	}
	walk(nil, reflect.TypeFor[Limits]())
	var zero Limits
	for _, o := range cases {
		if zero.equal(o) {
			t.Errorf("equal ignores the field set in %+v", o)
		}
		if got := zero.overriddenBy(o); !got.equal(o) {
			t.Errorf("Limits{}.overriddenBy(%+v) = %+v, want the override", o, got)
		}
		if got := o.overriddenBy(zero); !got.equal(o) {
			t.Errorf("%+v.overriddenBy(Limits{}) = %+v, want it inherited", o, got)
		}
		if got := zero.stricter(o); !got.equal(o) {
			t.Errorf("Limits{}.stricter(%+v) = %+v, want it kept", o, got)
		}
		if got := o.stricter(zero); !got.equal(o) {
			t.Errorf("%+v.stricter(Limits{}) = %+v, want it kept", o, got)
		}
	}
	if len(cases) < 10 {
		t.Errorf("walked %d Limits fields, want at least the 10 there were when this test was written", len(cases))
	}
}
