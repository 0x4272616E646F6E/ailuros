package policy

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/0x4272616E646F6E/ailuros/internal/inspect"
)

func TestParseEmptyUsesDefaults(t *testing.T) {
	p, err := Parse(nil)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(p, Default()) {
		t.Errorf("Parse(nil) = %+v, want Default()", p)
	}
}

func TestParseFull(t *testing.T) {
	p, err := Parse([]byte(`
categories:
  - name: sqli
    description: SQL injection
  - name: scanner
routes:
  - match: { path_prefix: /admin }
    failure_mode: closed
  - match: { host: api.example.com, grpc_service: payments.v1.Payments }
    threshold: 0.5
redact:
  headers: [authorization]
  json_fields: [password]
`))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Categories) != 2 || p.Categories[0].Name != "sqli" || p.Categories[0].Description != "SQL injection" {
		t.Errorf("categories = %+v", p.Categories)
	}
	if p.Categories[1] != (Category{Name: "scanner"}) {
		t.Errorf("categories[1] = %+v", p.Categories[1])
	}
	if p.Routes[0].Match.PathPrefix != "/admin" || p.Routes[0].FailureMode != FailClosed {
		t.Errorf("routes[0] = %+v", p.Routes[0])
	}
	r1 := p.Routes[1]
	if r1.Match.Host != "api.example.com" || r1.Match.GRPCService != "payments.v1.Payments" || r1.FailureMode != "" || *r1.Threshold != 0.5 {
		t.Errorf("routes[1] = %+v", r1)
	}
	if !reflect.DeepEqual(p.Redact, Redact{Headers: []string{"authorization"}, JSONFields: []string{"password"}}) {
		t.Errorf("redact = %+v", p.Redact)
	}
}

func TestParseRejects(t *testing.T) {
	cases := map[string]string{
		"unknown key":         "categoriez: []",
		"empty categories":    "categories: []",
		"benign redefined":    "categories: [{name: benign}]",
		"bad name":            "categories: [{name: SQLi}]",
		"duplicate":           "categories: [{name: sqli}, {name: sqli}]",
		"category threshold":  "categories: [{name: sqli, threshold: 0.6}]",
		"threshold zero":      "routes: [{match: {path_prefix: /}, threshold: 0}]",
		"threshold above one": "routes: [{match: {path_prefix: /}, threshold: 1.5}]",
		"empty match":         "routes: [{failure_mode: closed}]",
		"host only a dot":     "routes: [{match: {host: .}, failure_mode: closed}]",
		"host only a port":    `routes: [{match: {host: ":8443"}, failure_mode: closed}]`,
		"bad failure mode":    "routes: [{match: {path_prefix: /}, failure_mode: maybe}]",
		"bad yaml":            "categories: [",
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			if p, err := Parse([]byte(doc)); err == nil {
				t.Errorf("Parse succeeded with %+v, want error", p)
			}
		})
	}
}

func TestParseRejectsCategoryThreshold(t *testing.T) {
	_, err := Parse([]byte("categories: [{name: scanner, threshold: 0.6}]"))
	if err == nil || !strings.Contains(err.Error(), "threshold") {
		t.Errorf("err = %v, want an unknown-key error naming threshold", err)
	}
}

func TestParseRejectsMatchEmptyAfterNormalization(t *testing.T) {
	_, err := Parse([]byte("routes: [{match: {host: .}, failure_mode: closed}]"))
	if err == nil || !strings.Contains(err.Error(), "empty after normalization") {
		t.Errorf("err = %v, want routes[0] empty-after-normalization error", err)
	}
}

func TestParseRejectsAnyMatchFieldEmptyAfterNormalization(t *testing.T) {
	for _, doc := range []string{
		"routes: [{match: {host: ., path_prefix: /admin}, failure_mode: closed}]",
		"routes: [{match: {host: ':8443', grpc_service: admin.v1.Admin}, failure_mode: closed}]",
	} {
		_, err := Parse([]byte(doc))
		if err == nil || !strings.Contains(err.Error(), "routes[0]") || !strings.Contains(err.Error(), "host") || !strings.Contains(err.Error(), "empty after normalization") {
			t.Errorf("%s: err = %v, want routes[0] host empty-after-normalization error", doc, err)
		}
	}
}

func TestParseReportsAllErrors(t *testing.T) {
	_, err := Parse([]byte("categories: [{name: benign}, {name: Bad}]"))
	if err == nil || !strings.Contains(err.Error(), "built in") || !strings.Contains(err.Error(), "must match") {
		t.Errorf("err = %v, want both problems reported", err)
	}
}

func TestLoad(t *testing.T) {
	p, err := Load("")
	if err != nil || !reflect.DeepEqual(p, Default()) {
		t.Errorf("Load(\"\") = %+v, %v; want Default()", p, err)
	}
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte("categories: [{name: rce}]"), 0o644); err != nil {
		t.Fatal(err)
	}
	if p, err := Load(path); err != nil || p.Categories[0].Name != "rce" {
		t.Errorf("Load(file) = %+v, %v", p, err)
	}
	if _, err := Load(filepath.Join(t.TempDir(), "missing.yaml")); err == nil {
		t.Error("Load(missing) succeeded, want error")
	}
}

func TestParseFailureMode(t *testing.T) {
	if m, err := ParseFailureMode("closed"); err != nil || m != FailClosed {
		t.Errorf("ParseFailureMode(closed) = %q, %v", m, err)
	}
	if _, err := ParseFailureMode("sometimes"); err == nil {
		t.Error("ParseFailureMode(sometimes) succeeded, want error")
	}
}

func TestParseNormalizesMatchFields(t *testing.T) {
	cases := []struct {
		name, match string
		hosts       []string
		paths       []string
		wantHost    string
		wantPrefix  string
	}{
		{"uppercase host with trailing dot", "{ host: API.Example.com. }", []string{"api.example.com"}, []string{"/"}, "api.example.com", ""},
		{"host with port", "{ host: \"api.example.com:8443\" }", []string{"api.example.com"}, []string{"/"}, "api.example.com", ""},
		{"trailing slash prefix", "{ path_prefix: /admin/ }", []string{"x"}, []string{"/admin", "/admin/x"}, "", "/admin"},
		{"encoded prefix", "{ path_prefix: /%61dmin }", []string{"x"}, []string{"/admin"}, "", "/admin"},
		{"root prefix kept", "{ path_prefix: / }", []string{"x"}, []string{"/", "/a"}, "", "/"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p, err := Parse([]byte("routes:\n  - match: " + c.match + "\n    failure_mode: closed\n"))
			if err != nil {
				t.Fatal(err)
			}
			m := p.Routes[0].Match
			if m.Host != c.wantHost || m.PathPrefix != c.wantPrefix {
				t.Errorf("Match = %+v, want host %q prefix %q", m, c.wantHost, c.wantPrefix)
			}
			for _, h := range c.hosts {
				for _, path := range c.paths {
					if got := p.Resolve(&inspect.Request{Host: h, Path: path}, defaults).Route; got != "0" {
						t.Errorf("host=%q path=%q: Route = %q, want 0", h, path, got)
					}
				}
			}
		})
	}
}

func TestParseRejectsMalformedValues(t *testing.T) {
	for _, c := range []struct{ name, doc, want string }{
		{"second document", "routes: []\n---\nroutes: [{match: {path_prefix: /admin}, failure_mode: closed}]\n", "more than one YAML document"},
		{"host with scheme", "routes: [{match: {host: https://api.example.com}}]\n", "must be a host name"},
		{"host wildcard", "routes: [{match: {host: '*.example.com'}}]\n", "must be a host name"},
		{"service with method", "routes: [{match: {grpc_service: pkg.Svc/Run}}]\n", "without a method"},
		{"empty header", "redact: {headers: ['']}\n", "is not a header name"},
		{"header with colon", "redact: {headers: ['x-api-key:']}\n", "is not a header name"},
		{"empty field", "redact: {json_fields: [' ']}\n", "must not be empty"},
	} {
		if _, err := Parse([]byte(c.doc)); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want %q", c.name, err, c.want)
		}
	}
	for _, ok := range []string{
		"routes: [{match: {host: 'api.example.com:8443'}}, {match: {host: '[::1]'}}, {match: {grpc_service: Payments}}]\n",
		"---\nroutes: [{match: {path_prefix: /admin}}]\n",
		"routes: [{match: {path_prefix: /admin}}]\n---\n",
		"routes: [{match: {host: '::1'}}, {match: {host: my_service.internal}}, {match: {host: bücher.example}}, {match: {path_prefix: admin}}]\n",
	} {
		if _, err := Parse([]byte(ok)); err != nil {
			t.Errorf("%q rejected: %v", ok, err)
		}
	}
}

func TestParseLimitsErrors(t *testing.T) {
	cases := map[string]string{
		"limits:\n  graphql: { max_depth: 0 }\n":                           "limits.graphql.max_depth: must be at least 1",
		"limits:\n  graphql: { max_fields: -3 }\n":                         "limits.graphql.max_fields: must be at least 1",
		"limits:\n  graphql: { max_fields: 1048576 }\n":                    "limits.graphql.max_fields: must be below 1048576",
		"limits:\n  graphql: { max_batch: 5000000 }\n":                     "limits.graphql.max_batch: must be below 1048576",
		"limits:\n  graphql: { max_depth: 1.5 }\n":                         "limits.graphql.max_depth: must be an integer",
		"limits:\n  graphql: { max_fields: 0.5 }\n":                        "limits.graphql.max_fields: must be an integer",
		"limits:\n  graphql: { introspection: deny }\n":                    `limits.graphql.introspection: "deny" is not allow or block`,
		"limits:\n  smuggling: yes\n":                                      `limits.smuggling: "yes" is not allow or block`,
		"limits:\n  websocket: { cross_origin: maybe }\n":                  `limits.websocket.cross_origin: "maybe" is not allow or block`,
		"limits:\n  ja4: { block: [\"\"] }\n":                              `limits.ja4.block[0]: "" is not a JA4 fingerprint or prefix`,
		"limits:\n  ja4: { block: [\"T13*x\"] }\n":                         `limits.ja4.block[0]: "T13*x" is not a JA4 fingerprint or prefix`,
		"limits:\n  graphql: { depth: 3 }\n":                               "field depth not found",
		"routes:\n  - match: { host: a }\n    limits: { smuggling: no }\n": `routes[0].limits.smuggling: "no" is not allow or block`,
	}
	for in, want := range cases {
		if _, err := Parse([]byte(in)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: err = %v, want it to contain %q", in, err, want)
		}
	}
}

func TestParseLimits(t *testing.T) {
	p, err := Parse([]byte(`
limits:
  graphql: { max_depth: 12, max_aliases: 50, max_fields: 500, max_operations: 1, max_batch: 10, introspection: block }
  smuggling: block
  websocket: { cross_origin: block, bad_version: allow }
  ja4: { block: ["t13d1516h2_8daaf6152771_b186095e22b6", "t12i*"] }
`))
	if err != nil {
		t.Fatal(err)
	}
	want := Limits{
		GraphQL:   GraphQLLimits{MaxDepth: 12, MaxAliases: 50, MaxFields: 500, MaxOperations: 1, MaxBatch: 10, Introspection: ActionBlock},
		Smuggling: ActionBlock,
		WebSocket: WebSocketLimits{CrossOrigin: ActionBlock, BadVersion: ActionAllow},
		JA4Block:  []string{"t13d1516h2_8daaf6152771_b186095e22b6", "t12i*"},
	}
	if !p.Limits.equal(want) {
		t.Errorf("limits = %+v", p.Limits)
	}
}

func TestEmptyJA4Inherits(t *testing.T) {
	p, err := Parse([]byte(`
limits:
  ja4: { block: ["t12i*"] }
routes:
  - match: { path_prefix: /a }
    limits: { ja4: {} }
  - match: { path_prefix: /b }
    limits: { ja4: { block: [] } }
`))
	if err != nil {
		t.Fatal(err)
	}
	a := p.Resolve(&inspect.Request{Path: "/a"}, defaults)
	b := p.Resolve(&inspect.Request{Path: "/b"}, defaults)
	if len(a.Limits.JA4Block) != 1 {
		t.Errorf("ja4: {} cleared the list: %v", a.Limits.JA4Block)
	}
	if len(b.Limits.JA4Block) != 0 {
		t.Errorf("block: [] did not clear: %v", b.Limits.JA4Block)
	}
}
