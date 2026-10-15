package policy

import (
	"os"
	"slices"
	"strings"
	"testing"
)

func TestExamplePolicyParses(t *testing.T) {
	p, err := Load("../../examples/policy.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Categories) == 0 || len(p.Routes) == 0 || len(p.Redact.JSONFields) == 0 {
		t.Errorf("example policy should demonstrate categories, routes, and redaction: %+v", p)
	}
}

func TestExamplePolicyStartsFromTheDefaults(t *testing.T) {
	p, err := Load("../../examples/policy.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(p.Categories, DefaultCategories()) {
		t.Errorf("examples/policy.yaml categories differ from DefaultCategories():\n got %+v\nwant %+v", p.Categories, DefaultCategories())
	}
	for _, h := range DefaultRedact().Headers {
		if !slices.Contains(p.Redact.Headers, h) {
			t.Errorf("examples/policy.yaml redact.headers drops the built-in %q", h)
		}
	}
}

func TestExamplePolicyLimitsUncommented(t *testing.T) {
	data, err := os.ReadFile("../../examples/policy.yaml")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(data), "\n")
	uncommented := 0
	for i := 0; i < len(lines); i++ {
		switch {
		case lines[i] == "# limits:":
			for ; i < len(lines) && strings.HasPrefix(lines[i], "# "); i++ {
				lines[i] = strings.TrimPrefix(lines[i], "# ")
				uncommented++
			}
		case strings.TrimSpace(lines[i]) == "# - match: { path_prefix: /internal/graphql }":
			indent := lines[i][:strings.Index(lines[i], "#")]
			lines[i] = indent + strings.TrimPrefix(lines[i][len(indent):], "# ")
			for i++; i < len(lines) && strings.HasPrefix(lines[i], indent+"#   "); i++ {
				lines[i] = indent + strings.TrimPrefix(lines[i][len(indent):], "# ")
				uncommented++
			}
		}
	}
	if uncommented < 15 {
		t.Fatalf("found only %d commented example lines", uncommented)
	}
	p, err := Parse([]byte(strings.Join(lines, "\n")))
	if err != nil {
		t.Fatalf("uncommented limits example does not parse: %v", err)
	}
	if p.Limits.GraphQL.MaxDepth != 12 || !p.Limits.Smuggling.Blocks() {
		t.Errorf("top-level limits not set: %+v", p.Limits)
	}
	found := false
	for _, r := range p.Routes {
		found = found || r.Limits.GraphQL.MaxDepth == 30
	}
	if !found {
		t.Errorf("no route with the example's max_depth 30: %+v", p.Routes)
	}
}
