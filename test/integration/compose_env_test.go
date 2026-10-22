//go:build integration

package integration

import (
	"slices"
	"strings"
	"testing"
)

func TestComposeEnvDropsDecisionWafVariables(t *testing.T) {
	t.Setenv("DECISION_WAF_INSPECTION_MODE", "standard")
	t.Setenv("IT_UNRELATED", "kept")
	env := composeEnv(map[string]string{"DECISION_WAF_DEEP_OVERSIZE": "block"})
	for _, kv := range env {
		if strings.HasPrefix(kv, "DECISION_WAF_") && kv != "DECISION_WAF_DEEP_OVERSIZE=block" {
			t.Errorf("compose env leaks %q", kv)
		}
	}
	if !slices.Contains(env, "DECISION_WAF_DEEP_OVERSIZE=block") || !slices.Contains(env, "IT_UNRELATED=kept") {
		t.Errorf("compose env = %q, want the override and unrelated variables", env)
	}
}

func TestComposeEnvDropsEnvoyLiteConfig(t *testing.T) {
	t.Setenv("ENVOY_LITE_CONFIG", "/tmp/patched-lite.yaml")
	for _, kv := range composeEnv(nil) {
		if strings.HasPrefix(kv, "ENVOY_LITE_CONFIG=") {
			t.Errorf("compose env leaks %q", kv)
		}
	}
	var got []string
	for _, kv := range composeEnv(map[string]string{"ENVOY_LITE_CONFIG": "/tmp/explicit.yaml"}) {
		if strings.HasPrefix(kv, "ENVOY_LITE_CONFIG=") {
			got = append(got, kv)
		}
	}
	if !slices.Equal(got, []string{"ENVOY_LITE_CONFIG=/tmp/explicit.yaml"}) {
		t.Errorf("compose env has %q, want only the explicit ENVOY_LITE_CONFIG", got)
	}
}

func TestProjectNameIsPerEnv(t *testing.T) {
	if got := projectName("nginx", nil); got != "decision-waf-it-nginx" {
		t.Errorf("projectName(nginx, nil) = %q", got)
	}
	a := projectName("envoy-deep", map[string]string{"DECISION_WAF_DEEP_OVERSIZE": "block", "DECISION_WAF_DEEP_MAX_MESSAGES": "3"})
	b := projectName("envoy-deep", map[string]string{"DECISION_WAF_DEEP_MAX_MESSAGES": "3", "DECISION_WAF_DEEP_OVERSIZE": "block"})
	c := projectName("envoy-deep", map[string]string{"DECISION_WAF_DEEP_OVERSIZE": "allow"})
	if a != b || a == c || !strings.HasPrefix(a, "decision-waf-it-envoy-deep-") || len(a) != len("decision-waf-it-envoy-deep-")+6 {
		t.Errorf("project names a=%q b=%q c=%q, want a == b != c with a 6-character suffix", a, b, c)
	}
}
