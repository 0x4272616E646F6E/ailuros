//go:build integration

package integration

import (
	"cmp"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/0x4272616E646F6E/decision-waf/internal/classifier"
	"github.com/0x4272616E646F6E/decision-waf/internal/config"
	"github.com/0x4272616E646F6E/decision-waf/internal/eval/dataset"
	"github.com/0x4272616E646F6E/decision-waf/internal/policy"
)

const samplePath = "../../eval/datasets/sample.jsonl"

func loadSample(t *testing.T) *dataset.Dataset {
	t.Helper()
	ds, err := dataset.LoadFile(samplePath, classifier.Labels(policy.DefaultCategories()))
	if err != nil {
		t.Fatal(err)
	}
	return ds
}

func TestSampleHasNoStubMarkers(t *testing.T) {
	for _, e := range loadSample(t).Entries {
		text := strings.Join([]string{e.Path, e.Query, fmt.Sprint(e.Headers), e.BodyB64}, " ")
		for _, m := range []string{"attack", "xss-marker", "stub-"} {
			if strings.Contains(text, m) {
				t.Errorf("%s contains stub marker %q", e.ID, m)
			}
		}
	}
}

func TestModelProfile(t *testing.T) {
	modelURL := os.Getenv("AILUROS_IT_MODEL_URL")
	if modelURL == "" {
		t.Skip("set MODEL_URL and MODEL (make test-integration-model) to profile a real model")
	}
	timeout := cmp.Or(os.Getenv("AILUROS_IT_MODEL_TIMEOUT"), "10s")
	d, err := time.ParseDuration(timeout)
	if err != nil {
		t.Fatalf("AILUROS_IT_MODEL_TIMEOUT: %v", err)
	}
	cfg, err := os.ReadFile("../../deploy/envoy/lite.yaml")
	if err != nil {
		t.Fatal(err)
	}
	shipped := "message_timeout: " + (config.DefaultClassifierTimeout + config.ProxyTimeoutMargin).String()
	patched := strings.Replace(string(cfg), shipped, "message_timeout: "+(d+config.ProxyTimeoutMargin).String(), 1)
	if patched == string(cfg) {
		t.Fatalf("lite.yaml has no %q to raise", shipped)
	}
	cfgPath, err := filepath.Abs(filepath.Join(t.TempDir(), "lite.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfgPath, []byte(patched), 0o644); err != nil {
		t.Fatal(err)
	}
	s := up(t, "envoy-lite", map[string]string{
		"ENVOY_LITE_CONFIG":           cfgPath,
		"AILUROS_CLASSIFIER_TIMEOUT":  timeout,
		"AILUROS_CLASSIFIER_BASE_URL": modelURL,
		"AILUROS_CLASSIFIER_MODEL":    os.Getenv("AILUROS_IT_MODEL"),
		"AILUROS_CLASSIFIER_BACKEND":  cmp.Or(os.Getenv("AILUROS_IT_MODEL_BACKEND"), "jev"),
		"AILUROS_CLASSIFIER_API_KEY":  os.Getenv("AILUROS_IT_MODEL_API_KEY"),
	})
	var report strings.Builder
	fmt.Fprintf(&report, "%-14s %-11s %-6s %-9s %-14s %s\n", "label", "outcome", "score", "latency", "category", "request")
	tally := map[string]int{}
	attacks, benign := 0, 0
	for _, e := range loadSample(t).Entries {
		kind := "attack"
		if e.Label == policy.Benign {
			kind = "benign"
			benign++
		} else {
			attacks++
		}
		h := http.Header{}
		for k, vs := range e.Headers {
			for _, v := range vs {
				h.Add(k, v)
			}
		}
		target := e.Path
		if e.Query != "" {
			target += "?" + e.Query
		}
		resp := s.Send(t, "http1", Request{Method: e.Method, Path: target, Header: h})
		id := resp.Header.Get("X-Ailuros-Request-Id")
		if resp.Status == http.StatusOK {
			id = upstreamID(t, echoed(t, resp))
		}
		d := s.Decision(t, id)
		outcome := d.Str("outcome")
		tally[kind+" "+outcome]++
		score := "-"
		if v, ok := d["attack_score"].(float64); ok {
			score = fmt.Sprintf("%.3f", v)
		}
		fmt.Fprintf(&report, "%-14s %-11s %-6s %-9s %-14s %s (%s)\n", e.Label, outcome, score,
			fmt.Sprintf("%.0fms", d["classifier_latency_ms"]), cmp.Or(d.Str("category"), d.Str("reason")), target, e.Note)
	}
	fmt.Fprintf(&report, "attacks blocked %d/%d, benign blocked %d/%d, undecided (failure mode) %d\n",
		tally["attack block"], attacks, tally["benign block"], benign,
		tally["attack fail_open"]+tally["attack fail_closed"]+tally["benign fail_open"]+tally["benign fail_closed"])
	t.Logf("model %s at %s:\n%s", os.Getenv("AILUROS_IT_MODEL"), modelURL, report.String())
}
