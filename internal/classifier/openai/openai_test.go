package openai

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/0x4272616E646F6E/decision-waf/internal/classifier"
	"github.com/0x4272616E646F6E/decision-waf/internal/inspect"
	"github.com/0x4272616E646F6E/decision-waf/internal/policy"
)

var (
	cats = []policy.Category{{Name: "injection", Description: "SQL injection"}, {Name: "recon"}}
	req  = &inspect.Request{Method: "GET", Path: "/items", Query: "id=1' OR '1'='1"}
	ctx  = context.Background()
)

func server(t *testing.T, handle func(chatRequest) (int, any)) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" {
			t.Errorf("path = %s, want /v1/chat/completions", r.URL.Path)
		}
		var in chatRequest
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			t.Errorf("decode request: %v", err)
		}
		status, body := handle(in)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func reply(content string, tokens []tokenLogprob) map[string]any {
	choice := map[string]any{"message": map[string]any{"role": "assistant", "content": content}}
	if tokens != nil {
		choice["logprobs"] = map[string]any{"content": tokens}
	}
	return map[string]any{"choices": []any{choice}}
}

func newClient(srv *httptest.Server, caps Capabilities) *Client {
	c := New(srv.URL+"/v1", "llama3.2", "", srv.Client())
	c.caps.Store(&caps)
	return c
}

func TestClassifyBuildsSchemaRequest(t *testing.T) {
	var got chatRequest
	srv := server(t, func(r chatRequest) (int, any) { got = r; return 200, reply(`{"category":"injection"}`, nil) })
	if _, err := newClient(srv, Capabilities{JSONSchema: true, Logprobs: true}).Classify(ctx, req, cats); err != nil {
		t.Fatal(err)
	}
	if got.Model != "llama3.2" || got.Temperature != 0 || !got.Logprobs {
		t.Errorf("request = %+v", got)
	}
	if got.ResponseFormat.Type != "json_schema" || got.ResponseFormat.JSONSchema == nil {
		t.Fatalf("response_format = %+v", got.ResponseFormat)
	}
	enum := got.ResponseFormat.JSONSchema.Schema["properties"].(map[string]any)["category"].(map[string]any)["enum"]
	if !reflect.DeepEqual(enum, []any{"benign", "injection", "recon"}) {
		t.Errorf("enum = %v", enum)
	}
	if len(got.Messages) != 2 || got.Messages[0].Role != "system" || !strings.Contains(got.Messages[0].Content, "- injection: SQL injection") {
		t.Errorf("system message = %+v", got.Messages)
	}
	if got.Messages[1].Role != "user" || got.Messages[1].Content != classifier.Prompt(req) {
		t.Errorf("user message = %+v", got.Messages[1])
	}
}

func TestClassifyJSONObjectFallbackRequest(t *testing.T) {
	var got chatRequest
	srv := server(t, func(r chatRequest) (int, any) { got = r; return 200, reply(`{"category":"benign"}`, nil) })
	if _, err := newClient(srv, Capabilities{}).Classify(ctx, req, cats); err != nil {
		t.Fatal(err)
	}
	if got.ResponseFormat.Type != "json_object" || got.ResponseFormat.JSONSchema != nil || got.Logprobs {
		t.Errorf("request = %+v", got)
	}
}

func TestClassifyConfidenceFromLogprobs(t *testing.T) {
	tokens := []tokenLogprob{
		{Token: `{"`}, {Token: "category"}, {Token: `":"`},
		{Token: "inject", Logprob: math.Log(0.9)}, {Token: "ion", Logprob: math.Log(0.8)}, {Token: `"}`},
	}
	srv := server(t, func(chatRequest) (int, any) { return 200, reply(`{"category":"injection"}`, tokens) })
	v, err := newClient(srv, Capabilities{JSONSchema: true, Logprobs: true}).Classify(ctx, req, cats)
	if err != nil {
		t.Fatal(err)
	}
	if v.Category != "injection" || math.Abs(v.Confidence-0.72) > 1e-9 || math.Abs(v.Probs["injection"]-0.72) > 1e-9 || math.Abs(v.Benign-0.28) > 1e-9 {
		t.Errorf("verdict = %+v, want injection @ 0.72 with benign 0.28", v)
	}
}

func TestClassifyBenignLabel(t *testing.T) {
	tokens := []tokenLogprob{{Token: `{"category":"`}, {Token: "benign", Logprob: math.Log(0.9)}, {Token: `"}`}}
	srv := server(t, func(chatRequest) (int, any) { return 200, reply(`{"category":"benign"}`, tokens) })
	v, err := newClient(srv, Capabilities{JSONSchema: true, Logprobs: true}).Classify(ctx, req, cats)
	if err != nil {
		t.Fatal(err)
	}
	if math.Abs(v.Benign-0.9) > 1e-9 || v.Category != "" || v.Confidence != 0 || math.Abs(v.Probs["benign"]-0.9) > 1e-9 {
		t.Errorf("verdict = %+v, want benign 0.9, no category, confidence 0", v)
	}
}

func TestLabelVerdict(t *testing.T) {
	cases := []struct {
		label              string
		c                  float64
		benign, confidence float64
		category           string
	}{
		{"benign", 0.6, 0.6, 0, ""},
		{"injection", 0.6, 0.4, 0.6, "injection"},
		{"injection", 1, 0, 1, "injection"},
	}
	for _, c := range cases {
		v := labelVerdict(c.label, c.c)
		if math.Abs(v.Benign-c.benign) > 1e-9 || v.Category != c.category || v.Confidence != c.confidence || v.Probs[c.label] != c.c {
			t.Errorf("labelVerdict(%q, %v) = %+v", c.label, c.c, v)
		}
	}
}

func TestClassifyConfidenceWithoutUsableLogprobs(t *testing.T) {
	cases := map[string][]tokenLogprob{
		"none":     nil,
		"mismatch": {{Token: `{"x"}`, Logprob: -3}},
	}
	for name, tokens := range cases {
		t.Run(name, func(t *testing.T) {
			srv := server(t, func(chatRequest) (int, any) { return 200, reply(`{"category":"injection"}`, tokens) })
			v, err := newClient(srv, Capabilities{JSONSchema: true, Logprobs: true}).Classify(ctx, req, cats)
			if err != nil || v.Confidence != 1.0 {
				t.Errorf("verdict = %+v, err = %v; want confidence 1.0", v, err)
			}
		})
	}
}

func TestClassifyRejectsBadOutput(t *testing.T) {
	bodies := map[string]any{
		"not json":      reply("not json", nil),
		"wrong case":    reply(`{"category":"INJECTION"}`, nil),
		"unknown label": reply(`{"category":"xss"}`, nil),
		"missing field": reply(`{}`, nil),
	}
	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			srv := server(t, func(chatRequest) (int, any) { return 200, body })
			_, err := newClient(srv, Capabilities{}).Classify(ctx, req, cats)
			if classifier.ReasonOf(err) != classifier.ReasonBadOutput {
				t.Errorf("ReasonOf = %q (%v), want bad_output", classifier.ReasonOf(err), err)
			}
		})
	}
	srv := server(t, func(chatRequest) (int, any) { return 200, map[string]any{"choices": []any{}} })
	if _, err := newClient(srv, Capabilities{}).Classify(ctx, req, cats); classifier.ReasonOf(err) != classifier.ReasonBadResponse {
		t.Errorf("no choices: ReasonOf = %q (%v), want bad_response", classifier.ReasonOf(err), err)
	}
}

func TestClassifyHTTPErrors(t *testing.T) {
	for status, want := range map[int]classifier.Reason{429: classifier.ReasonRateLimited, 500: classifier.ReasonUpstream5xx} {
		srv := server(t, func(chatRequest) (int, any) { return status, map[string]string{"error": "x"} })
		_, err := newClient(srv, Capabilities{}).Classify(ctx, req, cats)
		if classifier.ReasonOf(err) != want {
			t.Errorf("status %d: ReasonOf = %q, want %q", status, classifier.ReasonOf(err), want)
		}
	}
}

var benignTokens = []tokenLogprob{{Token: `{"category":"`}, {Token: "benign", Logprob: -0.01}, {Token: `"}`}}

func TestProbeFullSupport(t *testing.T) {
	srv := server(t, func(chatRequest) (int, any) { return 200, reply(`{"category":"benign"}`, benignTokens) })
	c := New(srv.URL+"/v1", "m", "", srv.Client())
	caps, err := c.Probe(ctx)
	if err != nil || caps != (Capabilities{JSONSchema: true, Logprobs: true}) || c.Capabilities() != caps {
		t.Errorf("caps = %+v, stored %+v, err = %v", caps, c.Capabilities(), err)
	}
}

func TestProbeFallsBackWhenSchemaRejected(t *testing.T) {
	srv := server(t, func(r chatRequest) (int, any) {
		if r.ResponseFormat.Type == "json_schema" {
			return 400, map[string]string{"error": "response_format json_schema not supported"}
		}
		return 200, reply(`{"category":"benign"}`, benignTokens)
	})
	caps, err := New(srv.URL+"/v1", "m", "", srv.Client()).Probe(ctx)
	if err != nil || caps != (Capabilities{JSONSchema: false, Logprobs: true}) {
		t.Errorf("caps = %+v, err = %v", caps, err)
	}
}

func TestProbeDetectsIgnoredLogprobs(t *testing.T) {
	srv := server(t, func(chatRequest) (int, any) { return 200, reply(`{"category":"benign"}`, nil) })
	caps, err := New(srv.URL+"/v1", "m", "", srv.Client()).Probe(ctx)
	if err != nil || caps != (Capabilities{JSONSchema: true, Logprobs: false}) {
		t.Errorf("caps = %+v, err = %v", caps, err)
	}
}

func TestProbeFailsWhenEverythingRejected(t *testing.T) {
	for _, c := range []struct {
		status   int
		attempts int
	}{{400, 4}, {422, 4}, {401, 1}, {403, 1}, {404, 1}} {
		attempts := 0
		srv := server(t, func(chatRequest) (int, any) { attempts++; return c.status, map[string]string{"error": "no"} })
		_, err := New(srv.URL+"/v1", "m", "", srv.Client()).Probe(ctx)
		if err == nil || classifier.ReasonOf(err) != classifier.ReasonUpstream4xx || attempts != c.attempts {
			t.Errorf("HTTP %d: err = %v, attempts = %d; want upstream_4xx after %d", c.status, err, attempts, c.attempts)
		}
	}
}

func TestProbeKeepsAFormatThatAnswersOutsideTheSchema(t *testing.T) {
	attempts := 0
	srv := server(t, func(chatRequest) (int, any) { attempts++; return 200, reply(`{"category":"needs_review"}`, nil) })
	caps, err := New(srv.URL+"/v1", "m", "", srv.Client()).Probe(ctx)
	if err != nil || !caps.JSONSchema || !caps.SchemaIgnored || attempts != 1 {
		t.Errorf("caps %+v, err %v, attempts %d; want json_schema kept, marked ignored, after 1 attempt", caps, err, attempts)
	}
}

func TestUnmatchedLogprobsAreReported(t *testing.T) {
	calls := 0
	for _, c := range []struct {
		tokens []tokenLogprob
		want   int
	}{
		{[]tokenLogprob{{Token: "something else", Logprob: -0.1}}, 1},
		{nil, 0},
	} {
		calls = 0
		srv := server(t, func(chatRequest) (int, any) { return 200, reply(`{"category":"injection"}`, c.tokens) })
		cl := newClient(srv, Capabilities{Logprobs: true})
		cl.OnUnmatchedLogprobs = func() { calls++ }
		v, err := cl.Classify(ctx, req, cats)
		if err != nil || v.Confidence != 1 || calls != c.want {
			t.Errorf("tokens %v: verdict %+v, err %v, reports %d; want confidence 1 and %d reports", c.tokens, v, err, calls, c.want)
		}
	}
}

func TestHTTP200ErrorBodyReported(t *testing.T) {
	for _, body := range []any{
		map[string]any{"error": "Unexpected endpoint or method. (POST /chat/completions)"},
		map[string]any{"error": map[string]any{"message": "Unexpected endpoint or method. (POST /chat/completions)"}},
	} {
		srv := server(t, func(chatRequest) (int, any) { return 200, body })
		_, err := newClient(srv, Capabilities{}).Classify(ctx, req, cats)
		if classifier.ReasonOf(err) != classifier.ReasonBadResponse || !strings.Contains(err.Error(), "Unexpected endpoint") {
			t.Errorf("body %v: err = %v, want bad_response with the server's message", body, err)
		}
	}
}

func TestProbeInvalidVerdictIsNotSchemaIgnored(t *testing.T) {
	srv := server(t, func(r chatRequest) (int, any) {
		if r.Logprobs {
			return 200, reply(`{"category":"benign"}`, []tokenLogprob{{Token: `{"category":"`}, {Token: "benign", Logprob: 5}, {Token: `"}`}})
		}
		return 200, reply(`{"category":"benign"}`, nil)
	})
	caps, err := New(srv.URL+"/v1", "m", "", srv.Client()).Probe(ctx)
	if err != nil || caps != (Capabilities{JSONSchema: true}) {
		t.Errorf("caps = %+v, err = %v; want json_schema without logprobs, not marked ignored", caps, err)
	}
}
