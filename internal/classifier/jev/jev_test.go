package jev

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/0x4272616E646F6E/decision-waf/internal/classifier"
	"github.com/0x4272616E646F6E/decision-waf/internal/inspect"
	"github.com/0x4272616E646F6E/decision-waf/internal/policy"
)

var (
	cats = []policy.Category{{Name: "sqli", Description: "SQL injection"}, {Name: "scanner"}}
	req  = &inspect.Request{Method: "GET", Path: "/items", Query: "id=1' OR '1'='1"}
	ctx  = context.Background()
)

func server(t *testing.T, handle func(r *http.Request, body request) (int, any)) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in request
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			t.Errorf("decode request: %v", err)
		}
		status, body := handle(r, in)
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func answer(choice string, probs map[string]float64) map[string]any {
	return map[string]any{
		"model":   "jev-1.13.0",
		"answers": map[string]any{questionID: map[string]any{"type": "choice", "choice": choice, "confidence": 0.4, "probabilities": probs}},
		"usage":   map[string]int{"input_tokens": 10, "output_tokens": 0},
	}
}

func TestClassifyRequestShape(t *testing.T) {
	var gotReq *http.Request
	var got request
	srv := server(t, func(r *http.Request, body request) (int, any) {
		gotReq, got = r, body
		return 200, answer("benign", map[string]float64{"benign": 0.97, "sqli": 0.02, "scanner": 0.01})
	})
	if _, err := New(srv.URL, "jev-latest", "k", srv.Client()).Classify(ctx, req, cats); err != nil {
		t.Fatal(err)
	}
	if gotReq.URL.Path != "/v1/systemone" || gotReq.Header.Get("Authorization") != "Bearer k" {
		t.Errorf("path = %s, auth = %q", gotReq.URL.Path, gotReq.Header.Get("Authorization"))
	}
	if got.Model != "jev-latest" || got.State != classifier.Prompt(req) {
		t.Errorf("model = %q, state = %q", got.Model, got.State)
	}
	q := got.Questions[questionID]
	if q.Type != "choice" || q.Instructions != classifier.Instructions {
		t.Errorf("question = %+v", q)
	}
	if d := q.Criteria["benign"]; d == nil || *d != classifier.BenignDescription {
		t.Errorf("benign criterion = %v", d)
	}
	if d := q.Criteria["sqli"]; d == nil || *d != "SQL injection" {
		t.Errorf("sqli criterion = %v", d)
	}
	if d, ok := q.Criteria["scanner"]; !ok || d != nil {
		t.Errorf("scanner criterion = %v (present %v), want null", d, ok)
	}
}

func TestClassifyMapsDistribution(t *testing.T) {
	cases := []struct {
		name       string
		choice     string
		probs      map[string]float64
		benign     float64
		category   string
		confidence float64
	}{
		{"attack", "sqli", map[string]float64{"benign": 0.1, "sqli": 0.85, "scanner": 0.05}, 0.1, "sqli", 0.85},
		{"split attack", "benign", map[string]float64{"benign": 0.4, "sqli": 0.25, "scanner": 0.35}, 0.4, "scanner", 0.35},
		{"benign", "benign", map[string]float64{"benign": 0.97, "sqli": 0.02, "scanner": 0.01}, 0.97, "sqli", 0.02},
		{"no attack probabilities", "benign", map[string]float64{"benign": 1}, 1, "", 0},
		{"tie", "sqli", map[string]float64{"benign": 0.2, "scanner": 0.4, "sqli": 0.4}, 0.2, "sqli", 0.4},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := server(t, func(*http.Request, request) (int, any) { return 200, answer(c.choice, c.probs) })
			v, err := New(srv.URL, "jev-latest", "", srv.Client()).Classify(ctx, req, cats)
			if err != nil {
				t.Fatal(err)
			}
			if v.Benign != c.benign || v.Category != c.category || v.Confidence != c.confidence || len(v.Probs) != len(c.probs) {
				t.Errorf("verdict = %+v, want benign %v, %q @ %v (not Jev's spread confidence 0.4)", v, c.benign, c.category, c.confidence)
			}
		})
	}
}

func TestClassifyRejectsBadOutput(t *testing.T) {
	bodies := map[string]struct {
		body any
		want classifier.Reason
	}{
		"unknown choice":        {answer("rce", map[string]float64{"rce": 1}), classifier.ReasonBadOutput},
		"missing benign":        {answer("sqli", map[string]float64{"sqli": 1}), classifier.ReasonBadResponse},
		"missing answer":        {map[string]any{"answers": map[string]any{}}, classifier.ReasonBadResponse},
		"probability above one": {answer("sqli", map[string]float64{"benign": 0.1, "sqli": 1.2}), classifier.ReasonBadResponse},
		"negative benign":       {answer("sqli", map[string]float64{"benign": -0.1, "sqli": 0.9}), classifier.ReasonBadResponse},
		"benign above one":      {answer("benign", map[string]float64{"benign": 1.5}), classifier.ReasonBadResponse},
	}
	for name, c := range bodies {
		t.Run(name, func(t *testing.T) {
			srv := server(t, func(*http.Request, request) (int, any) { return 200, c.body })
			_, err := New(srv.URL, "jev-latest", "", srv.Client()).Classify(ctx, req, cats)
			if classifier.ReasonOf(err) != c.want {
				t.Errorf("ReasonOf = %q (%v), want %s", classifier.ReasonOf(err), err, c.want)
			}
		})
	}
}

func TestClassifyHTTPErrors(t *testing.T) {
	cases := map[int]classifier.Reason{429: classifier.ReasonRateLimited, 529: classifier.ReasonUpstream5xx, 422: classifier.ReasonUpstream4xx}
	for status, want := range cases {
		srv := server(t, func(*http.Request, request) (int, any) { return status, map[string]string{"error": "x"} })
		_, err := New(srv.URL, "jev-latest", "", srv.Client()).Classify(ctx, req, cats)
		if classifier.ReasonOf(err) != want {
			t.Errorf("status %d: ReasonOf = %q, want %q", status, classifier.ReasonOf(err), want)
		}
	}
}

func TestProbe(t *testing.T) {
	var got request
	srv := server(t, func(_ *http.Request, body request) (int, any) {
		got = body
		return 200, answer("benign", map[string]float64{"benign": 1})
	})
	if err := New(srv.URL, "jev-latest", "", srv.Client()).Probe(ctx); err != nil {
		t.Errorf("Probe = %v", err)
	}
	criteria := got.Questions[questionID].Criteria
	if len(criteria) != 2 {
		t.Errorf("probe criteria keys = %d, want exactly benign and attack", len(criteria))
	}
	for _, k := range []string{"benign", "attack"} {
		if _, ok := criteria[k]; !ok {
			t.Errorf("probe criteria missing %q", k)
		}
	}
}
