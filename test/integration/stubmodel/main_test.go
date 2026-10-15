//go:build integration

package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/0x4272616E646F6E/ailuros/internal/classifier"
	"github.com/0x4272616E646F6E/ailuros/internal/classifier/jev"
	"github.com/0x4272616E646F6E/ailuros/internal/inspect"
	"github.com/0x4272616E646F6E/ailuros/internal/policy"
)

func start(t *testing.T, slow time.Duration) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(newServer(slow).handler())
	t.Cleanup(srv.Close)
	return srv
}

func classify(t *testing.T, srv *httptest.Server, timeout time.Duration, r *inspect.Request) (classifier.Verdict, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return jev.New(srv.URL, "stub", "", srv.Client()).Classify(ctx, r, policy.DefaultCategories())
}

func TestStubDecidesOnMarkers(t *testing.T) {
	srv := start(t, time.Second)
	cases := []struct {
		path     string
		benign   float64
		category string
	}{
		{"/hello", 0.99, ""},
		{"/search?q=attack", 0.01, "sqli"},
		{"/comment/xss-marker", 0.01, "xss"},
	}
	for _, c := range cases {
		path, query, _ := strings.Cut(c.path, "?")
		v, err := classify(t, srv, time.Second, &inspect.Request{Method: "GET", Path: path, Query: query})
		if err != nil {
			t.Fatalf("%s: %v", c.path, err)
		}
		if v.Benign != c.benign {
			t.Errorf("%s: Benign = %v, want %v", c.path, v.Benign, c.benign)
		}
		if c.category != "" && (v.Category != c.category || v.Confidence != 0.99) {
			t.Errorf("%s: Category = %q (%v), want %q (0.99)", c.path, v.Category, v.Confidence, c.category)
		}
	}
}

func TestStubAttackWithoutSqliCategory(t *testing.T) {
	criteria := map[string]*string{"benign": nil, "attack": nil}
	if a := decide("GET /attack", criteria); a.Choice != "attack" || a.Probabilities["attack"] != 0.99 {
		t.Errorf("decide = %+v, want choice attack with 0.99", a)
	}
	if a := decide("GET /", criteria); a.Choice != "benign" || a.Probabilities["benign"] != 0.99 {
		t.Errorf("decide = %+v, want benign 0.99", a)
	}
}

func TestStubControlMarkers(t *testing.T) {
	srv := start(t, 300*time.Millisecond)
	cases := map[string]classifier.Reason{
		"/stub-fail":      classifier.ReasonUpstream5xx,
		"/stub-garbage":   classifier.ReasonBadResponse,
		"/stub-offformat": classifier.ReasonBadOutput,
	}
	for path, want := range cases {
		_, err := classify(t, srv, time.Second, &inspect.Request{Method: "GET", Path: path})
		if got := classifier.ReasonOf(err); got != want {
			t.Errorf("%s: reason = %q (%v), want %q", path, got, err, want)
		}
	}
	if _, err := classify(t, srv, 100*time.Millisecond, &inspect.Request{Method: "GET", Path: "/stub-slow"}); classifier.ReasonOf(err) != classifier.ReasonTimeout {
		t.Errorf("stub-slow with 100ms timeout: %v, want timeout", err)
	}
	start := time.Now()
	v, err := classify(t, srv, 2*time.Second, &inspect.Request{Method: "GET", Path: "/stub-slow"})
	if err != nil || v.Benign != 0.99 {
		t.Fatalf("stub-slow with 2s timeout: %+v, %v", v, err)
	}
	if elapsed := time.Since(start); elapsed < 300*time.Millisecond {
		t.Errorf("stub-slow answered after %v, want at least 300ms", elapsed)
	}
}

func TestStubIsSlowOnLargePrompts(t *testing.T) {
	srv := start(t, 300*time.Millisecond)
	small := &inspect.Request{Method: "POST", Path: "/upload", Body: []byte(strings.Repeat(".", 16<<10))}
	if _, err := classify(t, srv, 200*time.Millisecond, small); err != nil {
		t.Errorf("16 KiB body: %v, want a prompt answer", err)
	}
	large := &inspect.Request{Method: "POST", Path: "/upload", Body: []byte(strings.Repeat(".", 33<<10))}
	if _, err := classify(t, srv, 100*time.Millisecond, large); classifier.ReasonOf(err) != classifier.ReasonTimeout {
		t.Errorf("33 KiB body with 100ms timeout: %v, want timeout", err)
	}
	start := time.Now()
	if v, err := classify(t, srv, 2*time.Second, large); err != nil || v.Benign != 0.99 {
		t.Fatalf("33 KiB body with 2s timeout: %+v, %v", v, err)
	}
	if elapsed := time.Since(start); elapsed < 300*time.Millisecond {
		t.Errorf("33 KiB body answered after %v, want at least 300ms", elapsed)
	}
}

func TestStubRecordsPrompts(t *testing.T) {
	srv := start(t, time.Second)
	for _, p := range []string{"/one-m1", "/two-m2", "/three-m1"} {
		if _, err := classify(t, srv, time.Second, &inspect.Request{Method: "GET", Path: p}); err != nil {
			t.Fatal(err)
		}
	}
	resp, err := srv.Client().Get(srv.URL + "/prompts?contains=" + url.QueryEscape("-m1"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var got []string
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || !strings.Contains(got[0], "path: /one-m1") || !strings.Contains(got[1], "path: /three-m1") {
		t.Errorf("prompts = %q, want the /one-m1 and /three-m1 prompts in order", got)
	}
}

func TestStubHealthcheck(t *testing.T) {
	srv := start(t, time.Second)
	if err := healthcheck(srv.URL + "/healthz"); err != nil {
		t.Errorf("healthcheck(/healthz) = %v, want nil", err)
	}
	if err := healthcheck(srv.URL + "/missing"); err == nil {
		t.Error("healthcheck(/missing) = nil, want an error")
	}
	resp, err := srv.Client().Get(srv.URL + "/v1/systemone")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("GET /v1/systemone = %d, want 405", resp.StatusCode)
	}
}
