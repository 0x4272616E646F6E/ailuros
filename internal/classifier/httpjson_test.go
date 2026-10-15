package classifier

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestPostJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer k" || r.Header.Get("Content-Type") != "application/json" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var in map[string]string
		_ = json.NewDecoder(r.Body).Decode(&in)
		_ = json.NewEncoder(w).Encode(map[string]string{"echo": in["msg"]})
	}))
	defer srv.Close()

	var out map[string]string
	if err := PostJSON(context.Background(), srv.Client(), srv.URL, "k", map[string]string{"msg": "hi"}, &out); err != nil {
		t.Fatal(err)
	}
	if out["echo"] != "hi" {
		t.Errorf("out = %v", out)
	}
	err := PostJSON(context.Background(), srv.Client(), srv.URL, "wrong", map[string]string{}, &out)
	if ReasonOf(err) != ReasonUpstream4xx {
		t.Errorf("bad key: ReasonOf = %q (%v), want upstream_4xx", ReasonOf(err), err)
	}
}

func TestPostJSONStatusAndDecodeErrors(t *testing.T) {
	cases := []struct {
		status int
		body   string
		want   Reason
	}{
		{429, "slow down", ReasonRateLimited},
		{503, "unavailable", ReasonUpstream5xx},
		{200, "not json", ReasonBadResponse},
		{204, "", ReasonUpstreamOther},
		{302, "moved", ReasonUpstreamOther},
		{404, "not found", ReasonUpstream4xx},
	}
	for _, c := range cases {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(c.status)
			_, _ = io.WriteString(w, c.body)
		}))
		var out map[string]any
		err := PostJSON(context.Background(), srv.Client(), srv.URL, "", struct{}{}, &out)
		if ReasonOf(err) != c.want {
			t.Errorf("status %d: ReasonOf = %q (%v), want %q", c.status, ReasonOf(err), err, c.want)
		}
		srv.Close()
	}
}

func TestPostJSONConnectionError(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close()
	var out map[string]any
	err := PostJSON(context.Background(), http.DefaultClient, url, "", struct{}{}, &out)
	if ReasonOf(err) != ReasonConnection {
		t.Errorf("ReasonOf = %q (%v), want connection", ReasonOf(err), err)
	}
}

func TestNewHTTPClientDoesNotFollowRedirects(t *testing.T) {
	var followed atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { followed.Store(true) }))
	defer target.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/v1", http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	var out map[string]any
	err := PostJSON(context.Background(), NewHTTPClient(), srv.URL, "sk-test", struct{}{}, &out)
	if err == nil || !strings.Contains(err.Error(), "redirect to "+target.URL+"/v1") {
		t.Errorf("err = %v, want the redirect target named", err)
	}
	if followed.Load() {
		t.Error("the redirect was followed")
	}
}

func TestPostJSONEncodingErrorIsInternal(t *testing.T) {
	err := PostJSON(context.Background(), http.DefaultClient, "http://127.0.0.1:1", "", map[string]any{"x": make(chan int)}, nil)
	if ReasonOf(err) != ReasonInternal {
		t.Errorf("ReasonOf = %q (%v), want internal", ReasonOf(err), err)
	}
}
