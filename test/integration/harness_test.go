//go:build integration || k8s

package integration

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/0x4272616E646F6E/decision-waf/internal/config"
)

var keep = flag.Bool("keep", false, "leave the compose stacks or kind cluster running after the tests")

const (
	composeDir   = "compose"
	readyTimeout = 90 * time.Second
	logTimeout   = 10 * time.Second
	forgedIP     = "203.0.113.7"
)

const (
	stubPort      = 8080
	echoAdminPort = 8081
)

var decisionWafAdminPort = mustPort(config.DefaultMetricsAddr)

func mustPort(addr string) int {
	p, err := strconv.Atoi(strings.TrimPrefix(addr, ":"))
	if err != nil {
		panic(fmt.Sprintf("address %q has no port: %v", addr, err))
	}
	return p
}

type proxy struct {
	host        string
	forwardAuth bool
	ownDenyBody bool
}

type environment interface {
	decisionWafLogs() ([]byte, error)
	stopDecisionWaf() error
	diagnostics() string
}

type Stack struct {
	Name      string
	env       environment
	proxy     proxy
	ProxyAddr string
	stubURL   string
	echoURL   string
	adminURL  string
	http1     *http.Client
	h2c       *http.Client
}

func newStack(name string, env environment, p proxy) *Stack {
	h2 := &http.Transport{Protocols: new(http.Protocols)}
	h2.Protocols.SetUnencryptedHTTP2(true)
	return &Stack{
		Name: name, env: env, proxy: p,
		http1: &http.Client{Timeout: 20 * time.Second},
		h2c:   &http.Client{Timeout: 20 * time.Second, Transport: h2},
	}
}

func (s *Stack) StopDecisionWaf(t *testing.T) {
	t.Helper()
	if err := s.env.stopDecisionWaf(); err != nil {
		t.Fatal(err)
	}
}

func (s *Stack) waitReady(t *testing.T) {
	t.Helper()
	s.waitAdminReady(t)
	s.waitOK(t, "proxy", func() int {
		if resp, err := s.do(s.http1, Request{Method: "GET", Path: "/healthz"}); err == nil {
			return resp.Status
		}
		return 0
	})
}

func (s *Stack) waitAdminReady(t *testing.T) {
	t.Helper()
	s.waitOK(t, s.adminURL+"/readyz", func() int {
		resp, err := s.http1.Get(s.adminURL + "/readyz")
		if err != nil {
			return 0
		}
		resp.Body.Close()
		return resp.StatusCode
	})
}

func (s *Stack) waitOK(t *testing.T, what string, status func() int) {
	t.Helper()
	deadline := time.Now().Add(readyTimeout)
	for {
		last := status()
		if last == http.StatusOK {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("stack %s: %s not ready after %v (last status %d)", s.Name, what, readyTimeout, last)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

func (s *Stack) dumpDiagnostics(t *testing.T) {
	t.Logf("stack %s: %s", s.Name, s.env.diagnostics())
	if prompts, err := s.prompts(""); err == nil {
		if len(prompts) > 10 {
			prompts = prompts[len(prompts)-10:]
		}
		t.Logf("stack %s: last %d stub prompts:\n%s", s.Name, len(prompts), strings.Join(prompts, "\n---\n"))
	}
}

type Request struct {
	Method string
	Path   string
	Header http.Header
	Body   []byte
}

type Response struct {
	Status int
	Proto  string
	Header http.Header
	Body   []byte
}

func (s *Stack) do(c *http.Client, r Request) (*Response, error) {
	req, err := http.NewRequest(r.Method, "http://"+s.ProxyAddr+r.Path, bytes.NewReader(r.Body))
	if err != nil {
		return nil, err
	}
	for k, v := range r.Header {
		req.Header[k] = v
	}
	if s.proxy.host != "" {
		req.Host = s.proxy.host
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return &Response{Status: resp.StatusCode, Proto: resp.Proto, Header: resp.Header, Body: body}, nil
}

func (s *Stack) Send(t *testing.T, proto string, r Request) *Response {
	t.Helper()
	c := s.http1
	if proto == "h2c" {
		c = s.h2c
	}
	resp, err := s.do(c, r)
	if err != nil {
		t.Fatalf("%s %s over %s: %v", r.Method, r.Path, proto, err)
	}
	if want := map[string]int{"http1": 1, "h2c": 2}[proto]; !strings.HasPrefix(resp.Proto, fmt.Sprintf("HTTP/%d", want)) {
		t.Fatalf("%s %s: response protocol %s, want HTTP/%d", r.Method, r.Path, resp.Proto, want)
	}
	return resp
}

func (s *Stack) Get(t *testing.T, proto, path string, header http.Header) *Response {
	t.Helper()
	return s.Send(t, proto, Request{Method: "GET", Path: path, Header: header})
}

type echoView struct {
	Kind    string      `json:"kind"`
	Method  string      `json:"method"`
	Path    string      `json:"path"`
	Query   string      `json:"query"`
	Headers http.Header `json:"headers"`
	Body    []byte      `json:"body_b64"`
}

func echoed(t *testing.T, resp *Response) echoView {
	t.Helper()
	if resp.Status != http.StatusOK {
		t.Fatalf("status = %d, want 200 from echo; body: %s", resp.Status, resp.Body)
	}
	var v echoView
	if err := json.Unmarshal(resp.Body, &v); err != nil {
		t.Fatalf("response is not echo's JSON: %v; body: %s", err, resp.Body)
	}
	return v
}

func upstreamID(t *testing.T, v echoView) string {
	t.Helper()
	ids := v.Headers.Values("X-Decision-Waf-Request-Id")
	if len(ids) != 1 || ids[0] == "" {
		t.Fatalf("echo saw X-Decision-Waf-Request-Id %q, want exactly one non-empty value", ids)
	}
	return ids[0]
}

func wantDeny(t *testing.T, resp *Response, status int, msg string) string {
	t.Helper()
	if resp.Status != status {
		t.Fatalf("status = %d, want %d; body: %s", resp.Status, status, resp.Body)
	}
	id := resp.Header.Get("X-Decision-Waf-Request-Id")
	if id == "" {
		t.Errorf("denial has no X-Decision-Waf-Request-Id header")
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	var body map[string]string
	if err := json.Unmarshal(resp.Body, &body); err != nil {
		t.Fatalf("denial body is not JSON: %v; body: %s", err, resp.Body)
	}
	if want := map[string]string{"error": msg, "request_id": id}; !maps.Equal(body, want) {
		t.Errorf("denial body = %v, want %v", body, want)
	}
	return id
}

type Decision map[string]any

func (d Decision) Str(key string) string { s, _ := d[key].(string); return s }

func (s *Stack) decisions(t *testing.T, requestID string) []Decision {
	t.Helper()
	out, err := s.env.decisionWafLogs()
	if err != nil {
		t.Fatal(err)
	}
	var found []Decision
	for _, line := range strings.Split(string(out), "\n") {
		var d Decision
		if json.Unmarshal([]byte(line), &d) == nil && d.Str("msg") == "decision" && d.Str("request_id") == requestID {
			found = append(found, d)
		}
	}
	return found
}

func (s *Stack) pollDecisions(t *testing.T, requestID, want string, pick func([]Decision) (Decision, []Decision, bool)) (Decision, []Decision) {
	t.Helper()
	deadline := time.Now().Add(logTimeout)
	for {
		found := s.decisions(t, requestID)
		if d, all, ok := pick(found); ok {
			return d, all
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s for request_id %q; logged: %v", want, requestID, found)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func (s *Stack) Decision(t *testing.T, requestID string) Decision {
	t.Helper()
	d, _ := s.pollDecisions(t, requestID, "no decision log line", func(found []Decision) (Decision, []Decision, bool) {
		if len(found) > 0 {
			return found[0], found, true
		}
		return nil, nil, false
	})
	return d
}

func (s *Stack) Decisions(t *testing.T, requestID string, n int) []Decision {
	t.Helper()
	_, all := s.pollDecisions(t, requestID, fmt.Sprintf("want %d decision log lines", n), func(found []Decision) (Decision, []Decision, bool) {
		return nil, found, len(found) >= n
	})
	return all
}

func (s *Stack) WantDecision(t *testing.T, requestID, outcome, reason string) Decision {
	t.Helper()
	d, _ := s.pollDecisions(t, requestID, fmt.Sprintf("no decision with outcome=%q reason=%q", outcome, reason), func(found []Decision) (Decision, []Decision, bool) {
		for _, d := range found {
			if d.Str("outcome") == outcome && d.Str("reason") == reason {
				return d, found, true
			}
		}
		return nil, nil, false
	})
	return d
}

func getJSON(c *http.Client, u string, out any) error {
	resp, err := c.Get(u)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %s", u, resp.Status)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (s *Stack) prompts(contains string) ([]string, error) {
	var out []string
	err := getJSON(s.http1, s.stubURL+"/prompts?contains="+url.QueryEscape(contains), &out)
	return out, err
}

func (s *Stack) Prompts(t *testing.T, marker string) []string {
	t.Helper()
	out, err := s.prompts(marker)
	if err != nil {
		t.Fatalf("stub prompts: %v", err)
	}
	return out
}

func (s *Stack) Seen(t *testing.T, marker string) []echoView {
	t.Helper()
	var out []echoView
	if err := getJSON(s.http1, s.echoURL+"/seen?contains="+url.QueryEscape(marker), &out); err != nil {
		t.Fatalf("echo seen: %v", err)
	}
	return out
}

func newMarker(t *testing.T) string {
	t.Helper()
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return "m" + hex.EncodeToString(b)
}

func settle(t *testing.T, s *Stack, proto string) {
	t.Helper()
	for range 2 {
		echoed(t, s.Get(t, proto, "/settle/"+newMarker(t), nil))
	}
}
