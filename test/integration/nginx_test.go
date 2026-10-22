//go:build integration

package integration

import (
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestNginx(t *testing.T) {
	t.Parallel()
	s := up(t, "nginx", nil)
	t.Run("http1", func(t *testing.T) { sharedCases(t, s, "http1") })

	t.Run("forged X-Forwarded-Uri and X-Forwarded-Method do not change what is classified", func(t *testing.T) {
		m := newMarker(t)
		forged := http.Header{"X-Forwarded-Uri": {"/search?q=attack"}, "X-Forwarded-Method": {"DELETE"}}
		v := echoed(t, s.Get(t, "http1", "/real/"+m, forged))
		d := s.WantDecision(t, upstreamID(t, v), "allow", "")
		if d.Str("method") != "GET" || d.Str("path") != "/real/"+m {
			t.Errorf("classified %s %s, want GET /real/%s", d.Str("method"), d.Str("path"), m)
		}
		if prompts := s.Prompts(t, m); len(prompts) != 1 || strings.Contains(prompts[0], "attack") {
			t.Errorf("prompts = %q, want one prompt without the forged URI", prompts)
		}

		m = newMarker(t)
		resp := s.Get(t, "http1", "/search/"+m+"?q=attack", http.Header{"X-Forwarded-Uri": {"/"}, "X-Forwarded-Method": {"GET"}})
		s.WantDecision(t, wantDeny(t, resp, http.StatusForbidden, "request blocked"), "block", "")
	})

	t.Run("decision-waf hanging fails closed with 503 within seconds", func(t *testing.T) {
		c := composeOf(t, s)
		if out, err := c.run("pause", "decision-waf"); err != nil {
			t.Fatalf("compose pause decision-waf: %v\n%s", err, out)
		}
		unpaused := false
		unpause := func() {
			if unpaused {
				return
			}
			unpaused = true
			if out, err := c.run("unpause", "decision-waf"); err != nil {
				t.Errorf("compose unpause decision-waf: %v\n%s", err, out)
			}
		}
		defer unpause()

		start := time.Now()
		resp, err := s.do(s.http1, Request{Method: "GET", Path: "/hang/" + newMarker(t)})
		elapsed := time.Since(start)
		if err != nil {
			t.Fatalf("request with decision-waf paused: %v after %v", err, elapsed.Round(100*time.Millisecond))
		}
		t.Logf("NGINX answered %d after %v", resp.Status, elapsed.Round(100*time.Millisecond))
		if resp.Status != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want 503; body: %s", resp.Status, resp.Body)
		}
		if elapsed > 5*time.Second {
			t.Errorf("503 took %v, want under 5s (proxy_read_timeout is 1500ms)", elapsed.Round(100*time.Millisecond))
		}
		var body map[string]string
		if err := json.Unmarshal(resp.Body, &body); err != nil || body["error"] != "service unavailable" {
			t.Errorf("body = %s, want the 503 JSON (%v)", resp.Body, err)
		}
		if _, ok := body["request_id"]; !ok {
			t.Errorf("body = %s, want a request_id field", resp.Body)
		}

		unpause()
		echoed(t, s.Get(t, "http1", "/after-hang/"+newMarker(t), nil))
	})

	failClosedWhenDecisionWafDown(t, s, http.StatusServiceUnavailable, func(t *testing.T, resp *Response) {
		var body map[string]string
		if err := json.Unmarshal(resp.Body, &body); err != nil || body["error"] != "service unavailable" || body["request_id"] != "" {
			t.Errorf("body = %s, want the 503 JSON with an empty request_id (%v)", resp.Body, err)
		}
	})
}

func dockerOut(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command("docker", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("docker %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

func TestNginxReResolvesDecisionWafWithoutReload(t *testing.T) {
	t.Parallel()
	s := up(t, "nginx", map[string]string{"DECISION_WAF_FAILURE_MODE": "open"})
	c := composeOf(t, s)
	network := c.project + "_default"
	ipOf := func(container string) string {
		return dockerOut(t, "inspect", "-f", `{{(index .NetworkSettings.Networks "`+network+`").IPAddress}}`, container)
	}
	container := func(service string) string { return dockerOut(t, "compose", "-p", c.project, "ps", "-q", service) }

	m := newMarker(t)
	echoed(t, s.Get(t, "http1", "/before/"+m, nil))

	nginxID := container("nginx")
	nginxStarted := dockerOut(t, "inspect", "-f", "{{.State.StartedAt}}", nginxID)
	oldIP := ipOf(container("decision-waf"))

	s.StopDecisionWaf(t)
	holder := "decision-waf-it-ipholder-" + newMarker(t)
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", holder).Run() })
	dockerOut(t, "run", "-d", "--name", holder, "--label", extraLabel+"="+c.project, "--network", network,
		"--entrypoint", "sleep", composeImage(t, "nginx.yaml"), "3600")
	holderIP := ipOf(holder)
	t.Logf("decision-waf IP before: %s; throwaway container IP: %s", oldIP, holderIP)

	if out, err := c.run("start", "decision-waf"); err != nil {
		t.Fatalf("compose start decision-waf: %v\n%s", err, out)
	}
	newIP := ipOf(container("decision-waf"))
	t.Logf("decision-waf IP after restart: %s", newIP)
	if newIP == oldIP {
		t.Fatalf("decision-waf came back on the same IP %s (the throwaway container got %s); the test needs it to move", oldIP, holderIP)
	}

	s.adminURL = "http://" + c.port(t, "decision-waf", decisionWafAdminPort)
	s.waitAdminReady(t)

	start := time.Now()
	var last string
	for {
		resp, err := s.do(s.http1, Request{Method: "GET", Path: "/after/" + newMarker(t)})
		if err == nil && resp.Status == http.StatusOK {
			t.Logf("NGINX served a benign request %v after decision-waf was ready", time.Since(start).Round(100*time.Millisecond))
			break
		}
		if err != nil {
			last = err.Error()
		} else {
			last = resp.Proto + " " + http.StatusText(resp.Status) + " " + string(resp.Body)
		}
		if time.Since(start) > 20*time.Second {
			t.Fatalf("NGINX still failing 20s after decision-waf moved from %s to %s (last: %s); it is not re-resolving", oldIP, newIP, last)
		}
		time.Sleep(500 * time.Millisecond)
	}
	if got := container("nginx"); got != nginxID {
		t.Errorf("NGINX container changed from %s to %s", nginxID, got)
	}
	if got := dockerOut(t, "inspect", "-f", "{{.State.StartedAt}}", nginxID); got != nginxStarted {
		t.Errorf("NGINX was restarted (started %s, now %s)", nginxStarted, got)
	}
}

func composeImage(t *testing.T, file string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(composeDir, file))
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^\s+image:\s*(\S+)\s*$`).FindSubmatch(data)
	if m == nil {
		t.Fatalf("%s has no image: line", file)
	}
	return string(m[1])
}
