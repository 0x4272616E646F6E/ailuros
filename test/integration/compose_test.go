//go:build integration

package integration

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
)

var (
	liveMu       sync.Mutex
	liveProjects = map[string]bool{}
)

type composeProxy struct {
	service string
	port    int
	proxy
}

var proxies = map[string]composeProxy{
	"envoy-lite":     {"envoy", 8080, proxy{}},
	"envoy-standard": {"envoy", 8080, proxy{}},
	"envoy-deep":     {"envoy", 8080, proxy{}},
	"envoy-extauthz": {"envoy", 8080, proxy{}},
	"nginx":          {"nginx", 80, proxy{forwardAuth: true, ownDenyBody: true}},
	"traefik":        {"traefik", 80, proxy{host: "app.example.com", forwardAuth: true}},
}

func TestMain(m *testing.M) {
	flag.Parse()
	cmd := exec.Command("docker", "compose", "-p", "ailuros-it", "-f", filepath.Join(composeDir, "common.yaml"), "build")
	cmd.Env = composeEnv(nil)
	if out, err := cmd.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "docker compose build: %v\n%s", err, out)
		os.Exit(1)
	}
	os.Exit(m.Run())
}

func composeEnv(overrides map[string]string) []string {
	env := slices.DeleteFunc(os.Environ(), func(kv string) bool {
		return strings.HasPrefix(kv, "AILUROS_") || strings.HasPrefix(kv, "ENVOY_LITE_CONFIG=")
	})
	for _, k := range slices.Sorted(maps.Keys(overrides)) {
		env = append(env, k+"="+overrides[k])
	}
	return env
}

func projectName(name string, env map[string]string) string {
	project := "ailuros-it-" + name
	if len(env) > 0 {
		h := sha256.New()
		for _, k := range slices.Sorted(maps.Keys(env)) {
			fmt.Fprintf(h, "%s=%s\n", k, env[k])
		}
		project += "-" + hex.EncodeToString(h.Sum(nil))[:6]
	}
	return project
}

func up(t *testing.T, name string, env map[string]string) *Stack {
	t.Helper()
	p, ok := proxies[name]
	if !ok {
		t.Fatalf("unknown stack %q", name)
	}
	c := &composeEnvironment{
		project: projectName(name, env),
		files:   []string{filepath.Join(composeDir, "common.yaml"), filepath.Join(composeDir, name+".yaml")},
		vars:    composeEnv(env),
	}
	s := newStack(name, c, p.proxy)
	startProject(t, s, c)
	s.ProxyAddr = c.port(t, p.service, p.port)
	s.stubURL = "http://" + c.port(t, "stubmodel", stubPort)
	s.echoURL = "http://" + c.port(t, "echo", echoAdminPort)
	s.adminURL = "http://" + c.port(t, "ailuros", ailurosAdminPort)
	s.waitReady(t)
	return s
}

func composeOf(t *testing.T, s *Stack) *composeEnvironment {
	t.Helper()
	c, ok := s.env.(*composeEnvironment)
	if !ok {
		t.Fatalf("stack %s is not a docker compose stack", s.Name)
	}
	return c
}

func startProject(t *testing.T, s *Stack, c *composeEnvironment, services ...string) {
	t.Helper()
	liveMu.Lock()
	if liveProjects[c.project] {
		liveMu.Unlock()
		t.Fatalf("compose project %s is already in use by another live test in this run", c.project)
	}
	liveProjects[c.project] = true
	liveMu.Unlock()

	t.Cleanup(func() {
		liveMu.Lock()
		delete(liveProjects, c.project)
		liveMu.Unlock()
		if t.Failed() {
			s.dumpDiagnostics(t)
		}
		if *keep {
			t.Logf("kept stack %s; remove it with: docker compose -p %s down -v", c.project, c.project)
			return
		}
		c.removeExtras()
		if out, err := c.run("down", "-v", "--remove-orphans"); err != nil {
			t.Logf("compose down %s: %v\n%s", c.project, err, out)
		}
	})
	c.removeExtras()
	_, _ = c.run("down", "-v", "--remove-orphans")
	if out, err := c.run(append([]string{"up", "-d", "--wait", "--wait-timeout", "120", "--no-build"}, services...)...); err != nil {
		t.Fatalf("compose up %s: %v\n%s", c.project, err, out)
	}
}

const extraLabel = "ailuros-it.project"

type composeEnvironment struct {
	project string
	files   []string
	vars    []string
}

func (c *composeEnvironment) removeExtras() {
	out, _ := exec.Command("docker", "ps", "-aq", "--filter", "label="+extraLabel+"="+c.project).Output()
	if ids := strings.Fields(string(out)); len(ids) > 0 {
		_ = exec.Command("docker", append([]string{"rm", "-f"}, ids...)...).Run()
	}
}

func (c *composeEnvironment) run(args ...string) ([]byte, error) {
	full := []string{"compose", "-p", c.project}
	for _, f := range c.files {
		full = append(full, "-f", f)
	}
	cmd := exec.Command("docker", append(full, args...)...)
	cmd.Env = c.vars
	return cmd.CombinedOutput()
}

func (c *composeEnvironment) port(t *testing.T, service string, port int) string {
	t.Helper()
	out, err := c.run("port", service, fmt.Sprint(port))
	if err != nil {
		t.Fatalf("compose port %s %d: %v\n%s", service, port, err, out)
	}
	return strings.TrimSpace(string(out))
}

func (c *composeEnvironment) ailurosLogs() ([]byte, error) {
	out, err := c.run("logs", "--no-color", "--no-log-prefix", "ailuros")
	if err != nil {
		return nil, fmt.Errorf("compose logs: %w\n%s", err, out)
	}
	return out, nil
}

func (c *composeEnvironment) stopAiluros() error {
	if out, err := c.run("stop", "ailuros"); err != nil {
		return fmt.Errorf("compose stop ailuros: %w\n%s", err, out)
	}
	return nil
}

func (c *composeEnvironment) diagnostics() string {
	out, _ := c.run("logs", "--no-color", "--tail", "50")
	return fmt.Sprintf("compose project %s: last 50 log lines per service:\n%s", c.project, out)
}
