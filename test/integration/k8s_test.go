//go:build k8s

package integration

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	kindCluster  = "ailuros-it"
	kubeContext  = "kind-" + kindCluster
	kindNode     = "kindest/node:v1.37.0@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5"
	egVersion    = "v1.9.2"
	egManifest   = "https://github.com/envoyproxy/gateway/releases/download/" + egVersion + "/install.yaml"
	egNamespace  = "envoy-gateway-system"
	k8sDir       = "k8s"
	k8sReadyWait = "3m"
)

var kubeconfigPath string

func TestMain(m *testing.M) {
	flag.Parse()
	if os.Getenv("AILUROS_K8S_SKIP_CLUSTER") == "1" {
		os.Exit(m.Run())
	}
	dir, err := os.MkdirTemp("", "ailuros-k8s-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "kubeconfig dir: %v\n", err)
		os.Exit(1)
	}
	kubeconfigPath = filepath.Join(dir, "kubeconfig")
	finish := func(code int) {
		if *keep {
			fmt.Printf("kept kind cluster %s; use it with: kubectl --kubeconfig %s --context %s ...\n"+
				"delete it with: kind delete cluster --name %s --kubeconfig %s\n",
				kindCluster, kubeconfigPath, kubeContext, kindCluster, kubeconfigPath)
		} else {
			if out, err := kindDelete().CombinedOutput(); err != nil {
				fmt.Fprintf(os.Stderr, "kind delete cluster: %v\n%s", err, out)
			}
			_ = os.RemoveAll(dir)
		}
		os.Exit(code)
	}
	if err := setupCluster(); err != nil {
		fmt.Fprintf(os.Stderr, "kind setup: %v\n", err)
		finish(1)
	}
	finish(m.Run())
}

func kindDelete() *exec.Cmd {
	return exec.Command("kind", "delete", "cluster", "--name", kindCluster, "--kubeconfig", kubeconfigPath)
}

func setupCluster() error {
	for _, tool := range []string{"docker", "kind", "kubectl"} {
		if _, err := exec.LookPath(tool); err != nil {
			return fmt.Errorf("make test-k8s needs %s on PATH", tool)
		}
	}
	steps := [][]string{
		kindDelete().Args,
		{"docker", "compose", "-p", "ailuros-it", "-f", filepath.Join(composeDir, "common.yaml"), "build"},
		{"kind", "create", "cluster", "--name", kindCluster, "--kubeconfig", kubeconfigPath, "--image", kindNode, "--wait", "120s"},
		{"kind", "load", "docker-image", "--name", kindCluster, "ailuros-it/ailuros:dev", "ailuros-it/stubmodel:dev", "ailuros-it/echo:dev"},
		append([]string{"kubectl"}, kubectlArgs("apply", "--server-side", "-f", egManifest)...),
		append([]string{"kubectl"}, kubectlArgs("-n", egNamespace, "wait", "--for=condition=Available", "--timeout=5m", "deployment/envoy-gateway")...),
		append([]string{"kubectl"}, kubectlArgs("apply", "-f", filepath.Join(k8sDir, "gatewayclass.yaml"))...),
	}
	for _, s := range steps {
		start := time.Now()
		ctx, cancel := context.WithTimeout(context.Background(), stepTimeout(s))
		out, err := exec.CommandContext(ctx, s[0], s[1:]...).CombinedOutput()
		timedOut := ctx.Err() != nil
		cancel()
		if timedOut {
			return fmt.Errorf("step timed out after %v: %s\n%s", stepTimeout(s), strings.Join(s, " "), out)
		}
		leftoverDelete := s[0] == "kind" && s[1] == "delete"
		if err != nil && !leftoverDelete {
			return fmt.Errorf("%s: %w\n%s", strings.Join(s, " "), err, out)
		}
		fmt.Fprintf(os.Stderr, "%s (%v)\n", strings.Join(s[:min(len(s), 4)], " "), time.Since(start).Round(time.Second))
	}
	return nil
}

func stepTimeout(step []string) time.Duration {
	switch {
	case step[0] == "docker":
		return 10 * time.Minute
	case step[0] == "kind" && (step[1] == "create" || step[1] == "load"):
		return 5 * time.Minute
	case step[0] == "kubectl" && slices.Contains(step, "--server-side"):
		return 5 * time.Minute
	case step[0] == "kubectl" && slices.Contains(step, "--timeout=5m"):
		return 6 * time.Minute
	}
	return time.Minute
}

func TestKubectlArgsPinContext(t *testing.T) {
	old := kubeconfigPath
	kubeconfigPath = "/tmp/test-kubeconfig"
	defer func() { kubeconfigPath = old }()
	got := kubectlArgs("-n", "x", "get", "pods")
	want := []string{"--kubeconfig", "/tmp/test-kubeconfig", "--context", "kind-ailuros-it", "-n", "x", "get", "pods"}
	if !slices.Equal(got, want) {
		t.Errorf("kubectlArgs = %q, want %q", got, want)
	}
}

func kubectlArgs(args ...string) []string {
	return append([]string{"--kubeconfig", kubeconfigPath, "--context", kubeContext}, args...)
}

func kubectl(args ...string) ([]byte, error) {
	var stdout, stderr bytes.Buffer
	cmd := exec.Command("kubectl", kubectlArgs(args...)...)
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return stdout.Bytes(), fmt.Errorf("kubectl %s: %w\n%s", strings.Join(args, " "), err, stderr.Bytes())
	}
	return stdout.Bytes(), nil
}

func mustKubectl(t *testing.T, args ...string) string {
	t.Helper()
	out, err := kubectl(args...)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(out))
}

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

var (
	forwardMu   sync.Mutex
	forwardLogs = map[string]*lockedBuffer{}
)

var forwarding = regexp.MustCompile(`Forwarding from 127\.0\.0\.1:(\d+)`)

func portForward(t *testing.T, ns, target string, port int) string {
	t.Helper()
	cmd := exec.Command("kubectl", kubectlArgs("-n", ns, "port-forward", target, fmt.Sprintf(":%d", port))...)
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stderr := &lockedBuffer{}
	cmd.Stderr = stderr
	forwardMu.Lock()
	forwardLogs[ns+" "+target] = stderr
	forwardMu.Unlock()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	found := make(chan string, 1)
	go func() {
		sc := bufio.NewScanner(out)
		for sc.Scan() {
			if m := forwarding.FindStringSubmatch(sc.Text()); m != nil {
				select {
				case found <- m[1]:
				default:
				}
			}
		}
	}()
	select {
	case p := <-found:
		return "127.0.0.1:" + p
	case <-time.After(30 * time.Second):
		t.Fatalf("kubectl port-forward %s/%s :%d did not start; stderr:\n%s", ns, target, port, stderr)
		return ""
	}
}

func policyKind(overlay string) string {
	if overlay == "ext_authz" {
		return "securitypolicy"
	}
	return "envoyextensionpolicy"
}

func upK8s(t *testing.T, overlay string) *Stack {
	t.Helper()
	ns := "ailuros-" + strings.ReplaceAll(overlay, "_", "-")
	dir := filepath.Join(k8sDir, overlay)
	s := newStack(overlay, kubeEnvironment{ns}, proxy{})
	forwarded := false
	t.Cleanup(func() {
		if t.Failed() && !forwarded {
			s.dumpDiagnostics(t)
		}
		if !*keep {
			_, _ = kubectl("delete", "namespace", ns, "--wait=false")
		}
	})
	if out, err := kubectl("create", "namespace", ns); err != nil && !strings.Contains(err.Error(), "AlreadyExists") {
		t.Fatalf("%v\n%s", err, out)
	}
	mustKubectl(t, "apply", "--dry-run=server", "-k", dir)
	mustKubectl(t, "apply", "-k", dir)
	for _, d := range []string{"ailuros", "stubmodel", "echo"} {
		mustKubectl(t, "-n", ns, "rollout", "status", "deployment/"+d, "--timeout="+k8sReadyWait)
	}
	policies := []string{policyKind(overlay) + "/ailuros"}
	if overlay == "deep" {
		policies = append(policies, "backendtrafficpolicy/ailuros-deep-timeouts", "clienttrafficpolicy/ailuros-deep-client-timeouts")
	}
	for _, p := range policies {
		mustKubectl(t, "-n", ns, "wait", p, "--timeout=2m",
			`--for=jsonpath={.status.ancestors[0].conditions[?(@.type=="Accepted")].status}=True`)
	}
	owner := "gateway.envoyproxy.io/owning-gateway-name=eg,gateway.envoyproxy.io/owning-gateway-namespace=" + ns
	var svc string
	deadline := time.Now().Add(2 * time.Minute)
	for {
		svcs := strings.Fields(mustKubectl(t, "-n", egNamespace, "get", "svc", "-l", owner, "-o", "name"))
		deps := strings.Fields(mustKubectl(t, "-n", egNamespace, "get", "deployment", "-l", owner, "-o", "name"))
		if len(svcs) > 1 || len(deps) > 1 {
			t.Fatalf("Gateway %s/eg owns %d Services %q and %d Deployments %q, want one of each", ns, len(svcs), svcs, len(deps), deps)
		}
		if len(svcs) == 1 && len(deps) == 1 {
			svc = strings.TrimPrefix(svcs[0], "service/")
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("Envoy Gateway created no Service and Deployment for Gateway %s/eg (services %q, deployments %q)", ns, svcs, deps)
		}
		time.Sleep(2 * time.Second)
	}
	mustKubectl(t, "-n", egNamespace, "wait", "deployment", "-l", owner, "--for=condition=Available", "--timeout="+k8sReadyWait)
	s.ProxyAddr = portForward(t, egNamespace, "svc/"+svc, 80)
	s.stubURL = "http://" + portForward(t, ns, "svc/stubmodel", stubPort)
	s.echoURL = "http://" + portForward(t, ns, "svc/app", echoAdminPort)
	s.adminURL = "http://" + portForward(t, ns, "svc/ailuros", ailurosAdminPort)
	forwarded = true
	t.Cleanup(func() {
		if t.Failed() {
			s.dumpDiagnostics(t)
		}
	})
	s.waitReady(t)
	waitAttached(t, s)
	return s
}

func waitAttached(t *testing.T, s *Stack) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	var last string
	for {
		resp, err := s.do(s.http1, Request{Method: "GET", Path: "/attached/" + newMarker(t)})
		if err != nil {
			last = err.Error()
		} else if resp.Status == 200 {
			var v echoView
			if err := json.Unmarshal(resp.Body, &v); err == nil && v.Headers.Get("X-Ailuros-Request-Id") != "" {
				return
			}
			last = "200 without X-Ailuros-Request-Id"
		} else {
			last = fmt.Sprintf("status %d", resp.Status)
		}
		if time.Now().After(deadline) {
			t.Fatalf("stack %s: Ailuros not attached to the proxy after 60s (last: %s)", s.Name, last)
		}
		time.Sleep(time.Second)
	}
}

type kubeEnvironment struct{ ns string }

func (k kubeEnvironment) ailurosLogs() ([]byte, error) {
	return kubectl("-n", k.ns, "logs", "-l", "app.kubernetes.io/name=ailuros", "--tail=-1", "--max-log-requests=10")
}

func (k kubeEnvironment) stopAiluros() error {
	if _, err := kubectl("-n", k.ns, "scale", "deployment/ailuros", "--replicas=0"); err != nil {
		return err
	}
	_, err := kubectl("-n", k.ns, "wait", "pod", "-l", "app.kubernetes.io/name=ailuros", "--for=delete", "--timeout=60s")
	return err
}

func (k kubeEnvironment) diagnostics() string {
	var b strings.Builder
	section := func(title string, args ...string) {
		out, err := kubectl(args...)
		fmt.Fprintf(&b, "\n== %s\n%s", title, out)
		if err != nil {
			fmt.Fprintf(&b, "(%v)\n", err)
		}
	}
	owner := "gateway.envoyproxy.io/owning-gateway-namespace=" + k.ns
	section("Ailuros logs", "-n", k.ns, "logs", "-l", "app.kubernetes.io/name=ailuros", "--tail=50")
	section("Envoy logs", "-n", egNamespace, "logs", "-l", owner, "--all-containers", "--tail=50")
	section("Envoy Gateway controller logs", "-n", egNamespace, "logs", "deployment/envoy-gateway", "--tail=50")
	section("policy and route status", "-n", k.ns, "get",
		"gateway,httproute,grpcroute,envoyextensionpolicy,securitypolicy,backendtrafficpolicy,clienttrafficpolicy", "-o", "yaml")
	forwardMu.Lock()
	for key, buf := range forwardLogs {
		if strings.HasPrefix(key, k.ns+" ") || strings.HasPrefix(key, egNamespace+" ") {
			fmt.Fprintf(&b, "\n== port-forward %s stderr\n%s", key, buf)
		}
	}
	forwardMu.Unlock()
	return b.String()
}
