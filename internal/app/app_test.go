package app

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/0x4272616E646F6E/decision-waf/internal/backend"
	"github.com/0x4272616E646F6E/decision-waf/internal/classifier"
	"github.com/0x4272616E646F6E/decision-waf/internal/classifier/fake"
	"github.com/0x4272616E646F6E/decision-waf/internal/config"
	"github.com/0x4272616E646F6E/decision-waf/internal/decision"
	"github.com/0x4272616E646F6E/decision-waf/internal/eval/dataset"
	"github.com/0x4272616E646F6E/decision-waf/internal/eval/results"
	"github.com/0x4272616E646F6E/decision-waf/internal/eval/run"
	"github.com/0x4272616E646F6E/decision-waf/internal/inspect"
	"github.com/0x4272616E646F6E/decision-waf/internal/policy"
)

func testConfig(policyFile string) config.Config {
	return config.Config{
		InspectionMode: inspect.ModeLite, FailureMode: policy.FailOpen, BlockThreshold: 0.8, BodyMaxBytes: 65536,
		Backend: "fake", Model: "fake", Timeout: time.Second,
		DeepMaxBytes: 1 << 20, DeepOversize: inspect.OversizeClassifyPrefix,
		ExtProcAddr: "127.0.0.1:0", ExtAuthzAddr: "127.0.0.1:0",
		ForwardAuthAddr: "127.0.0.1:0", MetricsAddr: "127.0.0.1:0", PolicyFile: policyFile, LogLevel: slog.LevelError,
	}
}

func start(t *testing.T, cfg config.Config, opts Options) *App {
	t.Helper()
	opts.Logger = slog.New(slog.DiscardHandler)
	a, err := New(cfg, opts)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Run: %v", err)
		}
	})
	return a
}

func authCheck(t *testing.T, a *App, uri string) int {
	t.Helper()
	req, _ := http.NewRequest("GET", "http://"+a.ForwardAuthAddr()+"/", nil)
	req.Header.Set("X-Forwarded-Method", "GET")
	req.Header.Set("X-Forwarded-Uri", uri)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode
}

func get(t *testing.T, url string) (int, string) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestServesDecisions(t *testing.T) {
	a := start(t, testConfig(""), Options{Classifier: fake.Attacks()})
	if got := authCheck(t, a, "/ok"); got != 200 {
		t.Errorf("/ok = %d, want 200", got)
	}
	if got := authCheck(t, a, "/attack"); got != 403 {
		t.Errorf("/attack = %d, want 403", got)
	}
	_, metrics := get(t, "http://"+a.AdminAddr()+"/metrics")
	want := `decision_waf_decisions_total{category="injection",frontend="forwardauth",outcome="block",route="default"} 1`
	if !strings.Contains(metrics, want) {
		t.Errorf("metrics missing %s", want)
	}
}

func TestReadinessWaitsForProbe(t *testing.T) {
	var healthy atomic.Bool
	probe := func(context.Context) error {
		if healthy.Load() {
			return nil
		}
		return errors.New("model still loading")
	}
	a := start(t, testConfig(""), Options{
		Classifier: fake.Returning(classifier.Verdict{Benign: 1}), Probe: probe, ProbeInterval: 10 * time.Millisecond,
	})
	if code, _ := get(t, "http://"+a.AdminAddr()+"/readyz"); code != 503 {
		t.Errorf("/readyz before probe success = %d, want 503", code)
	}
	if code, _ := get(t, "http://"+a.AdminAddr()+"/healthz"); code != 200 {
		t.Errorf("/healthz = %d, want 200", code)
	}
	healthy.Store(true)
	eventually(t, "readiness", func() bool { code, _ := get(t, "http://"+a.AdminAddr()+"/readyz"); return code == 200 })
}

func writePolicy(t *testing.T, path, doc string) {
	t.Helper()
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
}

const adminClosed = "routes: [{match: {path_prefix: /admin}, failure_mode: closed}]\n"

func TestReloadKeepsLastGoodPolicy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yaml")
	writePolicy(t, path, adminClosed)
	a := start(t, testConfig(path), Options{Classifier: fake.Failing(errors.New("down"))})
	if got := authCheck(t, a, "/admin"); got != 503 {
		t.Fatalf("/admin = %d, want 503 (fail closed)", got)
	}
	if err := os.WriteFile(path, []byte("routes: ["), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := a.Reload(); err == nil {
		t.Error("Reload accepted invalid YAML")
	}
	if got := authCheck(t, a, "/admin"); got != 503 {
		t.Errorf("/admin after bad reload = %d, want 503 (last good policy kept)", got)
	}
	_, metrics := get(t, "http://"+a.AdminAddr()+"/metrics")
	if !strings.Contains(metrics, `decision_waf_policy_reloads_total{result="failure"}`) {
		t.Error("failed reload not counted")
	}
}

func TestWatchReloadsOnAtomicReplace(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yaml")
	writePolicy(t, path, adminClosed)
	a := start(t, testConfig(path), Options{Classifier: fake.Failing(errors.New("down"))})
	if got := authCheck(t, a, "/admin"); got != 503 {
		t.Fatalf("/admin = %d, want 503", got)
	}
	writePolicy(t, path, "routes: [{match: {path_prefix: /other}, failure_mode: closed}]\n")
	eventually(t, "policy reload", func() bool { return authCheck(t, a, "/admin") == 200 })
}

func TestNewRejectsBadPolicyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yaml")
	writePolicy(t, path, "categories: []")
	if _, err := New(testConfig(path), Options{Classifier: fake.Failing(errors.New("x")), Logger: slog.New(slog.DiscardHandler)}); err == nil {
		t.Error("New accepted an invalid policy file")
	}
}

func TestRunStopsBackgroundWorkOnListenerError(t *testing.T) {
	var calls atomic.Int64
	probe := func(context.Context) error { calls.Add(1); return errors.New("down") }
	a, err := New(testConfig(""), Options{
		Classifier: fake.Failing(errors.New("x")), Probe: probe, ProbeInterval: 10 * time.Millisecond,
		Logger: slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- a.Run(context.Background()) }()
	eventually(t, "probe running", func() bool { return calls.Load() > 0 })
	_ = a.listeners[0].ln.Close()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Run returned nil after listener failure")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after listener failure")
	}
	n := calls.Load()
	time.Sleep(100 * time.Millisecond)
	if calls.Load() != n {
		t.Error("probe kept running after Run returned")
	}
}

func TestUnrelatedFileDoesNotReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	writePolicy(t, path, adminClosed)
	a := start(t, testConfig(path), Options{Classifier: fake.Failing(errors.New("down"))})
	time.Sleep(100 * time.Millisecond)
	writePolicy(t, filepath.Join(dir, "other.yaml"), "x: 1\n")
	time.Sleep(600 * time.Millisecond)
	_, metrics := get(t, "http://"+a.AdminAddr()+"/metrics")
	if strings.Contains(metrics, `decision_waf_policy_reloads_total{result="success"}`) {
		t.Error("unrelated file triggered a policy reload")
	}
}

func TestStartupWarnings(t *testing.T) {
	const debugWarn = "debug logging writes redacted, truncated request bodies to logs"
	const exposeWarn = "DECISION_WAF_EXPOSE_VERDICT sends classification categories to clients; use only for testing"
	cases := []struct {
		name               string
		level              slog.Level
		expose             bool
		wantDebug, wantExp bool
	}{
		{"defaults", slog.LevelInfo, false, false, false},
		{"debug", slog.LevelDebug, false, true, false},
		{"expose", slog.LevelInfo, true, false, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var buf bytes.Buffer
			cfg := testConfig("")
			cfg.LogLevel, cfg.ExposeVerdict = c.level, c.expose
			logStartupWarnings(slog.New(slog.NewTextHandler(&buf, nil)), cfg)
			out := buf.String()
			if got := strings.Count(out, debugWarn); got != b2i(c.wantDebug) {
				t.Errorf("debug warning count = %d, want %d; log:\n%s", got, b2i(c.wantDebug), out)
			}
			if got := strings.Count(out, exposeWarn); got != b2i(c.wantExp) {
				t.Errorf("expose warning count = %d, want %d; log:\n%s", got, b2i(c.wantExp), out)
			}
		})
	}
}

func TestLargeBodyLimitWarning(t *testing.T) {
	const warn = "are sent to the classifier"
	cases := []struct {
		name      string
		mode      inspect.Mode
		body      int
		deep      int
		noExtProc bool
		wantWarns int
	}{
		{"defaults", inspect.ModeStandard, 16384, 16384, false, 0},
		{"standard over", inspect.ModeStandard, 65536, 16384, false, 1},
		{"deep over", inspect.ModeDeep, 16384, 1 << 20, false, 1},
		{"lite ignores body limits", inspect.ModeLite, 1 << 20, 1 << 20, false, 0},
		{"no ext_proc, so no bodies", inspect.ModeStandard, 65536, 16384, true, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var buf bytes.Buffer
			cfg := testConfig("")
			cfg.InspectionMode, cfg.BodyMaxBytes, cfg.DeepMaxBytes = c.mode, c.body, c.deep
			if c.noExtProc {
				cfg.ExtProcAddr = ""
			}
			logStartupWarnings(slog.New(slog.NewTextHandler(&buf, nil)), cfg)
			if got := strings.Count(buf.String(), warn); got != c.wantWarns {
				t.Errorf("warnings = %d, want %d; log:\n%s", got, c.wantWarns, buf.String())
			}
		})
	}
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

func TestBackendEngineMatchesServer(t *testing.T) {
	cls := fake.New(func(_ context.Context, r *inspect.Request, _ []policy.Category) (classifier.Verdict, error) {
		switch {
		case r.Path == "/evil", r.Query == "q=evil":
			return classifier.Verdict{Benign: 0.1, Category: "injection", Confidence: 0.9}, nil
		case r.Path == "/borderline":
			return classifier.Verdict{Benign: 0.45, Category: "xss", Confidence: 0.5}, nil
		case r.Path == "/offlabel":
			return classifier.Verdict{}, classifier.Errorf(classifier.ReasonBadOutput, "off label")
		case r.Path == "/down":
			return classifier.Verdict{}, classifier.Errorf(classifier.ReasonUpstream5xx, "down")
		}
		return classifier.Verdict{Benign: 0.95}, nil
	})
	cfg := testConfig("")
	cfg.BlockThreshold = 0.5
	server := start(t, cfg, Options{Classifier: cls})

	uris := []string{"/ok", "/evil", "/borderline", "/search?q=evil", "/offlabel", "/down"}
	var entries []dataset.Entry
	for i, uri := range uris {
		path, query, _ := strings.Cut(uri, "?")
		entries = append(entries, dataset.Entry{ID: strconv.Itoa(i), Label: policy.Benign, Method: "GET", Path: path, Query: query})
	}
	var out bytes.Buffer
	w, err := results.NewWriter(&out, results.Header{})
	if err != nil {
		t.Fatal(err)
	}
	eng := backend.Engine(cfg, policy.Default(), cls, run.NewBreaker(), nil)
	if err := run.Run(context.Background(), eng, entries, nil, cfg.BodyMaxBytes, 1, w, nil); err != nil {
		t.Fatal(err)
	}
	f, err := results.Read(&out)
	if err != nil || len(f.Results) != len(uris) {
		t.Fatalf("results: %d, err %v", len(f.Results), err)
	}
	wantStatus := map[string]int{
		string(decision.Allow): http.StatusOK, string(decision.FailOpen): http.StatusOK,
		string(decision.Block): http.StatusForbidden, string(decision.FailClosed): http.StatusServiceUnavailable,
	}
	blocked := 0
	for _, r := range f.Results {
		i, _ := strconv.Atoi(r.ID)
		if got, want := authCheck(t, server, uris[i]), wantStatus[r.Outcome]; got != want {
			t.Errorf("%s: server answered %d, eval recorded %s", uris[i], got, r.Outcome)
		}
		if r.Outcome == string(decision.Block) {
			blocked++
		}
	}
	if blocked != 4 {
		t.Errorf("%d blocked, want 4 (evil, borderline, query, off-label)", blocked)
	}
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func TestSIGHUPBeforeRunIsQueued(t *testing.T) {
	pf := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(pf, []byte("redact:\n  headers: [authorization]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	logs := &syncBuffer{}
	a, err := New(testConfig(pf), Options{
		Classifier: fake.Returning(classifier.Verdict{Benign: 1}),
		Logger:     slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelInfo})),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Kill(os.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Run: %v", err)
		}
	}()
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(logs.String(), "policy reloaded") {
		if time.Now().After(deadline) {
			t.Fatalf("the SIGHUP sent before Run did not reload the policy; logs:\n%s", logs.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestSIGHUPDuringShutdownDrain(t *testing.T) {
	release := make(chan struct{})
	slow := fake.New(func(ctx context.Context, _ *inspect.Request, _ []policy.Category) (classifier.Verdict, error) {
		select {
		case <-release:
		case <-ctx.Done():
		}
		return classifier.Verdict{Benign: 1}, nil
	})
	a, err := New(testConfig(""), Options{Classifier: slow, Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()
	status := make(chan int, 1)
	go func() { status <- authCheck(t, a, "/slow") }()
	time.Sleep(200 * time.Millisecond)
	cancel()
	time.Sleep(200 * time.Millisecond)
	if err := syscall.Kill(os.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	close(release)
	if got := <-status; got != http.StatusOK {
		t.Errorf("in-flight request = %d, want 200", got)
	}
	if err := <-done; err != nil {
		t.Errorf("Run: %v", err)
	}
}
