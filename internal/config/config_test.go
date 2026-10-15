package config

import (
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/otel/propagation"

	"github.com/0x4272616E646F6E/ailuros/internal/inspect"
	"github.com/0x4272616E646F6E/ailuros/internal/policy"
)

func env(m map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
}

func noFiles(string) ([]byte, error) { return nil, os.ErrNotExist }

func required(extra map[string]string) map[string]string {
	m := map[string]string{"AILUROS_CLASSIFIER_BACKEND": "openai", "AILUROS_CLASSIFIER_MODEL": "llama3.2"}
	for k, v := range extra {
		m[k] = v
	}
	return m
}

func TestDefaults(t *testing.T) {
	cfg, err := Load(env(required(nil)), noFiles)
	if err != nil {
		t.Fatal(err)
	}
	want := Config{
		InspectionMode: inspect.ModeStandard, FailureMode: policy.FailOpen, BadOutput: policy.BadOutputBlock, BlockThreshold: 0.8, BodyMaxBytes: 16384,
		Backend: BackendOpenAI, BaseURL: "https://api.openai.com/v1", Model: "llama3.2", Timeout: time.Second,
		DeepMaxBytes: 16384, DeepOversize: inspect.OversizeClassifyPrefix, DeepMaxMessages: 100,
		ExtProcAddr: ":9001", ExtAuthzAddr: "", ForwardAuthAddr: ":9002", MetricsAddr: ":9090", LogLevel: slog.LevelInfo,
	}
	if !reflect.DeepEqual(cfg, want) {
		t.Errorf("Load = %+v\nwant   %+v", cfg, want)
	}
}

func TestJevBaseURLDefault(t *testing.T) {
	cfg, err := Load(env(required(map[string]string{"AILUROS_CLASSIFIER_BACKEND": "jev"})), noFiles)
	if err != nil || cfg.BaseURL != "https://api.typesafe.ai" {
		t.Errorf("BaseURL = %q, %v", cfg.BaseURL, err)
	}
}

func TestOverrides(t *testing.T) {
	cfg, err := Load(env(required(map[string]string{
		"AILUROS_INSPECTION_MODE": "deep", "AILUROS_FAILURE_MODE": "closed", "AILUROS_BLOCK_THRESHOLD": "0.65",
		"AILUROS_BODY_MAX_BYTES": "1024", "AILUROS_CLASSIFIER_BASE_URL": "http://ollama:11434/v1",
		"AILUROS_CLASSIFIER_API_KEY": "sk-test", "AILUROS_CLASSIFIER_TIMEOUT": "750ms",
		"AILUROS_FORWARDAUTH_ADDR": ":8000", "AILUROS_METRICS_ADDR": ":8001", "AILUROS_POLICY_FILE": "/etc/ailuros/policy.yaml",
		"AILUROS_LOG_LEVEL": "debug", "AILUROS_EXPOSE_VERDICT": "true", "AILUROS_BAD_OUTPUT": "failure_mode",
	})), noFiles)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.InspectionMode != inspect.ModeDeep || cfg.FailureMode != policy.FailClosed || cfg.BlockThreshold != 0.65 ||
		cfg.BodyMaxBytes != 1024 || cfg.BaseURL != "http://ollama:11434/v1" || cfg.APIKey != "sk-test" ||
		cfg.Timeout != 750*time.Millisecond || cfg.ForwardAuthAddr != ":8000" || cfg.MetricsAddr != ":8001" ||
		cfg.PolicyFile != "/etc/ailuros/policy.yaml" || cfg.LogLevel != slog.LevelDebug || !cfg.ExposeVerdict ||
		cfg.BadOutput != policy.BadOutputFailureMode {
		t.Errorf("Load = %+v", cfg)
	}
}

func TestEnvoySettings(t *testing.T) {
	cfg, err := Load(env(required(map[string]string{
		"AILUROS_EXTPROC_ADDR": "", "AILUROS_EXTAUTHZ_ADDR": ":9003",
		"AILUROS_DEEP_MAX_BYTES": "4096", "AILUROS_DEEP_OVERSIZE": "block",
	})), noFiles)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ExtProcAddr != "" || cfg.ExtAuthzAddr != ":9003" || cfg.DeepMaxBytes != 4096 || cfg.DeepOversize != inspect.OversizeBlock {
		t.Errorf("Load = %+v", cfg)
	}
}

func TestEmptyForwardAuthAddrDisables(t *testing.T) {
	cfg, err := Load(env(required(map[string]string{"AILUROS_FORWARDAUTH_ADDR": ""})), noFiles)
	if err != nil || cfg.ForwardAuthAddr != "" {
		t.Errorf("ForwardAuthAddr = %q, %v; want disabled", cfg.ForwardAuthAddr, err)
	}
}

func TestAPIKeyFile(t *testing.T) {
	read := func(path string) ([]byte, error) {
		if path == "/run/secrets/key" {
			return []byte("sk-from-file\n"), nil
		}
		return nil, os.ErrNotExist
	}
	cfg, err := Load(env(required(map[string]string{"AILUROS_CLASSIFIER_API_KEY_FILE": "/run/secrets/key"})), read)
	if err != nil || cfg.APIKey != "sk-from-file" {
		t.Errorf("APIKey = %q, %v", cfg.APIKey, err)
	}
	_, err = Load(env(required(map[string]string{"AILUROS_CLASSIFIER_API_KEY_FILE": "/missing"})), read)
	if err == nil {
		t.Error("missing key file accepted")
	}
}

func TestAPIKeyFileErrorHidesTheValue(t *testing.T) {
	const secret = "test-api-key"
	read := func(path string) ([]byte, error) {
		return nil, &fs.PathError{Op: "open", Path: path, Err: fs.ErrNotExist}
	}
	_, err := Load(env(required(map[string]string{"AILUROS_CLASSIFIER_API_KEY_FILE": secret})), read)
	if err == nil || strings.Contains(err.Error(), secret) || !strings.Contains(err.Error(), "file does not exist") {
		t.Errorf("err = %v, want the reason without the value", err)
	}
}

func TestAPIKeyFileEmpty(t *testing.T) {
	for _, content := range []string{"", " \n\t\n"} {
		read := func(string) ([]byte, error) { return []byte(content), nil }
		_, err := Load(env(required(map[string]string{"AILUROS_CLASSIFIER_API_KEY_FILE": "/run/secrets/key"})), read)
		if err == nil || !strings.Contains(err.Error(), "AILUROS_CLASSIFIER_API_KEY_FILE") || !strings.Contains(err.Error(), "/run/secrets/key is empty") {
			t.Errorf("key file %q: err = %v, want an error naming the variable and the empty file", content, err)
		}
	}
	if _, err := Load(env(required(map[string]string{"AILUROS_CLASSIFIER_API_KEY": ""})), noFiles); err != nil {
		t.Errorf("empty AILUROS_CLASSIFIER_API_KEY rejected: %v", err)
	}
}

func TestAPIKeyAndFileConflict(t *testing.T) {
	_, err := Load(env(required(map[string]string{
		"AILUROS_CLASSIFIER_API_KEY": "a", "AILUROS_CLASSIFIER_API_KEY_FILE": "/run/secrets/key",
	})), noFiles)
	if err == nil {
		t.Error("both API key and key file accepted")
	}
}

func TestCollectsAllErrors(t *testing.T) {
	_, err := Load(env(map[string]string{
		"AILUROS_INSPECTION_MODE": "full", "AILUROS_FAILURE_MODE": "maybe", "AILUROS_BLOCK_THRESHOLD": "NaN",
		"AILUROS_BODY_MAX_BYTES": "-1", "AILUROS_CLASSIFIER_TIMEOUT": "soon", "AILUROS_METRICS_ADDR": "",
		"AILUROS_LOG_LEVEL": "loud", "AILUROS_EXPOSE_VERDICT": "perhaps",
		"AILUROS_DEEP_MAX_BYTES": "0", "AILUROS_DEEP_OVERSIZE": "drop", "AILUROS_BAD_OUTPUT": "allow",
	}), noFiles)
	if err == nil {
		t.Fatal("invalid config accepted")
	}
	for _, name := range []string{
		"AILUROS_INSPECTION_MODE", "AILUROS_FAILURE_MODE", "AILUROS_BLOCK_THRESHOLD", "AILUROS_BODY_MAX_BYTES",
		"AILUROS_CLASSIFIER_BACKEND", "AILUROS_CLASSIFIER_MODEL", "AILUROS_CLASSIFIER_TIMEOUT",
		"AILUROS_METRICS_ADDR", "AILUROS_LOG_LEVEL", "AILUROS_EXPOSE_VERDICT",
		"AILUROS_DEEP_MAX_BYTES", "AILUROS_DEEP_OVERSIZE", "AILUROS_BAD_OUTPUT",
	} {
		if !strings.Contains(err.Error(), name) {
			t.Errorf("error does not mention %s:\n%v", name, err)
		}
	}
}

func TestDeepMaxBytesCap(t *testing.T) {
	cfg, err := Load(env(required(map[string]string{"AILUROS_DEEP_MAX_BYTES": "67108864"})), noFiles)
	if err != nil || cfg.DeepMaxBytes != 64<<20 {
		t.Fatalf("64 MiB rejected: %v", err)
	}
	_, err = Load(env(required(map[string]string{"AILUROS_DEEP_MAX_BYTES": "67108865"})), noFiles)
	if err == nil || !strings.Contains(err.Error(), "AILUROS_DEEP_MAX_BYTES") || !strings.Contains(err.Error(), "67108864") {
		t.Errorf("err = %v, want AILUROS_DEEP_MAX_BYTES rejected above 67108864 (64 MiB)", err)
	}
}

func TestDeepMaxMessages(t *testing.T) {
	cfg, err := Load(env(required(map[string]string{"AILUROS_DEEP_MAX_MESSAGES": "2500"})), noFiles)
	if err != nil || cfg.DeepMaxMessages != 2500 {
		t.Fatalf("DeepMaxMessages = %d, %v; want 2500", cfg.DeepMaxMessages, err)
	}
	for _, bad := range []string{"0", "-1", "many", "10001"} {
		_, err := Load(env(required(map[string]string{"AILUROS_DEEP_MAX_MESSAGES": bad})), noFiles)
		if err == nil || !strings.Contains(err.Error(), "AILUROS_DEEP_MAX_MESSAGES") {
			t.Errorf("AILUROS_DEEP_MAX_MESSAGES=%q: err = %v, want it rejected", bad, err)
		}
	}
}

func TestAPIKeyNeverPrints(t *testing.T) {
	const key = "test-api-key"
	cfg := Config{APIKey: Secret(key)}
	var logs strings.Builder
	slog.New(slog.NewTextHandler(&logs, nil)).Info("config", "cfg", cfg, "key", cfg.APIKey)
	for _, out := range []string{fmt.Sprintf("%v", cfg), fmt.Sprintf("%+v", cfg), fmt.Sprintf("%#v", cfg), fmt.Sprint(cfg.APIKey), logs.String()} {
		if strings.Contains(out, key) {
			t.Errorf("key printed: %s", out)
		}
	}
	if string(cfg.APIKey) != key {
		t.Error("string() must return the key itself")
	}
}

func TestBaseURLValidated(t *testing.T) {
	for _, u := range []string{"", "localhost:1234", "ftp://models", "http://", "http://h/v1?x=1", "http://h/v1#f"} {
		_, err := Load(env(required(map[string]string{"AILUROS_CLASSIFIER_BASE_URL": u})), noFiles)
		if err == nil || !strings.Contains(err.Error(), "AILUROS_CLASSIFIER_BASE_URL") {
			t.Errorf("base URL %q: err = %v, want it rejected", u, err)
		}
	}
	if _, err := Load(env(required(map[string]string{"AILUROS_CLASSIFIER_BASE_URL": "http://localhost:1234/v1"})), noFiles); err != nil {
		t.Errorf("valid base URL rejected: %v", err)
	}
}

func TestEmptyKeyVariablesAreUnset(t *testing.T) {
	read := func(string) ([]byte, error) { return []byte("sk-from-file"), nil }
	cfg, err := Load(env(required(map[string]string{"AILUROS_CLASSIFIER_API_KEY": "", "AILUROS_CLASSIFIER_API_KEY_FILE": "/run/k"})), read)
	if err != nil || string(cfg.APIKey) != "sk-from-file" {
		t.Errorf("empty key with a key file: %v, key from file %v", err, string(cfg.APIKey) == "sk-from-file")
	}
	cfg, err = Load(env(required(map[string]string{"AILUROS_CLASSIFIER_API_KEY": "sk-env", "AILUROS_CLASSIFIER_API_KEY_FILE": ""})), noFiles)
	if err != nil || string(cfg.APIKey) != "sk-env" {
		t.Errorf("key with an empty key file variable: %v", err)
	}
}

func TestAPIKeyTrimmed(t *testing.T) {
	cfg, err := Load(env(required(map[string]string{"AILUROS_CLASSIFIER_API_KEY": "sk-test\n"})), noFiles)
	if err != nil || string(cfg.APIKey) != "sk-test" {
		t.Errorf("key %q, err %v", string(cfg.APIKey), err)
	}
}

func TestJA4Header(t *testing.T) {
	cfg, err := Load(env(required(nil)), noFiles)
	if err != nil || cfg.JA4Header != "" {
		t.Errorf("unset: %q, %v", cfg.JA4Header, err)
	}
	cfg, err = Load(env(required(map[string]string{"AILUROS_JA4_HEADER": "X-Ailuros-JA4"})), noFiles)
	if err != nil || cfg.JA4Header != "x-ailuros-ja4" {
		t.Errorf("set: %q, %v", cfg.JA4Header, err)
	}
	_, err = Load(env(required(map[string]string{"AILUROS_JA4_HEADER": "bad name"})), noFiles)
	if err == nil || !strings.Contains(err.Error(), "AILUROS_JA4_HEADER") {
		t.Errorf("bad name: %v", err)
	}
}

func TestJA4HeaderRejectsInspectedHeaders(t *testing.T) {
	for _, h := range []string{"transfer-encoding", "Content-Length", "host", "content-type", "connection", "upgrade", "authorization", "cookie", "X-Forwarded-For", "content-encoding", "grpc-encoding", "origin", "sec-websocket-key", "Sec-WebSocket-Version", "sec-websocket-protocol", "referer", "traceparent", "Tracestate", "baggage", ":authority", ":path"} {
		_, err := Load(env(required(map[string]string{"AILUROS_JA4_HEADER": h})), noFiles)
		if err == nil || !strings.Contains(err.Error(), "AILUROS_JA4_HEADER") {
			t.Errorf("%q: err %v, want an AILUROS_JA4_HEADER error", h, err)
		}
	}
}

func TestJA4HeaderRejectsEveryHeaderReadByName(t *testing.T) {
	read := regexp.MustCompile(`[Hh]eaders\["([A-Za-z0-9-]+)"\]`)
	found := map[string]bool{}
	err := filepath.WalkDir("..", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, m := range read.FindAllStringSubmatch(string(src), -1) {
			found[strings.ToLower(m[1])] = true
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(found) < 10 {
		t.Fatalf("found only %v: is the pattern still right?", found)
	}
	for h := range found {
		_, err := Load(env(required(map[string]string{"AILUROS_JA4_HEADER": h})), noFiles)
		if err == nil || !strings.Contains(err.Error(), "AILUROS_JA4_HEADER") {
			t.Errorf("%q is read by name but accepted as AILUROS_JA4_HEADER (err %v)", h, err)
		}
	}
}

func TestJA4HeaderDocListsInspectedHeaders(t *testing.T) {
	doc, err := os.ReadFile("../../docs/configuration.md")
	if err != nil {
		t.Fatal(err)
	}
	var row string
	for line := range strings.Lines(string(doc)) {
		if strings.HasPrefix(line, "| `AILUROS_JA4_HEADER`") {
			row = line
		}
	}
	for _, h := range inspect.InspectedHeaders() {
		if !strings.Contains(row, "`"+h+"`") {
			t.Errorf("the AILUROS_JA4_HEADER row does not list %q", h)
		}
	}
}

func TestJA4HeaderRejectsPropagatorFields(t *testing.T) {
	for _, p := range []propagation.TextMapPropagator{propagation.TraceContext{}, propagation.Baggage{}} {
		for _, h := range p.Fields() {
			_, err := Load(env(required(map[string]string{"AILUROS_JA4_HEADER": h})), noFiles)
			if err == nil || !strings.Contains(err.Error(), "AILUROS_JA4_HEADER") {
				t.Errorf("%q is a propagator field but accepted as AILUROS_JA4_HEADER (err %v)", h, err)
			}
		}
	}
}

func TestIntegerAndEnumMessages(t *testing.T) {
	cases := []struct{ name, value, want string }{
		{"AILUROS_BODY_MAX_BYTES", "0", "AILUROS_BODY_MAX_BYTES: must be a positive integer"},
		{"AILUROS_BODY_MAX_BYTES", "ten", "AILUROS_BODY_MAX_BYTES: must be a positive integer"},
		{"AILUROS_DEEP_MAX_BYTES", "-3", "AILUROS_DEEP_MAX_BYTES: must be a positive integer"},
		{"AILUROS_DEEP_MAX_BYTES", "99999999999999999999", "AILUROS_DEEP_MAX_BYTES: must be a positive integer"},
		{"AILUROS_DEEP_MAX_BYTES", "67108865", "AILUROS_DEEP_MAX_BYTES: must be at most 67108864 (64 MiB): deep mode holds up to this many bytes per stream"},
		{"AILUROS_DEEP_MAX_MESSAGES", "0", "AILUROS_DEEP_MAX_MESSAGES: must be an integer from 1 to 10000"},
		{"AILUROS_DEEP_MAX_MESSAGES", "10001", "AILUROS_DEEP_MAX_MESSAGES: must be an integer from 1 to 10000"},
		{"AILUROS_DEEP_MAX_MESSAGES", "x", "AILUROS_DEEP_MAX_MESSAGES: must be an integer from 1 to 10000"},
		{"AILUROS_INSPECTION_MODE", "full", "AILUROS_INSPECTION_MODE: "},
		{"AILUROS_FAILURE_MODE", "maybe", "AILUROS_FAILURE_MODE: "},
		{"AILUROS_BAD_OUTPUT", "x", "AILUROS_BAD_OUTPUT: "},
		{"AILUROS_DEEP_OVERSIZE", "drop", "AILUROS_DEEP_OVERSIZE: "},
	}
	for _, c := range cases {
		_, err := Load(env(required(map[string]string{c.name: c.value})), noFiles)
		if err == nil || !strings.HasPrefix(err.Error(), c.want) || strings.Contains(err.Error(), "\n") {
			t.Errorf("%s=%q: err = %v, want one error starting %q", c.name, c.value, err, c.want)
		}
	}
}
