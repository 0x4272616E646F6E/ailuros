package k8sconfig

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"maps"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	yaml "go.yaml.in/yaml/v3"

	"github.com/0x4272616E646F6E/ailuros/internal/app"
	"github.com/0x4272616E646F6E/ailuros/internal/config"
	"github.com/0x4272616E646F6E/ailuros/internal/frontend/extproc"
	"github.com/0x4272616E646F6E/ailuros/internal/policy"
)

const root = "../../deploy/kubernetes"

var proxyTimeoutMS = strconv.FormatInt((config.DefaultClassifierTimeout+config.ProxyTimeoutMargin).Milliseconds(), 10) + "ms"

func portOf(addr string) int {
	p, _ := strconv.Atoi(strings.TrimPrefix(addr, ":"))
	return p
}

type object = map[string]any

func render(t *testing.T, dir string) []object {
	t.Helper()
	if _, err := exec.LookPath("kubectl"); err != nil {
		t.Skip("kubectl not installed")
	}
	out, err := exec.Command("kubectl", "kustomize", filepath.Join(root, dir)).CombinedOutput()
	if err != nil {
		t.Fatalf("kubectl kustomize %s: %v\n%s", dir, err, out)
	}
	var objs []object
	dec := yaml.NewDecoder(bytes.NewReader(out))
	for {
		var o object
		if err := dec.Decode(&o); errors.Is(err, io.EOF) {
			return objs
		} else if err != nil {
			t.Fatalf("%s: %v", dir, err)
		}
		objs = append(objs, o)
	}
}

func get(v any, path ...any) any {
	for _, p := range path {
		switch k := p.(type) {
		case string:
			m, ok := v.(object)
			if !ok {
				return nil
			}
			v = m[k]
		case int:
			s, ok := v.([]any)
			if !ok || k >= len(s) {
				return nil
			}
			v = s[k]
		}
	}
	return v
}

func find(t *testing.T, objs []object, kind, name string) object {
	t.Helper()
	for _, o := range objs {
		if o["kind"] == kind && get(o, "metadata", "name") == name {
			return o
		}
	}
	t.Fatalf("no %s %q rendered", kind, name)
	return nil
}

func env(t *testing.T, deploy object, name string) any {
	t.Helper()
	list, _ := get(deploy, "spec", "template", "spec", "containers", 0, "env").([]any)
	for _, e := range list {
		if get(e, "name") == name {
			return get(e, "value")
		}
	}
	return nil
}

func TestOverlays(t *testing.T) {
	cases := []struct {
		overlay, mode, kind, body string
	}{
		{"lite", "lite", "EnvoyExtensionPolicy", ""},
		{"standard", "standard", "EnvoyExtensionPolicy", "BufferedPartial"},
		{"deep", "deep", "EnvoyExtensionPolicy", "FullDuplexStreamed"},
		{"ext_authz", "lite", "SecurityPolicy", ""},
	}
	for _, c := range cases {
		t.Run(c.overlay, func(t *testing.T) {
			objs := render(t, filepath.Join("overlays", c.overlay))
			d := find(t, objs, "Deployment", "ailuros")
			if got := env(t, d, "AILUROS_INSPECTION_MODE"); got != c.mode {
				t.Errorf("AILUROS_INSPECTION_MODE = %v, want %s", got, c.mode)
			}
			if got := env(t, d, "AILUROS_POLICY_FILE"); got != "/etc/ailuros/policy.yaml" {
				t.Errorf("AILUROS_POLICY_FILE = %v", got)
			}
			sc := get(d, "spec", "template", "spec", "containers", 0, "securityContext")
			if get(sc, "readOnlyRootFilesystem") != true || get(sc, "allowPrivilegeEscalation") != false {
				t.Errorf("container securityContext = %v", sc)
			}
			podSpec := get(d, "spec", "template", "spec")
			preStop, _ := get(podSpec, "containers", 0, "lifecycle", "preStop", "sleep", "seconds").(int)
			if preStop != 5 {
				t.Errorf("preStop sleep seconds = %v, want 5", preStop)
			}
			grace, _ := get(podSpec, "terminationGracePeriodSeconds").(int)
			if need := preStop + int(app.ShutdownTimeout.Seconds()); grace < need {
				t.Errorf("terminationGracePeriodSeconds = %v, want at least preStop %ds + shutdown %v = %ds", grace, preStop, app.ShutdownTimeout, need)
			}
			ts := get(podSpec, "topologySpreadConstraints", 0)
			if get(ts, "maxSkew") != 1 || get(ts, "topologyKey") != "kubernetes.io/hostname" ||
				get(ts, "whenUnsatisfiable") != "ScheduleAnyway" ||
				get(ts, "labelSelector", "matchLabels", "app.kubernetes.io/name") != "ailuros" {
				t.Errorf("topologySpreadConstraints[0] = %v", ts)
			}
			if got := get(find(t, objs, "Service", "ailuros"), "spec", "selector", "app.kubernetes.io/name"); got != "ailuros" {
				t.Errorf("Service selects %v, want app.kubernetes.io/name: ailuros", got)
			}
			if got := get(find(t, objs, "PodDisruptionBudget", "ailuros"), "spec", "selector", "matchLabels", "app.kubernetes.io/name"); got != "ailuros" {
				t.Errorf("PodDisruptionBudget selects %v, want app.kubernetes.io/name: ailuros", got)
			}
			p := find(t, objs, c.kind, "ailuros")
			if got := get(p, "spec", "targetRefs", 0, "name"); got != "eg" {
				t.Errorf("policy targets %v, want Gateway eg", got)
			}
			if c.kind == "SecurityPolicy" {
				ea := get(p, "spec", "extAuth")
				if env(t, d, "AILUROS_EXTAUTHZ_ADDR") != config.ConventionalExtAuthzAddr || get(ea, "grpc", "backendRefs", 0, "port") != portOf(config.ConventionalExtAuthzAddr) ||
					get(ea, "failOpen") != false || get(ea, "timeout") != proxyTimeoutMS || get(ea, "statusOnError") != 503 {
					t.Errorf("extAuth = %v (extauthz addr %v)", ea, env(t, d, "AILUROS_EXTAUTHZ_ADDR"))
				}
				return
			}
			ep := get(p, "spec", "extProc", 0)
			if get(ep, "backendRefs", 0, "name") != "ailuros" || get(ep, "backendRefs", 0, "port") != portOf(config.DefaultExtProcAddr) ||
				get(ep, "messageTimeout") != proxyTimeoutMS || get(ep, "failOpen") != false {
				t.Errorf("extProc = %v", ep)
			}
			body, _ := get(ep, "processingMode", "request", "body").(string)
			if body != c.body || get(ep, "processingMode", "response") != nil {
				t.Errorf("processingMode = %v, want request body %q and no response processing", get(ep, "processingMode"), c.body)
			}
			attrs, _ := get(ep, "processingMode", "request", "attributes").([]any)
			if got := fmt.Sprint(attrs); got != fmt.Sprint(extproc.RequestAttributes) {
				t.Errorf("request attributes = %v, want %v (extproc.RequestAttributes)", got, extproc.RequestAttributes)
			}
			if c.overlay == "deep" {
				b := find(t, objs, "BackendTrafficPolicy", "ailuros-deep-timeouts")
				if get(b, "spec", "timeout", "http", "streamIdleTimeout") != "30s" || get(b, "spec", "timeout", "http", "requestTimeout") != nil {
					t.Errorf("deep backend timeouts = %v, want streamIdleTimeout 30s and no requestTimeout", get(b, "spec", "timeout"))
				}
				ctp := find(t, objs, "ClientTrafficPolicy", "ailuros-deep-client-timeouts")
				if get(ctp, "spec", "timeout", "http", "requestReceivedTimeout") != "60s" || get(ctp, "spec", "targetRefs", 0, "name") != "eg" {
					t.Errorf("deep client timeouts = %v", get(ctp, "spec"))
				}
			}
		})
	}
}

func TestServicePorts(t *testing.T) {
	svc := find(t, render(t, "base"), "Service", "ailuros")
	want := map[string][2]any{
		"extproc":  {portOf(config.DefaultExtProcAddr), "kubernetes.io/h2c"},
		"extauthz": {portOf(config.ConventionalExtAuthzAddr), "kubernetes.io/h2c"},
		"metrics":  {portOf(config.DefaultMetricsAddr), nil},
	}
	ports, _ := get(svc, "spec", "ports").([]any)
	if len(ports) != len(want) {
		t.Fatalf("ports = %v", ports)
	}
	for _, p := range ports {
		w, ok := want[get(p, "name").(string)]
		if !ok || get(p, "port") != w[0] || get(p, "appProtocol") != w[1] {
			t.Errorf("port %v, want %v", p, w)
		}
	}
}

func TestAPIKeyComponent(t *testing.T) {
	objs := render(t, "examples/with-api-key")
	d := find(t, objs, "Deployment", "ailuros")
	if env(t, d, "AILUROS_CLASSIFIER_API_KEY_FILE") != "/etc/ailuros-secret/api-key" {
		t.Errorf("API key file env = %v", env(t, d, "AILUROS_CLASSIFIER_API_KEY_FILE"))
	}
	if get(d, "spec", "template", "spec", "containers", 0, "volumeMounts", 0, "mountPath") != "/etc/ailuros-secret" {
		t.Errorf("volumeMounts = %v", get(d, "spec", "template", "spec", "containers", 0, "volumeMounts"))
	}
	if get(d, "spec", "template", "spec", "volumes", 1, "secret", "secretName") != "ailuros-classifier" {
		t.Errorf("volumes = %v", get(d, "spec", "template", "spec", "volumes"))
	}
}

func TestNetworkPolicyComponent(t *testing.T) {
	objs := render(t, "examples/with-network-policy")
	np := find(t, objs, "NetworkPolicy", "ailuros")
	d := find(t, objs, "Deployment", "ailuros")
	if got := get(np, "spec", "podSelector", "matchLabels", "app.kubernetes.io/name"); got != get(d, "spec", "selector", "matchLabels", "app.kubernetes.io/name") {
		t.Errorf("podSelector selects name %v, not the Deployment's pods", got)
	}
	proxy := get(np, "spec", "ingress", 0, "from", 0)
	if get(proxy, "podSelector", "matchLabels", "app.kubernetes.io/managed-by") != "envoy-gateway" ||
		get(proxy, "podSelector", "matchLabels", "app.kubernetes.io/component") != "proxy" ||
		get(proxy, "namespaceSelector", "matchLabels", "kubernetes.io/metadata.name") != "envoy-gateway-system" {
		t.Errorf("gRPC ports admit %v, want Envoy Gateway proxy pods in envoy-gateway-system", proxy)
	}
	ports := map[any]bool{}
	for _, p := range get(np, "spec", "ingress", 0, "ports").([]any) {
		ports[get(p, "port")] = true
	}
	named := map[any]bool{}
	for _, p := range get(d, "spec", "template", "spec", "containers", 0, "ports").([]any) {
		named[get(p, "name")] = true
	}
	if !ports["extproc"] || !ports["extauthz"] || len(ports) != 2 || !named["extproc"] || !named["extauthz"] || !named["metrics"] {
		t.Errorf("gRPC rule ports %v, container ports %v", ports, named)
	}
	if get(np, "spec", "ingress", 1, "ports", 0, "port") != "metrics" || get(np, "spec", "ingress", 1, "from") != nil {
		t.Errorf("metrics rule = %v, want metrics open to all", get(np, "spec", "ingress", 1))
	}
}

func TestMixedModes(t *testing.T) {
	objs := render(t, "examples/mixed-modes")
	for _, mode := range []string{"lite", "deep"} {
		name := "ailuros-" + mode
		p := find(t, objs, "EnvoyExtensionPolicy", name)
		if got := get(p, "spec", "extProc", 0, "backendRefs", 0, "name"); got != name {
			t.Errorf("%s policy references Service %v, want %s", mode, got, name)
		}
		if got := get(p, "spec", "targetRefs", 0, "kind"); got != "HTTPRoute" {
			t.Errorf("%s policy targets a %v, want an HTTPRoute (two policies on one Gateway would both apply)", mode, got)
		}
		svc := find(t, objs, "Service", name)
		if got := get(svc, "spec", "selector", "app.kubernetes.io/instance"); got != mode {
			t.Errorf("Service %s selects instance %v, want %s", name, got, mode)
		}
		d := find(t, objs, "Deployment", name)
		if get(d, "spec", "selector", "matchLabels", "app.kubernetes.io/instance") != mode ||
			get(d, "spec", "template", "metadata", "labels", "app.kubernetes.io/instance") != mode {
			t.Errorf("Deployment %s is not labelled instance=%s", name, mode)
		}
		if env(t, d, "AILUROS_INSPECTION_MODE") != mode {
			t.Errorf("Deployment %s mode = %v", name, env(t, d, "AILUROS_INSPECTION_MODE"))
		}
		if got := get(d, "spec", "template", "spec", "topologySpreadConstraints", 0, "labelSelector", "matchLabels", "app.kubernetes.io/instance"); got != mode {
			t.Errorf("Deployment %s spreads over instance %v, want %s", name, got, mode)
		}
		vol := get(d, "spec", "template", "spec", "volumes", 0, "configMap", "name")
		if vol != "ailuros-policy-"+mode {
			t.Errorf("Deployment %s mounts ConfigMap %v, want ailuros-policy-%s", name, vol, mode)
		}
	}
	b := find(t, objs, "BackendTrafficPolicy", "ailuros-deep-timeouts-deep")
	if get(b, "spec", "targetRefs", 0, "kind") != "HTTPRoute" || get(b, "spec", "targetRefs", 0, "name") != "app-deep" {
		t.Errorf("deep BackendTrafficPolicy targets %v, want HTTPRoute app-deep", get(b, "spec", "targetRefs"))
	}
}

func TestBasePolicySetsNoSection(t *testing.T) {
	cm := find(t, render(t, "base"), "ConfigMap", "ailuros-policy")
	data, ok := get(cm, "data", "policy.yaml").(string)
	if !ok {
		t.Fatalf("ailuros-policy has no policy.yaml: %v", get(cm, "data"))
	}
	var sections map[string]any
	if err := yaml.Unmarshal([]byte(data), &sections); err != nil {
		t.Fatal(err)
	}
	if len(sections) != 0 {
		t.Errorf("base policy.yaml sets %v; set nothing so the built-in defaults apply and follow releases", slices.Sorted(maps.Keys(sections)))
	}
	p, err := policy.Parse([]byte(data))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(p, policy.Default()) {
		t.Errorf("base policy parses to %+v, want policy.Default()", p)
	}
}

func TestIntegrationPolicyKeepsDefaultRedactedHeaders(t *testing.T) {
	p, err := policy.Load("../integration/k8s/common/policy.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range policy.DefaultRedact().Headers {
		if !slices.Contains(p.Redact.Headers, h) {
			t.Errorf("test/integration/k8s/common/policy.yaml redact.headers drops the built-in %q", h)
		}
	}
}
