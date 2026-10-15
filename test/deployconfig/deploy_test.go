package deployconfig

import (
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/0x4272616E646F6E/ailuros/internal/config"
	"github.com/0x4272616E646F6E/ailuros/internal/frontend/extproc"
)

var proxyTimeout = config.DefaultClassifierTimeout + config.ProxyTimeoutMargin

func port(addr string) string { return strings.TrimPrefix(addr, ":") }

func TestShippedEnvoyConfigsMatchModes(t *testing.T) {
	timeout := proxyTimeout.String()
	cases := map[string][]string{
		"lite.yaml":     {"request_body_mode: NONE", "message_timeout: " + timeout},
		"standard.yaml": {"request_body_mode: BUFFERED_PARTIAL", "message_timeout: " + timeout},
		"deep.yaml": {"request_body_mode: FULL_DUPLEX_STREAMED", "request_trailer_mode: SEND", "message_timeout: " + timeout,
			"request_timeout: 60s", "stream_idle_timeout: 30s"},
		"ext_authz.yaml": {"envoy.filters.http.ext_authz", "timeout: " + timeout, "include_tls_session: true",
			"status_on_error: { code: ServiceUnavailable }",
			"port_value: " + port(config.ConventionalExtAuthzAddr)},
	}
	extProc := []string{
		"envoy.filters.http.ext_proc",
		"response_header_mode: SKIP", "response_body_mode: NONE", "response_trailer_mode: SKIP",
		"port_value: " + port(config.DefaultExtProcAddr),
	}
	for name, want := range cases {
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile("../../deploy/envoy/" + name)
			if err != nil {
				t.Fatal(err)
			}
			if name != "ext_authz.yaml" {
				want = append(want, extProc...)
				if got := requestAttributes(string(data)); !slices.Equal(got, extproc.RequestAttributes) {
					t.Errorf("%s request_attributes = %v, want %v (extproc.RequestAttributes)", name, got, extproc.RequestAttributes)
				}
			}
			for _, w := range append(want, "failure_mode_allow: false", "grpc_health_check", "use_remote_address: true", "cidr_ranges: [{ address_prefix: 192.0.2.255, prefix_len: 32 }]") {
				if !strings.Contains(string(data), w) {
					t.Errorf("%s does not contain %q", name, w)
				}
			}
		})
	}
}

func requestAttributes(cfg string) []string {
	var attrs []string
	in := false
	for _, line := range strings.Split(cfg, "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case trimmed == "request_attributes:":
			in = true
		case in && strings.HasPrefix(trimmed, "- "):
			attrs = append(attrs, strings.TrimPrefix(trimmed, "- "))
		case in:
			return attrs
		}
	}
	return attrs
}

func TestShippedNginxConfigBoundsAuthTimeouts(t *testing.T) {
	data, err := os.ReadFile("../../deploy/nginx/nginx.conf")
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range []string{"proxy_connect_timeout 1s;", "proxy_read_timeout " + ms(proxyTimeout) + ";", "resolver_timeout 1s;"} {
		if !strings.Contains(string(data), w) {
			t.Errorf("nginx.conf does not contain %q", w)
		}
	}
}

func ms(d time.Duration) string {
	return strconv.FormatInt(d.Milliseconds(), 10) + "ms"
}

func TestDockerfileExposesEveryListener(t *testing.T) {
	data, err := os.ReadFile("../../Dockerfile")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^EXPOSE (.+)$`).FindSubmatch(data)
	if m == nil {
		t.Fatal("Dockerfile has no EXPOSE line")
	}
	exposed := strings.Fields(string(m[1]))
	for _, addr := range []string{config.DefaultExtProcAddr, config.DefaultForwardAuthAddr, config.DefaultMetricsAddr, config.ConventionalExtAuthzAddr} {
		if !slices.Contains(exposed, port(addr)) {
			t.Errorf("Dockerfile EXPOSE %v lacks %s", exposed, port(addr))
		}
	}
}

func TestForwardAuthConfigsUseTheDefaultPort(t *testing.T) {
	want := "ailuros:" + port(config.DefaultForwardAuthAddr)
	for _, f := range []string{"nginx/nginx.conf", "traefik/dynamic.yml"} {
		data, err := os.ReadFile("../../deploy/" + f)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(data), want) {
			t.Errorf("deploy/%s does not contain %q", f, want)
		}
	}
}
