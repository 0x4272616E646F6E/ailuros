package deployconfig

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	yaml "go.yaml.in/yaml/v3"
)

var envoyConfigs = []string{"lite.yaml", "standard.yaml", "deep.yaml", "ext_authz.yaml"}

var ja4BlockStart = regexp.MustCompile(`^(\s*)# (listener_filters:|- name: envoy\.filters\.http\.header_mutation)$`)

func uncommentJA4(data []byte) ([]byte, error) {
	lines := strings.Split(string(data), "\n")
	blocks := 0
	for i := 0; i < len(lines); i++ {
		m := ja4BlockStart.FindStringSubmatch(lines[i])
		if m == nil {
			continue
		}
		blocks++
		indent := m[1]
		lines[i] = indent + m[2]
		for i+1 < len(lines) && strings.HasPrefix(lines[i+1], indent+"#   ") {
			i++
			lines[i] = indent + strings.TrimPrefix(lines[i], indent+"# ")
		}
	}
	if blocks != 2 {
		return nil, fmt.Errorf("found %d commented JA4 blocks, want 2 (listener_filters and header_mutation)", blocks)
	}
	return []byte(strings.Join(lines, "\n")), nil
}

func readEnvoyConfig(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile("../../deploy/envoy/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

type ja4Config struct {
	StaticResources struct {
		Listeners []struct {
			ListenerFilters []struct {
				Name        string `yaml:"name"`
				TypedConfig struct {
					EnableJA4 bool `yaml:"enable_ja4_fingerprinting"`
				} `yaml:"typed_config"`
			} `yaml:"listener_filters"`
			FilterChains []struct {
				Filters []struct {
					TypedConfig struct {
						HTTPFilters []struct {
							Name        string `yaml:"name"`
							TypedConfig struct {
								Mutations struct {
									RequestMutations []struct {
										Append struct {
											Header struct {
												Key   string `yaml:"key"`
												Value string `yaml:"value"`
											} `yaml:"header"`
											AppendAction string `yaml:"append_action"`
										} `yaml:"append"`
									} `yaml:"request_mutations"`
								} `yaml:"mutations"`
							} `yaml:"typed_config"`
						} `yaml:"http_filters"`
					} `yaml:"typed_config"`
				} `yaml:"filters"`
			} `yaml:"filter_chains"`
		} `yaml:"listeners"`
	} `yaml:"static_resources"`
}

func TestJA4BlockUncommented(t *testing.T) {
	for _, name := range envoyConfigs {
		t.Run(name, func(t *testing.T) {
			data, err := uncommentJA4(readEnvoyConfig(t, name))
			if err != nil {
				t.Fatal(err)
			}
			var cfg ja4Config
			if err := yaml.Unmarshal(data, &cfg); err != nil {
				t.Fatalf("uncommented config does not parse: %v", err)
			}
			if len(cfg.StaticResources.Listeners) != 1 {
				t.Fatalf("%d listeners, want 1", len(cfg.StaticResources.Listeners))
			}
			l := cfg.StaticResources.Listeners[0]
			if len(l.ListenerFilters) != 1 || l.ListenerFilters[0].Name != "envoy.filters.listener.tls_inspector" || !l.ListenerFilters[0].TypedConfig.EnableJA4 {
				t.Errorf("listener_filters = %+v, want the tls_inspector with enable_ja4_fingerprinting", l.ListenerFilters)
			}
			if len(l.FilterChains) != 1 || len(l.FilterChains[0].Filters) != 1 {
				t.Fatalf("want one filter chain with one filter, got %+v", l.FilterChains)
			}
			filters := l.FilterChains[0].Filters[0].TypedConfig.HTTPFilters
			var names []string
			for _, f := range filters {
				names = append(names, f.Name)
			}
			ailuros := "envoy.filters.http.ext_proc"
			if name == "ext_authz.yaml" {
				ailuros = "envoy.filters.http.ext_authz"
			}
			if want := []string{"envoy.filters.http.header_mutation", ailuros, "envoy.filters.http.router"}; strings.Join(names, " ") != strings.Join(want, " ") {
				t.Fatalf("http_filters = %v, want %v", names, want)
			}
			muts := filters[0].TypedConfig.Mutations.RequestMutations
			if len(muts) != 1 {
				t.Fatalf("header_mutation has %d request mutations, want 1", len(muts))
			}
			a := muts[0].Append
			if a.Header.Key != "x-ailuros-ja4" || a.Header.Value != "%TLS_JA4_FINGERPRINT%" || a.AppendAction != "OVERWRITE_IF_EXISTS_OR_ADD" {
				t.Errorf("mutation = %+v, want x-ailuros-ja4 overwritten with %%TLS_JA4_FINGERPRINT%%", a)
			}
		})
	}
}

func TestJA4BlocksAreIdentical(t *testing.T) {
	blocks := map[string]string{}
	for _, name := range envoyConfigs {
		orig := strings.Split(string(readEnvoyConfig(t, name)), "\n")
		unc, err := uncommentJA4(readEnvoyConfig(t, name))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var changed []string
		for i, line := range strings.Split(string(unc), "\n") {
			if line != orig[i] {
				changed = append(changed, line)
			}
		}
		blocks[name] = strings.Join(changed, "\n")
	}
	for _, name := range envoyConfigs[1:] {
		if blocks[name] != blocks[envoyConfigs[0]] {
			t.Errorf("%s's JA4 block differs from %s's:\n%s\n---\n%s", name, envoyConfigs[0], blocks[name], blocks[envoyConfigs[0]])
		}
	}
}

func TestEnvoyValidates(t *testing.T) {
	image := os.Getenv("AILUROS_ENVOY_IMAGE")
	if image == "" {
		t.Skip("set AILUROS_ENVOY_IMAGE (make validate-envoy) to validate with Envoy")
	}
	dir := t.TempDir()
	for _, name := range envoyConfigs {
		shipped := readEnvoyConfig(t, name)
		ja4, err := uncommentJA4(shipped)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for variant, data := range map[string][]byte{"shipped": shipped, "with JA4 uncommented": ja4} {
			t.Run(name+" "+variant, func(t *testing.T) {
				path := filepath.Join(dir, strings.ReplaceAll(variant, " ", "-")+"-"+name)
				if err := os.WriteFile(path, data, 0o644); err != nil {
					t.Fatal(err)
				}
				var out bytes.Buffer
				cmd := exec.Command("docker", "run", "--rm", "-v", path+":/cfg.yaml:ro", image, "--mode", "validate", "-c", "/cfg.yaml")
				cmd.Stdout, cmd.Stderr = &out, &out
				if err := cmd.Run(); err != nil {
					t.Fatalf("envoy --mode validate: %v\n%s", err, out.String())
				}
			})
		}
	}
}
