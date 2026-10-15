package pins

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const root = "../.."

func read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, path))
	if err != nil {
		t.Fatal(err)
	}
	var keep []string
	for _, line := range strings.Split(string(b), "\n") {
		if !regexp.MustCompile(`^- \d{4}-\d{2}-\d{2}:`).MatchString(line) {
			keep = append(keep, line)
		}
	}
	return strings.Join(keep, "\n")
}

func one(t *testing.T, path, pattern string) string {
	t.Helper()
	m := regexp.MustCompile(pattern).FindStringSubmatch(read(t, path))
	if m == nil {
		t.Fatalf("%s: no match for %s", path, pattern)
	}
	return m[1]
}

func every(t *testing.T, path, pattern, want string) {
	t.Helper()
	ms := regexp.MustCompile(pattern).FindAllStringSubmatch(read(t, path), -1)
	if len(ms) == 0 {
		t.Errorf("%s: no match for %s", path, pattern)
	}
	for _, m := range ms {
		if m[1] != want {
			t.Errorf("%s: %q says %s, want %s", path, m[0], m[1], want)
		}
	}
}

func TestEnvoyVersion(t *testing.T) {
	envoy := one(t, "Makefile", `(?m)^ENVOY_IMAGE \?= envoyproxy/envoy:v(\S+)$`)
	every(t, "test/integration/compose/envoy-common.yaml", `image: envoyproxy/envoy:v(\S+)`, envoy)
	for _, f := range []string{"envoy-lite", "envoy-standard", "envoy-deep", "envoy-extauthz"} {
		if strings.Contains(read(t, "test/integration/compose/"+f+".yaml"), "image:") {
			t.Errorf("%s.yaml sets its own image; extend envoy-common.yaml instead", f)
		}
	}
	every(t, "docs/envoy.md", `tested with (\d+\.\d+\.\d+)`, envoy)
}

func TestEnvoyGatewayAndKubernetesVersions(t *testing.T) {
	eg := one(t, "test/integration/k8s_test.go", `egVersion\s*= "v([\d.]+)"`)
	k8s := one(t, "test/integration/k8s_test.go", `kindest/node:v([\d.]+)@`)
	every(t, "docs/kubernetes.md", `Envoy Gateway v([\d.]+)`, eg)
	every(t, "docs/kubernetes.md", `Kubernetes\s+v([\d.]+)`, k8s)
	every(t, "docs/design/kubernetes.md", `\(v([\d.]+) on Kubernetes v[\d.]+ in kind\)`, eg)
	every(t, "docs/design/kubernetes.md", `on Kubernetes v([\d.]+) in kind`, k8s)
	every(t, "CONTRIBUTING.md", `installs Envoy Gateway v([\d.]+)`, eg)
	every(t, ".github/workflows/ci.yml", `-kubernetes-version ([\d.]+)`, k8s)
}

func TestBaseImages(t *testing.T) {
	from := regexp.MustCompile(`(?m)^FROM (?:--platform=\S+ )?([^:@\s]+)(\S*)`)
	seen := map[string]string{}
	where := map[string]string{}
	for _, f := range []string{"Dockerfile", "test/integration/Dockerfile"} {
		ms := from.FindAllStringSubmatch(read(t, f), -1)
		if len(ms) == 0 {
			t.Fatalf("%s: no FROM lines", f)
		}
		for _, m := range ms {
			image, ref := m[1], m[2]
			if !strings.Contains(ref, "@sha256:") {
				t.Errorf("%s: FROM %s%s is not pinned by digest", f, image, ref)
			}
			if prev, ok := seen[image]; ok && prev != ref {
				t.Errorf("%s: FROM %s%s, but %s uses %s%s; update the image in both Dockerfile and test/integration/Dockerfile", f, image, ref, where[image], image, prev)
			}
			seen[image], where[image] = ref, f
		}
	}
}
