package main

import (
	"os/exec"
	"strings"
	"testing"
)

func TestNoServerDependencies(t *testing.T) {
	gobin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go not on PATH")
	}
	out, err := exec.Command(gobin, "list", "-deps", ".").Output()
	if err != nil {
		t.Fatalf("go list -deps: %v", err)
	}
	for _, pkg := range strings.Fields(string(out)) {
		for _, banned := range []string{
			"github.com/0x4272616E646F6E/decision-waf/internal/app",
			"github.com/0x4272616E646F6E/decision-waf/internal/frontend",
			"google.golang.org/grpc",
		} {
			if pkg == banned || strings.HasPrefix(pkg, banned+"/") {
				t.Errorf("ailuros-eval depends on %s", pkg)
			}
		}
	}
}
