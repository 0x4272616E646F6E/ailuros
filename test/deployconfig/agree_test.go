package deployconfig

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
)

var (
	ailurosFilter  = regexp.MustCompile(`^(\s*)- name: envoy\.filters\.http\.(ext_proc|ext_authz)$`)
	ailurosAddress = regexp.MustCompile(`(address: ailuros, port_value: )\d+`)
)

type line struct {
	n    int
	text string
}

func commonPart(name string, data []byte) []line {
	var lines []line
	for i, text := range strings.Split(string(data), "\n") {
		lines = append(lines, line{i + 1, text})
	}
	for len(lines) > 0 && strings.HasPrefix(lines[0].text, "#") {
		lines = lines[1:]
	}
	var out []line
	for i := 0; i < len(lines); i++ {
		l := lines[i]
		if m := ailurosFilter.FindStringSubmatch(l.text); m != nil {
			out = append(out, line{l.n, m[1] + "- (the Ailuros filter)"})
			for i+1 < len(lines) && strings.HasPrefix(lines[i+1].text, m[1]+"  ") {
				i++
			}
			continue
		}
		if name == "deep.yaml" {
			t := strings.TrimSpace(l.text)
			if strings.HasPrefix(t, "request_timeout:") {
				for len(out) > 0 && strings.HasPrefix(strings.TrimSpace(out[len(out)-1].text), "#") {
					out = out[:len(out)-1]
				}
				continue
			}
			if strings.HasPrefix(t, "stream_idle_timeout:") {
				continue
			}
		}
		out = append(out, line{l.n, ailurosAddress.ReplaceAllString(l.text, "${1}(port)")})
	}
	return out
}

func extProcFilter(data []byte) []line {
	var out []line
	in := ""
	for i, text := range strings.Split(string(data), "\n") {
		if m := ailurosFilter.FindStringSubmatch(text); m != nil {
			in = m[1]
		} else if in == "" || !strings.HasPrefix(text, in+"  ") {
			in = ""
			continue
		}
		if t := strings.TrimSpace(text); strings.HasPrefix(t, "request_body_mode:") || strings.HasPrefix(t, "request_trailer_mode:") {
			continue
		}
		out = append(out, line{i + 1, text})
	}
	return out
}

func firstDiff(name string, got, want []line) string {
	for i := range max(len(got), len(want)) {
		var g, w line
		if i < len(got) {
			g = got[i]
		}
		if i < len(want) {
			w = want[i]
		}
		if g.text != w.text {
			return fmt.Sprintf("deploy/envoy/%s:%d differs from deploy/envoy/standard.yaml:%d:\n  %-15s %s\n  %-15s %s\n"+
				"Apply the same change to every deploy/envoy/*.yaml, or, if the difference belongs to the mode, strip it in commonPart or extProcFilter (test/deployconfig/agree_test.go).",
				name, g.n, w.n, name+":", g.text, "standard.yaml:", w.text)
		}
	}
	return ""
}

func TestEnvoyConfigsAgreeOutsideTheirMode(t *testing.T) {
	want := commonPart("standard.yaml", readEnvoyConfig(t, "standard.yaml"))
	if len(want) < 50 {
		t.Fatalf("standard.yaml's common part has %d lines; the header or filter detection is broken", len(want))
	}
	for _, name := range envoyConfigs {
		if d := firstDiff(name, commonPart(name, readEnvoyConfig(t, name)), want); d != "" {
			t.Errorf("outside its mode-specific parts, %s", d)
		}
	}
}

func TestExtProcFiltersAgreeOutsideTheirMode(t *testing.T) {
	want := extProcFilter(readEnvoyConfig(t, "standard.yaml"))
	if len(want) < 10 {
		t.Fatalf("standard.yaml's ext_proc filter has %d lines; filter detection is broken", len(want))
	}
	for _, name := range []string{"lite.yaml", "deep.yaml"} {
		if d := firstDiff(name, extProcFilter(readEnvoyConfig(t, name)), want); d != "" {
			t.Errorf("in the ext_proc filter, outside the body and trailer modes, %s", d)
		}
	}
}
