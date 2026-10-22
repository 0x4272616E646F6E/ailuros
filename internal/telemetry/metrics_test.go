package telemetry

import (
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/0x4272616E646F6E/decision-waf/internal/classifier"
)

func TestMetricsHandlerExposesSeries(t *testing.T) {
	m := NewMetrics()
	m.BreakerChanged("jev", classifier.BreakerOpen)
	m.Downgrade("forwardauth")
	m.PolicyReload(true)
	m.PolicyReload(false)

	rr := httptest.NewRecorder()
	m.Handler().ServeHTTP(rr, httptest.NewRequest("GET", "/metrics", nil))
	body, _ := io.ReadAll(rr.Body)
	for _, want := range []string{
		`decision_waf_circuit_breaker_state{backend="jev"} 2`,
		`decision_waf_mode_downgrades_total{frontend="forwardauth"} 1`,
		`decision_waf_policy_reloads_total{result="success"} 1`,
		`decision_waf_policy_reloads_total{result="failure"} 1`,
		`go_goroutines`,
	} {
		if !strings.Contains(string(body), want) {
			t.Errorf("metrics missing %q", want)
		}
	}
}
