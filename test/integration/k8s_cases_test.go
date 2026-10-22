//go:build k8s

package integration

import (
	"net/http"
	"strings"
	"testing"
)

func routeStripsJA4(t *testing.T, s *Stack) {
	t.Run("an HTTPRoute RequestHeaderModifier removes x-decision-waf-ja4 after decision-waf", func(t *testing.T) {
		m := newMarker(t)
		v := echoed(t, s.Get(t, "http1", "/ja4/"+m, http.Header{"X-Decision-Waf-Ja4": {"ja4-" + m}}))
		if got := v.Headers.Values("X-Decision-Waf-Ja4"); len(got) != 0 {
			t.Errorf("upstream saw x-decision-waf-ja4 %q", got)
		}
		if p := s.Prompts(t, m); len(p) != 1 || !strings.Contains(p[0], "ja4-"+m) {
			t.Errorf("prompts = %q, want one with the x-decision-waf-ja4 value", p)
		}
	})
}

func TestK8sLite(t *testing.T) {
	t.Parallel()
	s := upK8s(t, "lite")
	t.Run("http1", func(t *testing.T) { sharedCases(t, s, "http1") })
	routeStripsJA4(t, s)
	grpcUnaryCases(t, s)
	failClosedWhenDecisionWafDown(t, s, http.StatusInternalServerError, nil)
}

func TestK8sStandard(t *testing.T) {
	t.Parallel()
	s := upK8s(t, "standard")
	t.Run("http1", func(t *testing.T) { sharedCases(t, s, "http1") })
	routeStripsJA4(t, s)
	bodyCases(t, s)
	grpcUnaryCases(t, s)
	failClosedWhenDecisionWafDown(t, s, http.StatusInternalServerError, nil)
}

func TestK8sDeep(t *testing.T) {
	t.Parallel()
	s := upK8s(t, "deep")
	t.Run("http1", func(t *testing.T) { sharedCases(t, s, "http1") })
	routeStripsJA4(t, s)
	bodyCases(t, s)
	grpcUnaryCases(t, s)
	deepStreamCases(t, s)
	failClosedWhenDecisionWafDown(t, s, http.StatusInternalServerError, nil)
}

func TestK8sExtAuthz(t *testing.T) {
	t.Parallel()
	s := upK8s(t, "ext_authz")
	t.Run("http1", func(t *testing.T) { sharedCases(t, s, "http1") })
	routeStripsJA4(t, s)
	failClosedWhenDecisionWafDown(t, s, http.StatusInternalServerError, nil)
}
