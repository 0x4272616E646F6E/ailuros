//go:build integration

package integration

import (
	"net/http"
	"testing"
)

func TestEnvoyExtAuthz(t *testing.T) {
	t.Parallel()
	s := up(t, "envoy-extauthz", nil)
	t.Run("http1", func(t *testing.T) { sharedCases(t, s, "http1") })

	t.Run("denial carries the request ID header and JSON body", func(t *testing.T) {
		m := newMarker(t)
		resp := s.Get(t, "http1", "/search/"+m+"?q=attack", nil)
		id := wantDeny(t, resp, http.StatusForbidden, "request blocked")
		if d := s.WantDecision(t, id, "block", ""); d.Str("frontend") != "extauthz" {
			t.Errorf("frontend = %q, want extauthz", d.Str("frontend"))
		}
	})

	failClosedWhenDecisionWafDown(t, s, http.StatusServiceUnavailable, nil)
}
