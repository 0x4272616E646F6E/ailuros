//go:build integration

package integration

import (
	"net/http"
	"testing"
)

func TestEnvoyLite(t *testing.T) {
	t.Parallel()
	s := up(t, "envoy-lite", nil)
	t.Run("http1", func(t *testing.T) { sharedCases(t, s, "http1") })
	t.Run("h2c", func(t *testing.T) { sharedCases(t, s, "h2c") })

	t.Run("a malformed model reply fails open", func(t *testing.T) {
		defer settle(t, s, "http1")
		m := newMarker(t)
		v := echoed(t, s.Get(t, "http1", "/items/"+m+"/stub-garbage", nil))
		s.WantDecision(t, upstreamID(t, v), "fail_open", "bad_response")
	})

	t.Run("an answer outside the label set is blocked", func(t *testing.T) {
		m := newMarker(t)
		id := wantDeny(t, s.Get(t, "http1", "/items/"+m+"/stub-offformat", nil), http.StatusForbidden, "request blocked")
		s.WantDecision(t, id, "block", "bad_output")
		if seen := s.Seen(t, m); len(seen) != 0 {
			t.Errorf("echo received the request: %+v", seen)
		}
	})

	grpcUnaryCases(t, s)

	failClosedWhenAilurosDown(t, s, http.StatusInternalServerError, nil)
}
