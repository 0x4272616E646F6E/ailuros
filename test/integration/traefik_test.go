//go:build integration

package integration

import (
	"net/http"
	"strings"
	"testing"
)

func TestTraefik(t *testing.T) {
	t.Parallel()
	s := up(t, "traefik", nil)
	t.Run("http1", func(t *testing.T) { sharedCases(t, s, "http1") })

	t.Run("ForwardAuth headers describe the original request", func(t *testing.T) {
		m := newMarker(t)
		v := echoed(t, s.Send(t, "http1", Request{Method: "PUT", Path: "/orders/" + m + "?id=7"}))
		d := s.WantDecision(t, upstreamID(t, v), "allow", "")
		if d.Str("method") != "PUT" || d.Str("path") != "/orders/"+m || d.Str("host") != "app.example.com" || d.Str("frontend") != "forwardauth" {
			t.Errorf("decision = %v, want PUT app.example.com/orders/%s via forwardauth", d, m)
		}
		prompts := s.Prompts(t, m)
		if len(prompts) != 1 || !strings.Contains(prompts[0], "query: id=7") {
			t.Errorf("prompts = %q, want one prompt with the query", prompts)
		}
	})

	t.Run("client-forged X-Real-IP is ignored", func(t *testing.T) {
		m := newMarker(t)
		peer := s.Decision(t, upstreamID(t, echoed(t, s.Get(t, "http1", "/peer/"+m, nil)))).Str("client_ip")
		v := echoed(t, s.Get(t, "http1", "/real-ip/"+m, http.Header{"X-Real-Ip": {forgedIP}}))
		if ip := s.Decision(t, upstreamID(t, v)).Str("client_ip"); ip != peer || ip == forgedIP {
			t.Errorf("client_ip = %q, want the real peer %q", ip, peer)
		}
	})

	failClosedWhenAilurosDown(t, s, http.StatusInternalServerError, nil)
}
