package policy

import (
	"testing"

	"github.com/0x4272616E646F6E/decision-waf/internal/inspect"
)

func ptr(f float64) *float64 { return &f }

var defaults = Defaults{Threshold: 0.8, FailureMode: FailOpen}

func TestResolveDefaults(t *testing.T) {
	res := Default().Resolve(&inspect.Request{Path: "/"}, defaults)
	if res.Route != "default" || res.FailureMode != FailOpen || res.Threshold() != 0.8 {
		t.Errorf("Resolve = %+v (threshold %v)", res, res.Threshold())
	}
}

func TestResolvePrecedence(t *testing.T) {
	p := &Policy{
		Categories: []Category{{Name: "sqli"}, {Name: "scanner"}},
		Routes: []Route{
			{Match: Match{PathPrefix: "/admin"}, FailureMode: FailClosed},
			{Match: Match{PathPrefix: "/api"}, Threshold: ptr(0.5)},
		},
	}
	if res := p.Resolve(&inspect.Request{Path: "/"}, defaults); res.Threshold() != 0.8 {
		t.Errorf("no route: threshold = %v, want global 0.8", res.Threshold())
	}
	res := p.Resolve(&inspect.Request{Path: "/admin/users"}, defaults)
	if res.Route != "0" || res.FailureMode != FailClosed || res.Threshold() != 0.8 {
		t.Errorf("/admin: %+v threshold=%v, want closed with global threshold 0.8", res, res.Threshold())
	}
	res = p.Resolve(&inspect.Request{Path: "/api/x"}, defaults)
	if res.Route != "1" || res.FailureMode != FailOpen || res.Threshold() != 0.5 {
		t.Errorf("/api: %+v threshold=%v, want route threshold 0.5", res, res.Threshold())
	}
}

func TestResolveFirstMatchWins(t *testing.T) {
	p := &Policy{Routes: []Route{
		{Match: Match{PathPrefix: "/"}, Threshold: ptr(0.9)},
		{Match: Match{PathPrefix: "/admin"}, Threshold: ptr(0.1)},
	}}
	if got := p.Resolve(&inspect.Request{Path: "/admin"}, defaults).Route; got != "0" {
		t.Errorf("Route = %q, want 0", got)
	}
}

func TestResolveMatchesAllFields(t *testing.T) {
	p := &Policy{Routes: []Route{{Match: Match{Host: "api.example.com", GRPCService: "payments.v1.Payments"}}}}
	if got := p.Resolve(&inspect.Request{Host: "api.example.com", Path: "/x"}, defaults).Route; got != "default" {
		t.Errorf("host only: Route = %q, want default", got)
	}
	r := &inspect.Request{Host: "api.example.com", GRPCService: "payments.v1.Payments", GRPCMethod: "Charge"}
	if got := p.Resolve(r, defaults).Route; got != "0" {
		t.Errorf("host+grpc: Route = %q, want 0", got)
	}
}

func TestResolveNormalizesBypassAttempts(t *testing.T) {
	p := &Policy{Routes: []Route{{Match: Match{Host: "api.example.com", PathPrefix: "/admin"}, FailureMode: FailClosed}}}
	cases := []struct{ host, path string }{
		{"api.example.com", "/admin"},
		{"API.Example.com:8443", "/admin/users"},
		{"api.example.com.", "/admin"},
		{"api.example.com", "//admin"},
		{"api.example.com", "/./admin"},
		{"api.example.com", "/public/../admin"},
		{"api.example.com", "/%61dmin"},
		{"api.example.com", "/%61dmin/%zz"},
		{"api.example.com", "/%61dmin/x%"},
	}
	for _, c := range cases {
		if got := p.Resolve(&inspect.Request{Host: c.host, Path: c.path}, defaults).Route; got != "0" {
			t.Errorf("host=%q path=%q: Route = %q, want 0", c.host, c.path, got)
		}
	}
}

func TestResolveDecodesOnce(t *testing.T) {
	p := &Policy{Routes: []Route{{Match: Match{PathPrefix: "/admin"}, FailureMode: FailClosed}}}
	if got := p.Resolve(&inspect.Request{Path: "/%2561dmin"}, defaults).Route; got != "default" {
		t.Errorf("double-encoded: Route = %q, want default", got)
	}
}

func TestResolveEncodedSlashTakesTheStricterReading(t *testing.T) {
	p := &Policy{Routes: []Route{
		{Match: Match{PathPrefix: "/admin"}, Threshold: ptr(0.2), FailureMode: FailClosed},
		{Match: Match{PathPrefix: "/public/"}, Threshold: ptr(1), FailureMode: FailOpen},
	}}
	for _, path := range []string{"/admin%2F..%2Fpublic/x", "/admin%2f..%2fpublic/x", "/admin%5C..%5Cpublic/x"} {
		res := p.Resolve(&inspect.Request{Path: path}, defaults)
		if res.Threshold() != 0.2 || res.FailureMode != FailClosed {
			t.Errorf("%s: threshold %v, %s; want the /admin route's 0.2 and closed", path, res.Threshold(), res.FailureMode)
		}
	}
	res := p.Resolve(&inspect.Request{Path: "/public%2F..%2Fadmin/x"}, defaults)
	if res.Threshold() != 0.2 || res.FailureMode != FailClosed {
		t.Errorf("decoded into /admin: threshold %v, %s; want 0.2 and closed", res.Threshold(), res.FailureMode)
	}
}

func TestResolvePrefixMatchesSegments(t *testing.T) {
	for _, prefix := range []string{"/public", "/public/"} {
		p := &Policy{Routes: []Route{{Match: normalizeMatch(Match{PathPrefix: prefix}), Threshold: ptr(1)}}}
		for path, want := range map[string]string{
			"/public": "0", "/public/": "0", "/public/x": "0",
			"/public-admin/delete": "default", "/publicity": "default", "/": "default",
		} {
			if got := p.Resolve(&inspect.Request{Path: path}, defaults).Route; got != want {
				t.Errorf("prefix %q, path %q: Route = %q, want %s", prefix, path, got, want)
			}
		}
	}
	root := &Policy{Routes: []Route{{Match: normalizeMatch(Match{PathPrefix: "/"})}}}
	if got := root.Resolve(&inspect.Request{Path: "/anything"}, defaults).Route; got != "0" {
		t.Errorf("prefix /: Route = %q, want 0", got)
	}
}

func TestResolveIPv6Host(t *testing.T) {
	for _, routeHost := range []string{"[::1]", "[::1]:8443"} {
		p := &Policy{Routes: []Route{{Match: normalizeMatch(Match{Host: routeHost})}}}
		for _, host := range []string{"[::1]", "[::1]:8443", "[::1]:80"} {
			if got := p.Resolve(&inspect.Request{Host: host, Path: "/"}, defaults).Route; got != "0" {
				t.Errorf("route %q, host %q: Route = %q, want 0", routeHost, host, got)
			}
		}
	}
}

func TestResolveStrictRouteCoversPrefixVariants(t *testing.T) {
	p := &Policy{Routes: []Route{
		{Match: normalizeMatch(Match{PathPrefix: "/admin"}), Threshold: ptr(0.2), FailureMode: FailClosed},
		{Match: normalizeMatch(Match{PathPrefix: "/public/"}), Threshold: ptr(1)},
	}}
	for _, path := range []string{"/admin;jsessionid=x/users", "/admin.json", "/admin"} {
		if res := p.Resolve(&inspect.Request{Path: path}, defaults); res.Threshold() != 0.2 || res.FailureMode != FailClosed {
			t.Errorf("%s: threshold %v, %s; want /admin's 0.2 and closed", path, res.Threshold(), res.FailureMode)
		}
	}
	if res := p.Resolve(&inspect.Request{Path: "/public-admin/x"}, defaults); res.Threshold() != defaults.Threshold {
		t.Errorf("/public-admin/x: threshold %v, want the default", res.Threshold())
	}
}

func TestResolveEncodedBackslashBothWays(t *testing.T) {
	p := &Policy{Routes: []Route{{Match: normalizeMatch(Match{PathPrefix: "/admin"}), Threshold: ptr(0.2), FailureMode: FailClosed}}}
	if res := p.Resolve(&inspect.Request{Path: "/public%5C..%5Cadmin/x"}, defaults); res.Threshold() != 0.2 || res.FailureMode != FailClosed {
		t.Errorf("threshold %v, %s; want /admin's 0.2 and closed", res.Threshold(), res.FailureMode)
	}
}

func TestResolveCaseAndBackslashReadings(t *testing.T) {
	p := &Policy{Routes: []Route{
		{Match: normalizeMatch(Match{PathPrefix: "/admin"}), Threshold: ptr(0.2), FailureMode: FailClosed},
		{Match: normalizeMatch(Match{PathPrefix: "/Public"}), Threshold: ptr(1)},
	}}
	for _, path := range []string{"/ADMIN/users", `/admin\x`, `/public\..\admin`} {
		if res := p.Resolve(&inspect.Request{Path: path}, defaults); res.Threshold() != 0.2 || res.FailureMode != FailClosed {
			t.Errorf("%s: threshold %v, %s; want /admin's 0.2 and closed", path, res.Threshold(), res.FailureMode)
		}
	}
	if res := p.Resolve(&inspect.Request{Path: "/public/x"}, defaults); res.Threshold() != defaults.Threshold {
		t.Errorf("/public/x under a /Public route: threshold %v, want the default (the stricter reading)", res.Threshold())
	}
}

func TestResolveRouteNamesEverySource(t *testing.T) {
	p := &Policy{Routes: []Route{
		{Match: normalizeMatch(Match{PathPrefix: "/admin"}), FailureMode: FailClosed},
		{Match: normalizeMatch(Match{PathPrefix: "/public/"}), Threshold: ptr(0.3), FailureMode: FailOpen},
	}}
	res := p.Resolve(&inspect.Request{Path: "/admin%2F..%2Fpublic/x"}, defaults)
	if res.Threshold() != 0.3 || res.FailureMode != FailClosed || res.Route != "1+0" {
		t.Errorf("threshold %v, %s, route %q; want 0.3, closed, route 1+0", res.Threshold(), res.FailureMode, res.Route)
	}
}

func TestResolvePathParameters(t *testing.T) {
	p := &Policy{Routes: []Route{{Match: normalizeMatch(Match{PathPrefix: "/admin"}), Threshold: ptr(0.2), FailureMode: FailClosed}}}
	for _, path := range []string{"/public/..;/admin/users", "/;/admin", "/public/%2e%2e;/admin", "/admin;jsessionid=1/x", "/public;x=1/../admin"} {
		if res := p.Resolve(&inspect.Request{Path: path}, defaults); res.Threshold() != 0.2 || res.FailureMode != FailClosed {
			t.Errorf("%s: threshold %v, %s; want /admin's 0.2 and closed", path, res.Threshold(), res.FailureMode)
		}
	}
}

func TestResolveBackslashWithEncodedSlashKept(t *testing.T) {
	p := &Policy{Routes: []Route{{Match: normalizeMatch(Match{PathPrefix: "/admin"}), Threshold: ptr(0.2), FailureMode: FailClosed}}}
	path := `/public\x%2Fy\..\..\admin`
	if res := p.Resolve(&inspect.Request{Path: path}, defaults); res.Threshold() != 0.2 || res.FailureMode != FailClosed {
		t.Errorf("%s: threshold %v, %s; want /admin's 0.2 and closed", path, res.Threshold(), res.FailureMode)
	}
}
