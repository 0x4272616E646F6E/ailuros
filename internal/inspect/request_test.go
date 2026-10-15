package inspect

import "testing"

func TestParseMode(t *testing.T) {
	for _, s := range []string{"lite", "standard", "deep"} {
		m, err := ParseMode(s)
		if err != nil || string(m) != s {
			t.Errorf("ParseMode(%q) = %q, %v", s, m, err)
		}
	}
	if _, err := ParseMode("full"); err == nil {
		t.Error("ParseMode(full) succeeded, want error")
	}
}

func TestParseGRPCPath(t *testing.T) {
	cases := []struct {
		path, service, method string
		ok                    bool
	}{
		{"/payments.v1.Payments/Charge", "payments.v1.Payments", "Charge", true},
		{"/only-one-segment", "", "", false},
		{"/a/b/c", "", "", false},
		{"//Method", "", "", false},
	}
	for _, c := range cases {
		s, m, ok := ParseGRPCPath(c.path)
		if s != c.service || m != c.method || ok != c.ok {
			t.Errorf("ParseGRPCPath(%q) = %q, %q, %v; want %q, %q, %v", c.path, s, m, ok, c.service, c.method, c.ok)
		}
	}
}

func TestCloneIsDeep(t *testing.T) {
	r := &Request{Headers: map[string][]string{"a": {"1"}}, TLS: &TLSInfo{SNI: "x"}, Body: []byte("b")}
	c := r.Clone()
	c.Headers["a"][0] = "2"
	c.TLS.SNI = "y"
	c.Body[0] = 'z'
	if r.Headers["a"][0] != "1" || r.TLS.SNI != "x" || string(r.Body) != "b" {
		t.Fatal("Clone shares memory with the original")
	}
}

func TestParseOversize(t *testing.T) {
	for _, s := range []string{"classify_prefix", "block", "allow"} {
		if o, err := ParseOversize(s); err != nil || string(o) != s {
			t.Errorf("ParseOversize(%q) = %q, %v", s, o, err)
		}
	}
	if _, err := ParseOversize("drop"); err == nil {
		t.Error("ParseOversize(drop) succeeded, want error")
	}
}

func TestNewRequest(t *testing.T) {
	h := map[string][]string{"content-type": {"application/json"}}
	r := NewRequest("POST", "https", "shop.example.com", "/api/cart?id=7&x=1", h)
	if r.Method != "POST" || r.Scheme != "https" || r.Host != "shop.example.com" || r.Path != "/api/cart" || r.Query != "id=7&x=1" || r.IsGRPC() {
		t.Errorf("request = %+v", r)
	}
	g := NewRequest("POST", "http", "api", "/payments.v1.Payments/Charge", map[string][]string{"content-type": {"application/grpc+proto"}})
	if g.GRPCService != "payments.v1.Payments" || g.GRPCMethod != "Charge" {
		t.Errorf("grpc = %q/%q", g.GRPCService, g.GRPCMethod)
	}
	u := NewRequest("POST", "http", "api", "/payments.v1.Payments/Charge", map[string][]string{"content-type": {"Application/GRPC"}})
	if u.GRPCService != "payments.v1.Payments" {
		t.Errorf("upper-case content type: grpc service = %q", u.GRPCService)
	}
}
