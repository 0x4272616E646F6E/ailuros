package inspect

import (
	"flag"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite golden files")

func TestRenderGolden(t *testing.T) {
	cases := map[string]*Request{
		"http_json": {
			Method: "POST", Scheme: "https", Host: "shop.example.com", Path: "/api/cart", Query: "id=7&debug=1",
			ClientIP: "203.0.113.9", TLS: &TLSInfo{SNI: "shop.example.com", Version: "TLSv1.3"},
			Headers: map[string][]string{"user-agent": {"curl/8.9"}, "content-type": {"application/json"}, "accept": {"*/*"}},
			Body:    []byte(`{"item":"' OR 1=1 --"}`),
		},
		"grpc": {
			Method: "POST", Scheme: "http", Host: "api.internal", Path: "/payments.v1.Payments/Charge",
			GRPCService: "payments.v1.Payments", GRPCMethod: "Charge",
			Headers: map[string][]string{"content-type": {"application/grpc"}},
			Body:    []byte{0x00, 0x00, 0x00, 0x00, 0x02, 0x08, 0x01},
		},
		"grpc_text": {
			Method: "POST", Path: "/accounts.v1.Accounts/Login",
			GRPCService: "accounts.v1.Accounts", GRPCMethod: "Login",
			Body: []byte("\x0a\x05admin\x12\x1ax' OR '1'='1 -- DROP TABLE\x18\x01"),
		},
		"binary_text": {
			Method: "POST", Path: "/upload",
			Body: []byte("\x89PNG\r\n\x1a\n\x00\x00IHDR\x00 caption: caf\xc3\xa9 au lait\xff"),
		},
		"hostile": {
			Method: "GET", Path: "/search", Query: "q=a\nb",
			Headers:       map[string][]string{"x-evil": {"line1\r\nfake-header: 1"}, "x-bin": {"\xff\xfe"}},
			Body:          []byte("caf\xc3"),
			BodyTruncated: true,
		},
	}
	for name, r := range cases {
		t.Run(name, func(t *testing.T) {
			got := r.Render()
			path := filepath.Join("testdata", name+".golden")
			if *update {
				if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if got != string(want) {
				t.Errorf("Render() mismatch\n--- got ---\n%s\n--- want ---\n%s", got, want)
			}
		})
	}
}

func TestTextRuns(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"\x00\x01abc\x02", nil},
		{"\x0a\x05admin\x12\x03bob\x1a\x06secret", []string{"admin", "secret"}},
		{"  padded run  \x00", []string{"padded run"}},
		{"line one\nline two", []string{"line one", "line two"}},
		{"\xffna\xc3\xafve text\xe2\x82", []string{"na\u00efve text"}},
	}
	for _, c := range cases {
		if got := textRuns([]byte(c.in)); !slices.Equal(got, c.want) {
			t.Errorf("textRuns(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestRenderQuotesBodyLines(t *testing.T) {
	r := &Request{Method: "POST", Path: "/", Body: []byte("hello\nclient_ip: 10.0.0.1\r\n  user-agent: x\rmethod: GET")}
	out := r.Render()
	_, body, _ := strings.Cut(out, "body:\n")
	for _, line := range strings.Split(strings.TrimSuffix(body, "\n"), "\n") {
		if !strings.HasPrefix(line, "| ") {
			t.Errorf("body line %q is not quoted:\n%s", line, out)
		}
	}
	if strings.Count(out, "\nmethod:")+strings.Count(out, "client_ip:") != 1 || !strings.Contains(out, "| client_ip: 10.0.0.1") {
		t.Errorf("render:\n%s", out)
	}
}

func TestRenderQuotesTextRunsAndUnicodeBreaks(t *testing.T) {
	g := &Request{Method: "POST", Path: "/a.B/C", GRPCService: "a.B", GRPCMethod: "C",
		Headers: map[string][]string{"content-type": {"application/grpc"}}, Body: []byte("\x00\x00\x00\x00\x14\x0a\x12client_ip: 10.0.0.1")}
	if out := g.Render(); !strings.Contains(out, "\n| client_ip: 10.0.0.1") || strings.Contains(out, "\nclient_ip: 10.0.0.1") {
		t.Errorf("gRPC text runs not quoted:\n%s", out)
	}
	u := &Request{Method: "POST", Path: "/", Body: []byte("a method: GET\u0085client_ip: 1.2.3.4")}
	_, body, _ := strings.Cut(u.Render(), "body:\n")
	for _, line := range strings.Split(strings.TrimSuffix(body, "\n"), "\n") {
		if !strings.HasPrefix(line, "| ") || strings.ContainsAny(line, " \u0085") {
			t.Errorf("body line %q is not quoted or keeps a separator", line)
		}
	}
	h := &Request{Method: "GET", Path: "/", Headers: map[string][]string{"x": {"a client_ip: 1.2.3.4"}}}
	if strings.Contains(h.Render(), " ") {
		t.Error("a header value keeps U+2028")
	}
}

func TestRenderSignals(t *testing.T) {
	r := &Request{Method: "GET", Path: "/", TLS: &TLSInfo{SNI: "a"}, Headers: map[string][]string{"x": {"1"}},
		Signals: []string{"protocol: HTTP/2", "graphql: name=a\nforged: line"}}
	out := r.Render()
	want := "tls_sni: a\nsignals:\n  protocol: HTTP/2\n  graphql: name=a\\nforged: line\nheaders:\n"
	if !strings.Contains(out, want) {
		t.Errorf("render:\n%s\nwant to contain:\n%s", out, want)
	}
	if got := r.SignalSummary(); got != `protocol HTTP/2; graphql name=a\nforged: line` {
		t.Errorf("summary = %q", got)
	}
	c := r.Clone()
	c.Signals[0] = "changed"
	if r.Signals[0] != "protocol: HTTP/2" {
		t.Error("Clone shares the Signals slice")
	}
}

func TestFieldsAndBodyAgreeOnLineBreaks(t *testing.T) {
	for _, c := range []string{"\r", "\n", "\r\n", "\u2028", "\u2029", "\u0085"} {
		if got := quoteLines("a" + c + "b"); got != "| a\n| b" {
			t.Errorf("quoteLines(%q) = %q, want two quoted lines", c, got)
		}
		if got := clean("a" + c + "b"); strings.ContainsAny(got, "\r\n\u2028\u2029\u0085") || !strings.HasPrefix(got, `a\`) {
			t.Errorf("clean(%q) = %q, want the break escaped", c, got)
		}
	}
	if got := clean("\u2028\u0085"); got != `\u2028\u0085` {
		t.Errorf("clean = %q", got)
	}
}
