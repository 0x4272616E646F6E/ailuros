package redact

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/0x4272616E646F6E/decision-waf/internal/inspect"
	"github.com/0x4272616E646F6E/decision-waf/internal/policy"
)

func newRedactor() *Redactor {
	return New(policy.Redact{Headers: []string{"Authorization", "cookie"}, JSONFields: []string{"password", "SSN"}})
}

func withBody(contentType, body string) *inspect.Request {
	return &inspect.Request{Headers: map[string][]string{"content-type": {contentType}}, Body: []byte(body)}
}

func TestHeadersMaskedWithoutMutatingInput(t *testing.T) {
	in := &inspect.Request{Headers: map[string][]string{
		"authorization": {"Bearer secret"}, "cookie": {"a=1", "b=2"}, "accept": {"*/*"},
	}}
	out := newRedactor().Apply(in)
	if got := out.Headers["authorization"]; len(got) != 1 || got[0] != Mask {
		t.Errorf("authorization = %v", got)
	}
	if got := out.Headers["cookie"]; len(got) != 2 || got[0] != Mask || got[1] != Mask {
		t.Errorf("cookie = %v", got)
	}
	if out.Headers["accept"][0] != "*/*" {
		t.Errorf("accept changed: %v", out.Headers["accept"])
	}
	if in.Headers["authorization"][0] != "Bearer secret" {
		t.Error("Apply mutated the input request")
	}
}

func TestJSONBodyNested(t *testing.T) {
	in := withBody("application/json", `{"user":"bob","password":"hunter2","profile":{"ssn":123456789,"tags":[{"Password":"x"}]},"note":"<script>"}`)
	got := string(newRedactor().Apply(in).Body)
	for _, secret := range []string{"hunter2", "123456789", `"x"`} {
		if strings.Contains(got, secret) {
			t.Errorf("body still contains %s: %s", secret, got)
		}
	}
	if !strings.Contains(got, `"user":"bob"`) || !strings.Contains(got, "<script>") {
		t.Errorf("non-secret content changed or HTML-escaped: %s", got)
	}
}

func TestJSONBodyUnchangedWhenNothingMatches(t *testing.T) {
	body := `{ "a" : 1 }`
	if got := string(newRedactor().Apply(withBody("application/json", body)).Body); got != body {
		t.Errorf("body = %q, want unchanged %q", got, body)
	}
}

func TestTruncatedJSONStillRedacted(t *testing.T) {
	cases := []string{
		`{"user":"bob","password":"hunter2-and-more`,
		`{"ssn": 123456789, "next": `,
		`{"PASSWORD" : "hunter2\"quoted", "x": 1`,
	}
	for _, body := range cases {
		got := string(newRedactor().Apply(withBody("application/json", body)).Body)
		if strings.Contains(got, "hunter2") || strings.Contains(got, "123456789") {
			t.Errorf("truncated body %q not redacted: %q", body, got)
		}
	}
}

func TestQueryAndFormRedacted(t *testing.T) {
	r := newRedactor()
	q := r.Apply(&inspect.Request{Query: "user=bob&password=hunter2&PASSWORD=x"}).Query
	if q != "user=bob&password=[REDACTED]&PASSWORD=[REDACTED]" {
		t.Errorf("query = %q", q)
	}
	form := r.Apply(withBody("application/x-www-form-urlencoded", "password=hunter2&next=%2F")).Body
	if string(form) != "password=[REDACTED]&next=%2F" {
		t.Errorf("form = %q", form)
	}
}

func TestNestedPairKeysRedacted(t *testing.T) {
	r := newRedactor()
	q := r.Apply(&inspect.Request{Query: "user%5Bpassword%5D=q1&password[]=q2&user.password=q3&passwords=keep"}).Query
	if q != "user%5Bpassword%5D=[REDACTED]&password[]=[REDACTED]&user.password=[REDACTED]&passwords=keep" {
		t.Errorf("query = %q", q)
	}
	form := r.Apply(withBody("application/x-www-form-urlencoded", "user[email]=a&user[password]=hunter2")).Body
	if string(form) != "user[email]=a&user[password]=[REDACTED]" {
		t.Errorf("form = %q", form)
	}
}

func TestGRPCBodyUntouched(t *testing.T) {
	in := withBody("application/grpc", `"password":"hunter2"`)
	in.GRPCService, in.GRPCMethod = "a.B", "C"
	if got := string(newRedactor().Apply(in).Body); got != `"password":"hunter2"` {
		t.Errorf("gRPC body changed: %q", got)
	}
}

func TestNoFieldsLeavesBodyAndQuery(t *testing.T) {
	r := New(policy.Redact{Headers: []string{"authorization"}})
	in := withBody("application/json", `{"password":"hunter2"}`)
	in.Query = "password=x"
	out := r.Apply(in)
	if string(out.Body) != `{"password":"hunter2"}` || out.Query != "password=x" {
		t.Errorf("body/query changed with no json_fields: %q %q", out.Body, out.Query)
	}
}

func TestTruncatedJSONNestedSecretRedacted(t *testing.T) {
	cases := []string{
		`{"password":{"pin":"4242`,
		`{"password":["hunter2`,
		`{"password":{"old":{"v":1},"pin":"4242`,
		`{"password":["x]}", "hunter2`,
		`{"password":["a\"]", "hunter2`,
	}
	for _, body := range cases {
		got := string(newRedactor().Apply(withBody("application/json", body)).Body)
		if strings.Contains(got, "4242") || strings.Contains(got, "hunter2") {
			t.Errorf("truncated nested body %q not redacted: %q", body, got)
		}
		if !strings.Contains(got, `"password":"[REDACTED]"`) {
			t.Errorf("truncated nested body %q: want \"password\":\"[REDACTED]\", got %q", body, got)
		}
	}
}

func TestGRPCJSONBodyAndRefererRedacted(t *testing.T) {
	r := newRedactor()
	in := withBody("application/grpc+json", "\x00\x00\x00\x00\x15{\"password\":\"hunter2\"}")
	in.GRPCService, in.GRPCMethod = "a.B", "C"
	if got := string(r.Apply(in).Body); strings.Contains(got, "hunter2") {
		t.Errorf("gRPC JSON body = %q", got)
	}
	ref := &inspect.Request{Headers: map[string][]string{"referer": {"https://site.example/reset?password=hunter2&next=%2F#top", "https://site.example/"}}}
	got := r.Apply(ref).Headers["referer"]
	if got[0] != "https://site.example/reset?password=[REDACTED]&next=%2F#top" || got[1] != "https://site.example/" {
		t.Errorf("referer = %q", got)
	}
}

func TestEscapedKeyRedactedInInvalidJSON(t *testing.T) {
	body := `{"\u0070assword":"hunter2","user":"bob","\u0053\u0053N":"123-45-6789"`
	got := string(newRedactor().Apply(withBody("application/json", body)).Body)
	if strings.Contains(got, "hunter2") || strings.Contains(got, "123-45-6789") || !strings.Contains(got, `"user":"bob"`) {
		t.Errorf("body = %s", got)
	}
}

func TestMultipartRedacted(t *testing.T) {
	ct := `multipart/form-data; boundary="XyZ"`
	body := "--XyZ\r\nContent-Disposition: form-data; name=\"user\"\r\n\r\nbob\r\n" +
		"--XyZ\r\nContent-Disposition: form-data; name=\"user[password]\"\r\n\r\nhunter2\r\n" +
		"--XyZ\r\nContent-Disposition: form-data; name=\"meta\"\r\nContent-Type: application/json\r\n\r\n{\"ssn\":\"123-45-6789\",\"ok\":1}\r\n" +
		"--XyZ--\r\n"
	got := string(newRedactor().Apply(withBody(ct, body)).Body)
	for _, secret := range []string{"hunter2", "123-45-6789"} {
		if strings.Contains(got, secret) {
			t.Errorf("%s not masked:\n%s", secret, got)
		}
	}
	if !strings.Contains(got, "\r\n\r\nbob\r\n--XyZ") || !strings.HasSuffix(got, "--XyZ--\r\n") || !strings.Contains(got, `"ok":1`) {
		t.Errorf("structure or other values changed:\n%s", got)
	}
	cut := body[:strings.Index(body, "hunter2")+3]
	if got := string(newRedactor().Apply(withBody(ct, cut)).Body); strings.Contains(got, "hun") {
		t.Errorf("truncated body not masked:\n%s", got)
	}
}

func TestGRPCWebTextJSONRedacted(t *testing.T) {
	frame := "\x00\x00\x00\x00\x15" + `{"password":"hunter2"}`
	in := withBody("application/grpc-web-text+json", base64.StdEncoding.EncodeToString([]byte(frame)))
	in.GRPCService, in.GRPCMethod = "a.B", "C"
	out := newRedactor().Apply(in)
	dec, ok := inspect.DecodeGRPCWebText(out.Body, false)
	if !ok || strings.Contains(string(dec), "hunter2") || !strings.Contains(string(dec), Mask) {
		t.Errorf("decoded body = %q (ok %v)", dec, ok)
	}
	if strings.Contains(out.Render(), "hunter2") {
		t.Error("the rendered prompt carries the secret")
	}
}

func TestMultipartEdgeCases(t *testing.T) {
	r := newRedactor()
	ct := `multipart/form-data; boundary=XyZ`
	for name, body := range map[string]string{
		"LF only, CRLFCRLF in a value": "--XyZ\nContent-Disposition: form-data; name=\"note\"\n\nx\r\n\r\ny\n--XyZ\nContent-Disposition: form-data; name=\"password\"\n\nhunter2\n--XyZ--\n",
		"boundary text inside a value": "--XyZ\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\nhun--XyZter2\r\n--XyZ--\r\n",
		"unparsable disposition":       "--XyZ\r\nContent-Disposition: form-data; name=password; filename=\"a\r\n\r\nhunter2\r\n--XyZ--\r\n",
		"nested multipart": "--XyZ\r\nContent-Disposition: form-data; name=\"files\"\r\nContent-Type: multipart/mixed; boundary=Inner\r\n\r\n" +
			"--Inner\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\nhunter2\r\n--Inner--\r\n--XyZ--\r\n",
	} {
		got := string(r.Apply(withBody(ct, body)).Body)
		if strings.Contains(got, "hunter2") || strings.Contains(got, "ter2") {
			t.Errorf("%s: secret leaked:\n%q", name, got)
		}
	}
	in := withBody("application/grpc-web-text+json", `{"password":"hunter2"} not base64!`)
	in.GRPCService, in.GRPCMethod = "a.B", "C"
	if got := string(r.Apply(in).Body); strings.Contains(got, "hunter2") {
		t.Errorf("invalid gRPC-Web text: %q", got)
	}
}

func TestMaskedContainerDoesNotHideTheRest(t *testing.T) {
	r := newRedactor()
	for name, body := range map[string]string{
		"truncated JSON": `{"password":[],"q":"' UNION SELECT card FROM cards --","pad":"` + strings.Repeat("x", 40),
		"nested object":  `{"password":{"a":"]}"},"q":"' UNION SELECT card FROM cards --",`,
	} {
		got := string(r.Apply(withBody("application/json", body)).Body)
		if !strings.Contains(got, "UNION SELECT") || !strings.Contains(got, `"password":"[REDACTED]"`) {
			t.Errorf("%s: %s", name, got)
		}
	}
	in := withBody("application/grpc+json", "\x00\x00\x00\x00\x40"+`{"password":[1,2],"q":"<script>alert(1)</script>"}`)
	in.GRPCService, in.GRPCMethod = "a.B", "C"
	if got := string(r.Apply(in).Body); !strings.Contains(got, "<script>") {
		t.Errorf("gRPC JSON: %q", got)
	}
}

func TestJSONDuplicateKeysKept(t *testing.T) {
	body := `{"password":"x","q":"' OR 1=1 --","q":"hello"}`
	got := string(newRedactor().Apply(withBody("application/json", body)).Body)
	if got != `{"password":"[REDACTED]","q":"' OR 1=1 --","q":"hello"}` {
		t.Errorf("body = %s", got)
	}
}

func TestPairsSplitOnSemicolonAndUndeclaredForms(t *testing.T) {
	r := newRedactor()
	q := r.Apply(&inspect.Request{Query: "user=bob;password=hunter2&next=1"}).Query
	if q != "user=bob;password=[REDACTED]&next=1" {
		t.Errorf("query = %q", q)
	}
	for _, ct := range []string{"text/plain", "application/octet-stream", ""} {
		body := r.Apply(withBody(ct, "user=bob&password=hunter2")).Body
		if string(body) != "user=bob&password=[REDACTED]" {
			t.Errorf("%q body = %q", ct, body)
		}
	}
}

func TestPairKeyDecodedLeniently(t *testing.T) {
	r := newRedactor()
	cases := map[string]string{
		"user[pass%77ord]%zz=secret&a=1": "user[pass%77ord]%zz=[REDACTED]&a=1",
		"b=2;pass%77ord[%zz]=secret":     "b=2;pass%77ord[%zz]=[REDACTED]",
		"pass+word=x&pass%2=y":           "pass+word=x&pass%2=y",
	}
	for in, want := range cases {
		if got := r.Apply(&inspect.Request{Query: in}).Query; got != want {
			t.Errorf("%q: got %q, want %q", in, got, want)
		}
	}
}

func TestPairValueWithSemicolonMaskedWhole(t *testing.T) {
	r := newRedactor()
	if got := r.Apply(&inspect.Request{Query: "password=hun;ter2&next=1;x=2"}).Query; got != "password=[REDACTED]&next=1;x=2" {
		t.Errorf("query = %q", got)
	}
}
