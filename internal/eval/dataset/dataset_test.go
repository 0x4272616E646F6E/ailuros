package dataset

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/0x4272616E646F6E/ailuros/internal/classifier"
	"github.com/0x4272616E646F6E/ailuros/internal/policy"
)

func labels() []string { return classifier.Labels(policy.DefaultCategories()) }

const valid = `{"ailuros_eval_dataset":1,"name":"t","description":"d"}
{"id":"b1","label":"benign","note":"home","method":"GET","path":"/","headers":{"User-Agent":["curl/8"]},"tags":["path"]}
{"id":"g1","label":"rce","method":"POST","path":"/pkg.Svc/Run","grpc":"pkg.Svc/Run","body_b64":"aGVsbG8gd29ybGQ="}
`

func TestReadValid(t *testing.T) {
	ds, err := Read(strings.NewReader(valid), labels())
	if err != nil {
		t.Fatal(err)
	}
	if ds.Header != (Header{Version: 1, Name: "t", Description: "d"}) {
		t.Errorf("header = %+v", ds.Header)
	}
	if len(ds.Entries) != 2 || ds.Entries[0].Note != "home" {
		t.Fatalf("entries = %+v", ds.Entries)
	}
	if got := ds.Entries[0].Headers["user-agent"]; !slices.Equal(got, []string{"curl/8"}) {
		t.Errorf("headers = %v, want names lower-cased", ds.Entries[0].Headers)
	}
	sum := sha256.Sum256([]byte(valid))
	if ds.SHA256 != hex.EncodeToString(sum[:]) {
		t.Errorf("sha256 = %s", ds.SHA256)
	}
}

func TestReadCRLFAndLongLines(t *testing.T) {
	body := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte("a"), 200<<10))
	in := "{\"ailuros_eval_dataset\":1}\r\n" +
		`{"id":"b1","label":"benign","method":"POST","path":"/u","body_b64":"` + body + "\"}\r\n"
	ds, err := Read(strings.NewReader(in), labels())
	if err != nil {
		t.Fatal(err)
	}
	if n := len(ds.Entries[0].Request(1 << 20).Body); n != 200<<10 {
		t.Errorf("body = %d bytes, want %d", n, 200<<10)
	}
}

func TestReadErrors(t *testing.T) {
	const h = `{"ailuros_eval_dataset":1}` + "\n"
	const ok = `{"id":"x","label":"benign","method":"GET","path":"/"}` + "\n"
	cases := []struct {
		name, in string
		want     []string
	}{
		{"empty", "", []string{"empty dataset"}},
		{"header only", h, []string{"no requests"}},
		{"no header", ok, []string{"line 1: header"}},
		{"future version", `{"ailuros_eval_dataset":2}` + "\n" + ok, []string{"unsupported dataset version 2"}},
		{"unknown field", h + `{"id":"b1","lable":"benign","method":"GET","path":"/"}` + "\n", []string{"line 2", `unknown field "lable"`}},
		{"missing fields", h + `{"label":"benign"}` + "\n", []string{"line 2: (no id): missing id", "missing method", `path must start with "/"`}},
		{"bad label", h + `{"id":"x","label":"sql","method":"GET","path":"/"}` + "\n", []string{`line 2: x: label "sql" is not one of benign, credential_stuffing`}},
		{"bad base64", h + `{"id":"x","label":"benign","method":"POST","path":"/","body_b64":"%%%"}` + "\n", []string{"x: body_b64 is not valid base64"}},
		{"bad grpc", h + `{"id":"x","label":"benign","method":"POST","path":"/a","grpc":"nomethod"}` + "\n", []string{`grpc "nomethod" must be "package.Service/Method"`}},
		{"grpc path mismatch", h + `{"id":"x","label":"benign","method":"POST","path":"/a","grpc":"pkg.S/M"}` + "\n", []string{`path must be "/pkg.S/M"`}},
		{"duplicate id", h + ok + ok, []string{`line 3: duplicate id "x" (first on line 2)`}},
		{"every problem reported", h + `{"id":"x","label":"nope","method":"GET","path":"/"}` + "\n" + `{"id":"y","label":"benign","method":"GET","path":"nope"}` + "\n", []string{"line 2: x: label", "line 3: y: path"}},
		{"trailing data", h + `{"id":"x","label":"benign","method":"GET","path":"/"} {}` + "\n", []string{"line 2", "after the JSON object"}},
		{"query in the path", h + `{"id":"x","label":"benign","method":"GET","path":"/login?password=x"}` + "\n", []string{"line 2", `path must not contain "?"`}},
		{"grpc with a non-gRPC content-type", h + `{"id":"x","label":"benign","method":"POST","path":"/pkg.S/M","grpc":"pkg.S/M","headers":{"content-type":["application/json"]}}` + "\n", []string{"line 2", "is not gRPC"}},
		{"content-encoding", h + `{"id":"x","label":"benign","method":"POST","path":"/","headers":{"content-encoding":["gzip"]}}` + "\n", []string{"line 2", "content-encoding is not supported"}},
		{"two content-types", h + `{"id":"x","label":"benign","method":"POST","path":"/","headers":{"content-type":["text/plain","application/grpc"]}}` + "\n", []string{"line 2", "several content-type values"}},
		{"label twice", h + `{"id":"x","label":"benign","label":"sqli","method":"GET","path":"/"}` + "\n", []string{"line 2", `duplicate key "label"`}},
		{"label in another case", h + `{"id":"x","label":"benign","LABEL":"sqli","method":"GET","path":"/"}` + "\n", []string{"line 2", `unknown field "LABEL"`}},
		{"header field in another case", `{"ailuros_eval_dataset":1,"NAME":"x"}` + "\n" + ok, []string{"line 1", `unknown field "NAME"`}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Read(strings.NewReader(c.in), labels())
			if err == nil {
				t.Fatal("no error")
			}
			for _, w := range c.want {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("error %q does not contain %q", err, w)
				}
			}
		})
	}
}

func TestRoundTrip(t *testing.T) {
	ds, err := Read(strings.NewReader(valid), labels())
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := Write(&buf, ds); err != nil {
		t.Fatal(err)
	}
	back, err := Read(&buf, labels())
	if err != nil {
		t.Fatal(err)
	}
	if back.Header != ds.Header || !reflect.DeepEqual(back.Entries, ds.Entries) {
		t.Errorf("round trip changed the dataset:\n%+v\n%+v", ds, back)
	}
}

func TestRequest(t *testing.T) {
	ds, err := Read(strings.NewReader(valid), labels())
	if err != nil {
		t.Fatal(err)
	}
	g := ds.Entries[1]
	r := g.Request(4)
	if string(r.Body) != "hell" || !r.BodyTruncated {
		t.Errorf("body = %q truncated=%v, want the first 4 bytes, truncated", r.Body, r.BodyTruncated)
	}
	if r.GRPCService != "pkg.Svc" || r.GRPCMethod != "Run" || r.Method != "POST" || r.Path != "/pkg.Svc/Run" {
		t.Errorf("request = %+v", r)
	}
	if ct := r.Headers["content-type"]; len(ct) != 1 || ct[0] != "application/grpc" {
		t.Errorf("gRPC entry content-type = %q, want application/grpc, as a gRPC client sends", ct)
	}
	if r := g.Request(1 << 20); r.BodyTruncated || string(r.Body) != "hello world" {
		t.Errorf("untruncated body = %q truncated=%v", r.Body, r.BodyTruncated)
	}
	b := ds.Entries[0]
	r = b.Request(16)
	if r.Body != nil || r.IsGRPC() {
		t.Errorf("benign request = %+v, want no body and not gRPC", r)
	}
	q := Entry{Method: "GET", Path: "/login", Query: "password=hunter2"}
	if r := q.Request(16); r.Path != "/login" || r.Query != "password=hunter2" {
		t.Errorf("request path %q query %q", r.Path, r.Query)
	}
	r.Headers["user-agent"][0] = "changed"
	if b.Headers["user-agent"][0] != "curl/8" {
		t.Error("Request shares header storage with the entry")
	}
}

func TestShippedSample(t *testing.T) {
	ds, err := LoadFile("../../../eval/datasets/sample.jsonl", labels())
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	lookalikes := 0
	for _, e := range ds.Entries {
		counts[e.Label]++
		if slices.Contains(e.Tags, "lookalike") {
			lookalikes++
		}
	}
	want := map[string]int{"benign": 10, "sqli": 3, "xss": 2, "path_traversal": 2, "rce": 3, "scanner": 4}
	if !reflect.DeepEqual(counts, want) || lookalikes != 5 || ds.Header.Name != "sample" {
		t.Errorf("sample: labels %v, %d lookalikes, name %q", counts, lookalikes, ds.Header.Name)
	}
}

func TestEntryMetadata(t *testing.T) {
	e := Entry{ID: "1", Label: "benign", Method: "GET", Path: "/", Protocol: "HTTP/2", JA4: "t13d1516h2_8daaf6152771_b186095e22b6"}
	r := e.Request(1024)
	if r.Protocol != "HTTP/2" || r.JA4 != e.JA4 {
		t.Errorf("request %+v", r)
	}
}
