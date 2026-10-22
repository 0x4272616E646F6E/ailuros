package dataset

import (
	"bufio"
	"bytes"
	"cmp"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"slices"
	"strings"

	"github.com/0x4272616E646F6E/decision-waf/internal/eval/strictjson"
	"github.com/0x4272616E646F6E/decision-waf/internal/inspect"
)

const Version = 1

const maxLine = 64 << 20

type Header struct {
	Version     int    `json:"decision_waf_eval_dataset"`
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
}

type Entry struct {
	ID       string              `json:"id"`
	Label    string              `json:"label"`
	Note     string              `json:"note,omitempty"`
	Method   string              `json:"method"`
	Scheme   string              `json:"scheme,omitempty"`
	Host     string              `json:"host,omitempty"`
	Path     string              `json:"path"`
	Query    string              `json:"query,omitempty"`
	Headers  map[string][]string `json:"headers,omitempty"`
	BodyB64  string              `json:"body_b64,omitempty"`
	GRPC     string              `json:"grpc,omitempty"`
	Protocol string              `json:"protocol,omitempty"`
	JA4      string              `json:"ja4,omitempty"`
	Tags     []string            `json:"tags,omitempty"`
}

type Dataset struct {
	Header  Header
	Entries []Entry
	SHA256  string
}

func LoadFile(path string, labels []string) (*Dataset, error) {
	f, err := os.Open(path) //nolint:gosec // G304: the path is the dataset the user named
	if err != nil {
		return nil, err
	}
	defer f.Close()
	ds, err := Read(f, labels)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return ds, nil
}

func Read(r io.Reader, labels []string) (*Dataset, error) {
	allowed := make(map[string]bool, len(labels))
	for _, l := range labels {
		allowed[l] = true
	}
	sum := sha256.New()
	sc := bufio.NewScanner(io.TeeReader(r, sum))
	sc.Buffer(nil, maxLine)
	var (
		ds     Dataset
		errs   []error
		header bool
		seen   = map[string]int{}
		n      int
	)
	for sc.Scan() {
		n++
		text := bytes.TrimSpace(sc.Bytes())
		if len(text) == 0 {
			continue
		}
		if !header {
			header = true
			if err := strictjson.Decode(text, &ds.Header); err != nil {
				return nil, fmt.Errorf("line %d: header: %w (line 1 must be {\"decision_waf_eval_dataset\": %d, ...})", n, err, Version)
			}
			if ds.Header.Version != Version {
				return nil, fmt.Errorf("line %d: unsupported dataset version %d (want %d)", n, ds.Header.Version, Version)
			}
			continue
		}
		var e Entry
		if err := strictjson.Decode(text, &e); err != nil {
			errs = append(errs, fmt.Errorf("line %d: %w", n, err))
			continue
		}
		e.Headers = lowerKeys(e.Headers)
		for _, p := range e.problems(allowed) {
			errs = append(errs, fmt.Errorf("line %d: %s: %s", n, cmp.Or(e.ID, "(no id)"), p))
		}
		if e.ID != "" {
			if first, dup := seen[e.ID]; dup {
				errs = append(errs, fmt.Errorf("line %d: duplicate id %q (first on line %d)", n, e.ID, first))
			} else {
				seen[e.ID] = n
			}
		}
		ds.Entries = append(ds.Entries, e)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("line %d: %w", n+1, err)
	}
	if !header {
		return nil, fmt.Errorf("empty dataset: line 1 must be the header {\"decision_waf_eval_dataset\": %d}", Version)
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	if len(ds.Entries) == 0 {
		return nil, errors.New("dataset has no requests")
	}
	ds.SHA256 = hex.EncodeToString(sum.Sum(nil))
	return &ds, nil
}

func (e *Entry) problems(allowed map[string]bool) []string {
	var p []string
	if e.ID == "" {
		p = append(p, "missing id")
	}
	switch {
	case e.Label == "":
		p = append(p, "missing label")
	case !allowed[e.Label]:
		p = append(p, fmt.Sprintf("label %q is not one of %s", e.Label, strings.Join(slices.Sorted(maps.Keys(allowed)), ", ")))
	}
	if e.Method == "" {
		p = append(p, "missing method")
	}
	if !strings.HasPrefix(e.Path, "/") {
		p = append(p, `path must start with "/"`)
	}
	if (&inspect.Request{Headers: e.Headers}).MultipleContentTypes() {
		p = append(p, "several content-type values: the server refuses such a request as malformed")
	}
	if len(e.Headers["content-encoding"]) > 0 {
		p = append(p, "content-encoding is not supported: store the decoded body in body_b64 and drop the header")
	}
	if strings.Contains(e.Path, "?") {
		p = append(p, `path must not contain "?"; put the query string in "query"`)
	}
	if _, err := base64.StdEncoding.DecodeString(e.BodyB64); err != nil {
		p = append(p, "body_b64 is not valid base64")
	}
	if e.GRPC != "" {
		if _, _, ok := inspect.ParseGRPCPath("/" + e.GRPC); !ok {
			p = append(p, fmt.Sprintf(`grpc %q must be "package.Service/Method"`, e.GRPC))
		} else if e.Path != "/"+e.GRPC {
			p = append(p, fmt.Sprintf("path must be %q for gRPC method %q", "/"+e.GRPC, e.GRPC))
		}
		if ct := e.Headers["content-type"]; len(ct) > 0 && !(&inspect.Request{Headers: e.Headers}).GRPCContent() {
			p = append(p, fmt.Sprintf("content-type %q is not gRPC; a grpc request needs application/grpc or none", ct[0]))
		}
	}
	return p
}

func (e *Entry) Request(bodyMax int) *inspect.Request {
	body, _ := base64.StdEncoding.DecodeString(e.BodyB64)
	var headers map[string][]string
	if e.Headers != nil || e.GRPC != "" {
		headers = make(map[string][]string, len(e.Headers)+1)
		for k, v := range e.Headers {
			headers[k] = slices.Clone(v)
		}
	}
	if e.GRPC != "" && len(headers["content-type"]) == 0 {
		headers["content-type"] = []string{"application/grpc"}
	}
	target := e.Path
	if e.Query != "" {
		target += "?" + e.Query
	}
	r := inspect.NewRequest(e.Method, e.Scheme, e.Host, target, headers)
	r.Protocol, r.JA4 = e.Protocol, e.JA4
	if len(body) > 0 {
		r.Body = body
	}
	if len(r.Body) > bodyMax {
		r.Body, r.BodyTruncated = r.Body[:bodyMax], true
	}
	return r
}

func Write(w io.Writer, ds *Dataset) error {
	bw := bufio.NewWriter(w)
	enc := json.NewEncoder(bw)
	enc.SetEscapeHTML(false)
	h := ds.Header
	h.Version = Version
	if err := enc.Encode(h); err != nil {
		return err
	}
	for i := range ds.Entries {
		if err := enc.Encode(&ds.Entries[i]); err != nil {
			return err
		}
	}
	return bw.Flush()
}

func lowerKeys(h map[string][]string) map[string][]string {
	if len(h) == 0 {
		return nil
	}
	out := make(map[string][]string, len(h))
	for _, k := range slices.Sorted(maps.Keys(h)) {
		lk := strings.ToLower(k)
		out[lk] = append(out[lk], h[k]...)
	}
	return out
}
