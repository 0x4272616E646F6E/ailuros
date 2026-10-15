package redact

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"mime"
	"regexp"
	"slices"
	"strings"

	"github.com/0x4272616E646F6E/ailuros/internal/inspect"
	"github.com/0x4272616E646F6E/ailuros/internal/policy"
)

const Mask = "[REDACTED]"

type Redactor struct {
	headers map[string]bool
	fields  map[string]bool
}

func New(p policy.Redact) *Redactor {
	x := &Redactor{headers: map[string]bool{}, fields: map[string]bool{}}
	for _, h := range p.Headers {
		x.headers[strings.ToLower(h)] = true
	}
	for _, f := range p.JSONFields {
		x.fields[strings.ToLower(f)] = true
	}
	return x
}

func (x *Redactor) Apply(r *inspect.Request) *inspect.Request {
	c := r.Clone()
	for name, values := range c.Headers {
		if x.headers[strings.ToLower(name)] {
			for i := range values {
				values[i] = Mask
			}
		}
	}
	if len(x.fields) == 0 {
		return c
	}
	c.Query = x.redactPairs(c.Query)
	for i, v := range c.Headers["referer"] {
		if base, query, ok := strings.Cut(v, "?"); ok {
			query, frag, hasFrag := strings.Cut(query, "#")
			v = base + "?" + x.redactPairs(query)
			if hasFrag {
				v += "#" + frag
			}
			c.Headers["referer"][i] = v
		}
	}
	switch mt := c.MediaType(); {
	case len(c.Body) == 0:
	case c.GRPCContent() && strings.HasSuffix(mt, "+json"):
		if !c.GRPCWebText() {
			c.Body = x.maskFields(c.Body)
		} else if dec, ok := inspect.DecodeGRPCWebText(c.Body, c.BodyTruncated); ok {
			c.Body = []byte(base64.StdEncoding.EncodeToString(x.maskFields(dec)))
		} else {
			c.Body = x.maskFields(c.Body)
		}
	case strings.HasPrefix(mt, "multipart/"):
		c.Body = x.redactMultipart(c.Body, c.Headers["content-type"][0])
	case !c.GRPCContent():
		c.Body = x.redactBody(c.Body)
	}
	return c
}

func (x *Redactor) redactPairs(s string) string {
	if s == "" {
		return s
	}
	var b strings.Builder
	for p := range inspect.QueryPairs(s, "&") {
		if x.pairField(p.Key()) {
			b.WriteString(p.RawKey() + "=" + Mask)
		} else {
			for q := range inspect.QueryPairs(p.Raw, ";") {
				if x.pairField(q.Key()) {
					b.WriteString(q.RawKey() + "=" + Mask)
				} else {
					b.WriteString(q.Raw)
				}
				b.WriteString(q.Sep)
			}
		}
		b.WriteString(p.Sep)
	}
	return b.String()
}

func (x *Redactor) pairField(name string) bool {
	name = strings.ToLower(name)
	if x.fields[name] {
		return true
	}
	for _, part := range strings.FieldsFunc(name, func(r rune) bool { return r == '[' || r == ']' || r == '.' }) {
		if x.fields[part] {
			return true
		}
	}
	return false
}

func (x *Redactor) redactBody(body []byte) []byte {
	if out, ok := x.redactJSON(body); ok {
		return out
	}
	return []byte(x.redactPairs(string(x.maskFields(body))))
}

func (x *Redactor) redactJSON(body []byte) ([]byte, bool) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil || dec.More() {
		return nil, false
	}
	if !x.walk(v) {
		return body, true
	}
	return x.maskFields(body), true
}

func (x *Redactor) walk(v any) bool {
	changed := false
	switch t := v.(type) {
	case map[string]any:
		for k, child := range t {
			if x.fields[strings.ToLower(k)] {
				t[k] = Mask
				changed = true
				continue
			}
			if x.walk(child) {
				changed = true
			}
		}
	case []any:
		for _, child := range t {
			if x.walk(child) {
				changed = true
			}
		}
	}
	return changed
}

func (x *Redactor) redactMultipart(body []byte, contentType string) []byte {
	_, params, err := mime.ParseMediaType(contentType)
	if err != nil || params["boundary"] == "" {
		return x.maskFields(body)
	}
	delim := []byte("--" + params["boundary"])
	var starts []int
	for i := 0; i < len(body); {
		j := bytes.Index(body[i:], delim)
		if j < 0 {
			break
		}
		if at := i + j; at == 0 || body[at-1] == '\n' {
			starts = append(starts, at)
		}
		i += j + 1
	}
	if len(starts) == 0 {
		return x.maskFields(body)
	}
	out := append([]byte(nil), body[:starts[0]]...)
	for n, start := range starts {
		end := len(body)
		if n+1 < len(starts) {
			end = starts[n+1]
		}
		out = append(append(out, delim...), x.redactPart(body[start+len(delim):end])...)
	}
	return out
}

func (x *Redactor) redactPart(seg []byte) []byte {
	end, sep := -1, 0
	for _, s := range []string{"\r\n\r\n", "\n\n"} {
		if i := bytes.Index(seg, []byte(s)); i >= 0 && (end < 0 || i < end) {
			end, sep = i, len(s)
		}
	}
	if end < 0 {
		return seg
	}
	headers, content := seg[:end+sep], seg[end+sep:]
	var trailer []byte
	if bytes.HasSuffix(content, []byte("\n")) {
		cut := len(content) - 1
		if cut > 0 && content[cut-1] == '\r' {
			cut--
		}
		content, trailer = content[:cut], content[cut:]
	}
	name, partType := partHeaders(headers)
	switch {
	case x.pairField(name):
		content = []byte(Mask)
	case strings.HasPrefix(strings.ToLower(partType), "multipart/"):
		content = x.redactMultipart(content, partType)
	default:
		content = x.redactBody(content)
	}
	return slices.Concat(headers, content, trailer)
}

var partName = regexp.MustCompile(`(?i)\bname\s*=\s*(?:"([^"]*)"|([^;\s]+))`)

func partHeaders(h []byte) (name, contentType string) {
	for line := range strings.Lines(string(h)) {
		key, value, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "content-disposition":
			if _, p, err := mime.ParseMediaType(value); err == nil {
				name = p["name"]
			} else if m := partName.FindStringSubmatch(value); m != nil {
				name = m[1] + m[2]
			}
		case "content-type":
			contentType = strings.TrimSpace(value)
		}
	}
	return name, contentType
}

var (
	jsonKey    = regexp.MustCompile(`"((?:[^"\\]|\\.)*)"\s*:\s*`)
	jsonScalar = regexp.MustCompile(`^(?:"(?:[^"\\]|\\.)*"?|-?[0-9][0-9.eE+-]*|true|false|null)`)
)

func valueEnd(b []byte) int {
	if len(b) == 0 || (b[0] != '[' && b[0] != '{') {
		if m := jsonScalar.FindIndex(b); m != nil {
			return m[1]
		}
		return 0
	}
	depth, inString := 0, false
	for i := 0; i < len(b); i++ {
		switch c := b[i]; {
		case inString && c == '\\':
			i++
		case c == '"':
			inString = !inString
		case inString:
		case c == '[' || c == '{':
			depth++
		case c == ']' || c == '}':
			if depth--; depth == 0 {
				return i + 1
			}
		}
	}
	return len(b)
}

func (x *Redactor) maskFields(body []byte) []byte {
	var out []byte
	cursor := 0
	for _, m := range jsonKey.FindAllSubmatchIndex(body, -1) {
		if m[0] < cursor {
			continue
		}
		var key string
		if json.Unmarshal(body[m[2]-1:m[3]+1], &key) != nil {
			key = string(body[m[2]:m[3]])
		}
		if !x.fields[strings.ToLower(key)] {
			continue
		}
		end := valueEnd(body[m[1]:])
		if end == 0 {
			continue
		}
		out = append(append(out, body[cursor:m[1]]...), `"`+Mask+`"`...)
		cursor = m[1] + end
	}
	if out == nil {
		return body
	}
	return append(out, body[cursor:]...)
}
