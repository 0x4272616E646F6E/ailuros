package signals

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/0x4272616E646F6E/ailuros/internal/inspect"
)

func queryParams(raw string) (queries []readings, opName string) {
	seen := false
	for p := range inspect.QueryPairs(raw, "&") {
		first := true
		for q := range inspect.QueryPairs(p.Raw, ";") {
			isFirst := first
			first = false
			switch q.Key() {
			case "query":
				rs := readings{q.Value()}
				if isFirst && p.Key() == "query" && p.Value() != rs[0] {
					rs = append(rs, p.Value())
				}
				queries = append(queries, rs)
			case "operationName":
				if !seen {
					opName, seen = q.Value(), true
				}
			}
		}
	}
	return queries, opName
}

func jsonDocuments(body []byte) (docs []readings, name string, batch int) {
	body = bytes.TrimPrefix(body, []byte(bom))
	docs, name, batch, err := walkJSON(body)
	if err == nil || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return docs, name, batch
	}
	sdocs, sname, sbatch := scanJSON(body)
	if name == "" {
		name = sname
	}
	return sdocs, name, max(batch, sbatch)
}

func walkJSON(body []byte) (docs []readings, name string, batch int, err error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	tok, err := dec.Token()
	if err != nil {
		return nil, "", 0, err
	}
	switch tok {
	case json.Delim('{'):
		docs, name, err = readObject(dec, body)
	case json.Delim('['):
		for {
			tok, err = dec.Token()
			if err != nil || tok == json.Delim(']') {
				break
			}
			batch++
			if tok != json.Delim('{') {
				if err = skipValue(dec, tok); err != nil {
					break
				}
				continue
			}
			var qs []readings
			var n string
			qs, n, err = readObject(dec, body)
			if len(qs) > 0 && name == "" {
				name = n
			}
			docs = append(docs, qs...)
			if err != nil {
				break
			}
		}
	}
	return docs, name, batch, err
}

func scanJSON(body []byte) (docs []readings, name string, batch int) {
	depth := 0
	topArray, expectElem := false, false
	seenName := false
	isSpace := func(c byte) bool { return c == ' ' || c == '\t' || c == '\r' || c == '\n' }
	for i := 0; i < len(body); {
		c := body[i]
		if depth == 1 && topArray && expectElem && !isSpace(c) && c != ',' && c != ']' {
			batch++
			expectElem = false
		}
		switch c {
		case '"':
			end := i + 1 + jsonStringEnd(body[i+1:])
			keys := jsonStringReadings(body[i+1:])
			i = end + 1
			k := i
			for k < len(body) && isSpace(body[k]) {
				k++
			}
			if k >= len(body) || body[k] != ':' {
				continue
			}
			k++
			for k < len(body) && isSpace(body[k]) {
				k++
			}
			isQuery := slices.ContainsFunc(keys, func(k string) bool { return strings.EqualFold(k, "query") })
			isName := slices.ContainsFunc(keys, func(k string) bool { return strings.EqualFold(k, "operationName") })
			if k >= len(body) || body[k] != '"' || !isQuery && !isName {
				continue
			}
			val := jsonStringReadings(body[k+1:])
			if isQuery {
				docs = append(docs, val)
			} else if !seenName {
				name, seenName = val[0], true
			}
			i = k + 1 + jsonStringEnd(body[k+1:]) + 1
			continue
		case '{', '[':
			if depth == 0 && c == '[' && strings.TrimSpace(string(body[:i])) == "" {
				topArray = true
			}
			depth++
			expectElem = depth == 1
		case '}', ']':
			depth = max(depth-1, 0)
		case ',':
			expectElem = depth == 1
		}
		i++
	}
	return docs, name, batch
}

func readObject(dec *json.Decoder, body []byte) (queries []readings, name string, err error) {
	seenName := false
	for {
		key, err := dec.Token()
		if err != nil || key == json.Delim('}') {
			return queries, name, err
		}
		k, _ := key.(string)
		isQuery, isName := strings.EqualFold(k, "query"), strings.EqualFold(k, "operationName")
		val, err := dec.Token()
		if err != nil {
			if rs, ok := cutString(dec, body); ok {
				if isQuery {
					queries = append(queries, rs)
				}
				if isName && !seenName {
					name = rs[0]
				}
			}
			return queries, name, err
		}
		if s, isStr := val.(string); isStr {
			if isQuery {
				queries = append(queries, readings{s})
			}
			if isName && !seenName {
				name, seenName = s, true
			}
			continue
		}
		if err := skipValue(dec, val); err != nil {
			return queries, name, err
		}
	}
}

func skipValue(dec *json.Decoder, tok json.Token) error {
	if d, ok := tok.(json.Delim); !ok || (d != '{' && d != '[') {
		return nil
	}
	for {
		t, err := dec.Token()
		if err != nil {
			return err
		}
		if t == json.Delim('}') || t == json.Delim(']') {
			return nil
		}
		if err := skipValue(dec, t); err != nil {
			return err
		}
	}
}

func cutString(dec *json.Decoder, body []byte) (readings, bool) {
	off := int(dec.InputOffset())
	if off < 0 || off > len(body) {
		return nil, false
	}
	rest := body[off:]
	i := 0
	for i < len(rest) && strings.IndexByte(" \t\r\n:", rest[i]) >= 0 {
		i++
	}
	if i == len(rest) || rest[i] != '"' {
		return nil, false
	}
	return jsonStringReadings(rest[i+1:]), true
}

func jsonStringReadings(b []byte) readings {
	end := jsonStringEnd(b)
	var out string
	if json.Unmarshal(append(append([]byte{'"'}, b[:end]...), '"'), &out) == nil {
		return readings{out}
	}
	kept, dropped := lenientJSONString(b[:end], false), lenientJSONString(b[:end], true)
	if kept == dropped {
		return readings{kept}
	}
	return readings{kept, dropped}
}

func lenientJSONString(s []byte, drop bool) string {
	var out strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '\\' {
			out.WriteByte(c)
			continue
		}
		if i+1 == len(s) {
			break
		}
		switch e := s[i+1]; e {
		case '"', '\\', '/':
			out.WriteByte(e)
			i++
		case 'b', 'f', 'n', 'r', 't':
			out.WriteByte("\b\f\n\r\t"[strings.IndexByte("bfnrt", e)])
			i++
		case 'u':
			r, ok := hex4(s[i+2:])
			if !ok {
				i++
				for n := 0; n < 3 && i+1 < len(s) && inspect.IsHex(s[i+1]); n++ {
					i++
				}
				continue
			}
			i += 5
			if utf16.IsSurrogate(r) {
				var r2 rune
				if rest := s[i+1:]; len(rest) >= 2 && rest[0] == '\\' && rest[1] == 'u' {
					r2, _ = hex4(rest[2:])
				}
				if r = utf16.DecodeRune(r, r2); r != utf8.RuneError {
					i += 6
				}
			}
			out.WriteRune(r)
		default:
			_, size := utf8.DecodeRune(s[i+1:])
			if !drop {
				out.Write(s[i+1 : i+1+size])
			}
			i += size
		}
	}
	return out.String()
}

func hex4(b []byte) (rune, bool) {
	if len(b) < 4 {
		return 0, false
	}
	var r rune
	for _, c := range b[:4] {
		if !inspect.IsHex(c) {
			return 0, false
		}
		r = r<<4 | rune(inspect.Unhex(c))
	}
	return r, true
}

func jsonStringEnd(b []byte) int {
	end := 0
	for end < len(b) && b[end] != '"' {
		if b[end] == '\\' {
			end++
		}
		end++
	}
	return min(end, len(b))
}
