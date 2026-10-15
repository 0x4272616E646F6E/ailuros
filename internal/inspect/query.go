package inspect

import (
	"iter"
	"strings"
)

type QueryPair struct {
	Raw string
	Sep string
}

func QueryPairs(raw, seps string) iter.Seq[QueryPair] {
	return func(yield func(QueryPair) bool) {
		for raw != "" {
			end := strings.IndexAny(raw, seps)
			if end < 0 {
				end = len(raw)
			}
			p := QueryPair{Raw: raw[:end]}
			if end < len(raw) {
				p.Sep = raw[end : end+1]
				end++
			}
			if !yield(p) {
				return
			}
			raw = raw[end:]
		}
	}
}

func (p QueryPair) RawKey() string {
	k, _, _ := strings.Cut(p.Raw, "=")
	return k
}

func (p QueryPair) RawValue() string {
	_, v, _ := strings.Cut(p.Raw, "=")
	return v
}

func (p QueryPair) Key() string { return QueryUnescape(p.RawKey()) }

func (p QueryPair) Value() string { return QueryUnescape(p.RawValue()) }

func QueryUnescape(s string) string {
	if !strings.ContainsAny(s, "%+") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '+':
			b.WriteByte(' ')
		case c == '%' && i+2 < len(s) && IsHex(s[i+1]) && IsHex(s[i+2]):
			b.WriteByte(Unhex(s[i+1])<<4 | Unhex(s[i+2]))
			i += 2
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

func IsHex(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F'
}

func Unhex(c byte) byte {
	switch {
	case c <= '9':
		return c - '0'
	case c <= 'F':
		return c - 'A' + 10
	default:
		return c - 'a' + 10
	}
}
