package signals

import "strings"

const bom = "\uFEFF"

type tokenKind int

const (
	tokEOF tokenKind = iota
	tokName
	tokPunct
	tokValue
)

type token struct {
	kind tokenKind
	text string
}

type lexer struct {
	s string
	i int
}

func isNameStart(c byte) bool { return c == '_' || 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' }
func isNameChar(c byte) bool  { return isNameStart(c) || '0' <= c && c <= '9' }

func (l *lexer) next() token {
	for l.i < len(l.s) {
		c := l.s[l.i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == ',':
			l.i++
		case strings.HasPrefix(l.s[l.i:], bom):
			l.i += len(bom)
		case c == '#':
			for l.i < len(l.s) && l.s[l.i] != '\n' && l.s[l.i] != '\r' {
				l.i++
			}
		case strings.HasPrefix(l.s[l.i:], `"""`):
			l.i += 3
			for l.i < len(l.s) {
				if strings.HasPrefix(l.s[l.i:], `\"""`) {
					l.i += 4
					continue
				}
				if strings.HasPrefix(l.s[l.i:], `"""`) {
					l.i += 3
					break
				}
				l.i++
			}
			return token{kind: tokValue}
		case c == '"':
			l.i++
			for l.i < len(l.s) && l.s[l.i] != '"' && l.s[l.i] != '\n' {
				if l.s[l.i] == '\\' {
					l.i++
				}
				l.i++
			}
			l.i = min(l.i+1, len(l.s))
			return token{kind: tokValue}
		case strings.HasPrefix(l.s[l.i:], "..."):
			l.i += 3
			return token{tokPunct, "..."}
		case isNameStart(c):
			start := l.i
			for l.i < len(l.s) && isNameChar(l.s[l.i]) {
				l.i++
			}
			return token{tokName, l.s[start:l.i]}
		case c == '-' || '0' <= c && c <= '9':
			l.i++
			for l.i < len(l.s) && (isNameChar(l.s[l.i]) || strings.IndexByte(".+-", l.s[l.i]) >= 0) {
				l.i++
			}
			return token{kind: tokValue}
		default:
			l.i++
			return token{tokPunct, string(c)}
		}
	}
	return token{kind: tokEOF}
}
