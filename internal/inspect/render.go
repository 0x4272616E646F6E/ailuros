package inspect

import (
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

func (r *Request) Render() string {
	var b strings.Builder
	line := func(key, value string) {
		if value != "" {
			fmt.Fprintf(&b, "%s: %s\n", key, clean(value))
		}
	}
	line("method", r.Method)
	line("scheme", r.Scheme)
	line("host", r.Host)
	line("path", r.Path)
	line("query", r.Query)
	line("client_ip", r.ClientIP)
	if r.TLS != nil {
		line("tls_sni", r.TLS.SNI)
		line("tls_version", r.TLS.Version)
	}
	if len(r.Signals) > 0 {
		b.WriteString("signals:\n")
		for _, s := range r.Signals {
			fmt.Fprintf(&b, "  %s\n", clean(s))
		}
	}
	if r.IsGRPC() {
		line("grpc_method", r.GRPCService+"/"+r.GRPCMethod)
	}
	if len(r.Headers) > 0 {
		b.WriteString("headers:\n")
		for _, name := range slices.Sorted(maps.Keys(r.Headers)) {
			for _, v := range r.Headers[name] {
				fmt.Fprintf(&b, "  %s: %s\n", clean(name), clean(v))
			}
		}
	}
	if len(r.Body) > 0 {
		body := r.Body
		var notes []string
		if r.BodyTruncated {
			notes = append(notes, "truncated")
		}
		if r.GRPCWebText() {
			if dec, ok := DecodeGRPCWebText(r.Body, r.BodyTruncated); ok {
				body = dec
				notes = append(notes, "decoded from grpc-web-text")
			} else {
				notes = append(notes, "grpc-web-text, not valid base64")
			}
		}
		label := "body"
		if len(notes) > 0 {
			label += " (" + strings.Join(notes, ", ") + ")"
		}
		if text, ok := textBody(body, r.BodyTruncated); ok && !r.IsGRPC() {
			fmt.Fprintf(&b, "%s:\n%s\n", label, quoteLines(text))
		} else if runs := textRuns(body); len(runs) > 0 {
			fmt.Fprintf(&b, "%s [text runs]:\n| %s\n", label, strings.Join(runs, " · "))
		} else {
			fmt.Fprintf(&b, "%s [binary, %d bytes, no readable text]\n", label, len(body))
		}
	}
	return b.String()
}

func (r *Request) SignalSummary() string {
	parts := make([]string, len(r.Signals))
	for i, s := range r.Signals {
		parts[i] = clean(strings.Replace(s, ": ", " ", 1))
	}
	return strings.Join(parts, "; ")
}

func quoteLines(text string) string {
	text = lineBreaks.Replace(text)
	return "| " + strings.ReplaceAll(text, "\n", "\n| ")
}

var breakChars = []string{"\r", "\n", "\u2028", "\u2029", "\u0085"}

var (
	lineBreaks = newBreakReplacer(func(string) string { return "\n" }, "\r\n", "\n")
	escapes    = newBreakReplacer(func(c string) string { return strings.Trim(strconv.QuoteToASCII(c), `"`) })
)

func newBreakReplacer(to func(string) string, first ...string) *strings.Replacer {
	pairs := first
	for _, c := range breakChars {
		pairs = append(pairs, c, to(c))
	}
	return strings.NewReplacer(pairs...)
}

func clean(s string) string {
	return escapes.Replace(strings.ToValidUTF8(s, "\uFFFD"))
}

func textBody(body []byte, truncated bool) (string, bool) {
	if utf8.Valid(body) {
		return string(body), true
	}
	if truncated {
		for cut := 1; cut < utf8.UTFMax && cut <= len(body); cut++ {
			if utf8.Valid(body[:len(body)-cut]) {
				return string(body[:len(body)-cut]), true
			}
		}
	}
	return "", false
}

const minTextRun = 4

func textRuns(b []byte) []string {
	var runs []string
	var cur strings.Builder
	flush := func() {
		if s := strings.TrimSpace(cur.String()); utf8.RuneCountInString(s) >= minTextRun {
			runs = append(runs, s)
		}
		cur.Reset()
	}
	for len(b) > 0 {
		r, size := utf8.DecodeRune(b)
		if (r == utf8.RuneError && size <= 1) || !unicode.IsPrint(r) {
			flush()
		} else {
			cur.WriteRune(r)
		}
		b = b[size:]
	}
	flush()
	return runs
}
