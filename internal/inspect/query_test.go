package inspect

import (
	"strconv"
	"strings"
	"testing"
)

func TestQueryPairs(t *testing.T) {
	cases := []struct {
		raw, seps string
		want      []QueryPair
	}{
		{"", "&;", nil},
		{"a=1", "&;", []QueryPair{{"a=1", ""}}},
		{"a=1;b=2&c", "&;", []QueryPair{{"a=1", ";"}, {"b=2", "&"}, {"c", ""}}},
		{"a=1;b=2&c", "&", []QueryPair{{"a=1;b=2", "&"}, {"c", ""}}},
		{"&&a=&", "&;", []QueryPair{{"", "&"}, {"", "&"}, {"a=", "&"}}},
	}
	for _, c := range cases {
		var got []QueryPair
		var back strings.Builder
		for p := range QueryPairs(c.raw, c.seps) {
			got = append(got, p)
			back.WriteString(p.Raw + p.Sep)
		}
		if len(got) != len(c.want) {
			t.Errorf("%q %q: got %v, want %v", c.raw, c.seps, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("%q %q: pair %d = %v, want %v", c.raw, c.seps, i, got[i], c.want[i])
			}
		}
		if back.String() != c.raw {
			t.Errorf("%q: rebuilt %q", c.raw, back.String())
		}
	}
	for range QueryPairs("a&b&c", "&") {
		break
	}
}

func TestQueryPairParts(t *testing.T) {
	p := QueryPair{Raw: "us%65r[pass%77ord]%zz=a+b%3D%2"}
	if p.RawKey() != "us%65r[pass%77ord]%zz" || p.Key() != "user[password]%zz" {
		t.Errorf("key %q %q", p.RawKey(), p.Key())
	}
	if p.RawValue() != "a+b%3D%2" || p.Value() != "a b=%2" {
		t.Errorf("value %q %q", p.RawValue(), p.Value())
	}
	if q := (QueryPair{Raw: "flag"}); q.Key() != "flag" || q.Value() != "" {
		t.Errorf("no '=': %q %q", q.Key(), q.Value())
	}
}

func TestQueryUnescape(t *testing.T) {
	cases := map[string]string{
		"":          "",
		"plain":     "plain",
		"a+b":       "a b",
		"%41%62%7a": "Abz",
		"%zz%4":     "%zz%4",
		"%":         "%",
		"100%25":    "100%",
		"%%41":      "%A",
		"%2B+%2b":   "+ +",
		"%E2%82%AC": "€",
	}
	for in, want := range cases {
		if got := QueryUnescape(in); got != want {
			t.Errorf("QueryUnescape(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestIsHexUnhex(t *testing.T) {
	for c := range 256 {
		n, err := strconv.ParseUint(string(rune(c)), 16, 8)
		if IsHex(byte(c)) != (err == nil) {
			t.Errorf("IsHex(%q) = %v", rune(c), IsHex(byte(c)))
		} else if err == nil && uint64(Unhex(byte(c))) != n {
			t.Errorf("Unhex(%q) = %d, want %d", rune(c), Unhex(byte(c)), n)
		}
	}
}
