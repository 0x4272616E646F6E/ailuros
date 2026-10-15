package inspect

import (
	"regexp"
	"testing"
)

var tokenRE = regexp.MustCompile("^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")

func TestIsToken(t *testing.T) {
	for c := range 256 {
		s := string([]byte{byte(c)})
		if got, want := IsToken(s), tokenRE.MatchString(s); got != want {
			t.Errorf("IsToken(%q) = %v, want %v", s, got, want)
		}
	}
	for _, c := range []struct {
		s    string
		want bool
	}{{"", false}, {"GET", true}, {"x-ailuros-ja4", true}, {"a b", false}, {"a:b", false}, {"é", false}, {"chat.v1", true}} {
		if got := IsToken(c.s); got != c.want {
			t.Errorf("IsToken(%q) = %v, want %v", c.s, got, c.want)
		}
	}
}
