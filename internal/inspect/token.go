package inspect

import "strings"

func IsToken(s string) bool {
	if s == "" {
		return false
	}
	for i := range len(s) {
		if !isTchar(s[i]) {
			return false
		}
	}
	return true
}

func isTchar(c byte) bool {
	switch {
	case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9':
		return true
	}
	return strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0
}
