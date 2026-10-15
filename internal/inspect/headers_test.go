package inspect

import (
	"slices"
	"testing"
)

func TestListElements(t *testing.T) {
	got := slices.Collect(ListElements([]string{" gzip, ,deflate ", "", "br,", ",x"}))
	if want := []string{"gzip", "deflate", "br", "x"}; !slices.Equal(got, want) {
		t.Errorf("ListElements = %q, want %q", got, want)
	}
	for range ListElements([]string{"a,b"}) {
		break
	}
}
