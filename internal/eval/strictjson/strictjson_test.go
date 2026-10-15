package strictjson

import (
	"strings"
	"testing"
)

type inner struct {
	Name string `json:"name"`
}

type outer struct {
	Label   string              `json:"label"`
	Info    inner               `json:"info"`
	List    []inner             `json:"list,omitempty"`
	Headers map[string][]string `json:"headers,omitempty"`
	Ptr     *inner              `json:"ptr,omitempty"`
}

func TestDecode(t *testing.T) {
	ok := `{"label":"benign","info":{"name":"x"},"list":[{"name":"y"}],"headers":{"User-Agent":["a"],"user-agent":["b"]},"ptr":{"name":"z"}}`
	var v outer
	if err := Decode([]byte(ok), &v); err != nil || v.Label != "benign" || v.Ptr.Name != "z" {
		t.Fatalf("Decode = %+v, %v", v, err)
	}
	for _, c := range []struct{ name, line, want string }{
		{"case variant", `{"label":"benign","LABEL":"sqli"}`, `unknown field "LABEL"`},
		{"duplicate", `{"label":"benign","label":"sqli"}`, `duplicate key "label"`},
		{"nested case", `{"info":{"NAME":"x"}}`, `unknown field "NAME"`},
		{"in a list", `{"list":[{"name":"a","name":"b"}]}`, `duplicate key "name"`},
		{"in a map", `{"headers":{"a":["1"],"a":["2"]}}`, `duplicate key "a"`},
		{"behind a pointer", `{"ptr":{"Name":"z"}}`, `unknown field "Name"`},
		{"unknown", `{"lable":"x"}`, `unknown field "lable"`},
		{"trailing data", `{"label":"x"} {}`, "unexpected data"},
	} {
		var v outer
		if err := Decode([]byte(c.line), &v); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want %q", c.name, err, c.want)
		}
	}
}
