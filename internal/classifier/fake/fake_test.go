package fake

import (
	"context"
	"errors"
	"testing"

	"github.com/0x4272616E646F6E/decision-waf/internal/classifier"
	"github.com/0x4272616E646F6E/decision-waf/internal/inspect"
)

func TestReturningRecordsCalls(t *testing.T) {
	f := Returning(classifier.Verdict{Benign: 0.1, Category: "sqli", Confidence: 0.9})
	r := &inspect.Request{Path: "/x"}
	v, err := f.Classify(context.Background(), r, nil)
	if err != nil || v.Category != "sqli" || f.Calls() != 1 || f.Last() != r {
		t.Errorf("v=%+v err=%v calls=%d last=%v", v, err, f.Calls(), f.Last())
	}
}

func TestFailing(t *testing.T) {
	want := errors.New("down")
	if _, err := Failing(want).Classify(context.Background(), &inspect.Request{}, nil); !errors.Is(err, want) {
		t.Errorf("err = %v, want %v", err, want)
	}
}
