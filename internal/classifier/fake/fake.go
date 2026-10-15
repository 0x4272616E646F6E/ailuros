package fake

import (
	"bytes"
	"context"
	"strings"
	"sync"

	"github.com/0x4272616E646F6E/ailuros/internal/classifier"
	"github.com/0x4272616E646F6E/ailuros/internal/inspect"
	"github.com/0x4272616E646F6E/ailuros/internal/policy"
)

type Func func(context.Context, *inspect.Request, []policy.Category) (classifier.Verdict, error)

type Classifier struct {
	fn    Func
	mu    sync.Mutex
	calls int
	last  *inspect.Request
}

func New(fn Func) *Classifier { return &Classifier{fn: fn} }

func Returning(v classifier.Verdict) *Classifier {
	return New(func(context.Context, *inspect.Request, []policy.Category) (classifier.Verdict, error) { return v, nil })
}

func Failing(err error) *Classifier {
	return New(func(context.Context, *inspect.Request, []policy.Category) (classifier.Verdict, error) {
		return classifier.Verdict{}, err
	})
}

func (f *Classifier) Classify(ctx context.Context, r *inspect.Request, cats []policy.Category) (classifier.Verdict, error) {
	f.mu.Lock()
	f.calls++
	f.last = r
	f.mu.Unlock()
	return f.fn(ctx, r, cats)
}

func (f *Classifier) Calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func (f *Classifier) Last() *inspect.Request {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.last
}

var AttackVerdict = classifier.Verdict{Benign: 0.01, Category: "sqli", Confidence: 0.99}

func Attacks() *Classifier {
	return New(func(_ context.Context, r *inspect.Request, _ []policy.Category) (classifier.Verdict, error) {
		if strings.Contains(r.Path, "attack") || bytes.Contains(r.Body, []byte("attack")) {
			return AttackVerdict, nil
		}
		return classifier.Verdict{Benign: 1}, nil
	})
}
