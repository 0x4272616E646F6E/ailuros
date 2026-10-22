package classifier

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/0x4272616E646F6E/decision-waf/internal/inspect"
	"github.com/0x4272616E646F6E/decision-waf/internal/policy"
)

type stub func(ctx context.Context) (Verdict, error)

func (s stub) Classify(ctx context.Context, _ *inspect.Request, _ []policy.Category) (Verdict, error) {
	return s(ctx)
}

func newGuard(inner Classifier, timeout time.Duration) (*Guard, *Breaker) {
	b := NewBreaker(testBreakerSettings, time.Now)
	return NewGuard(inner, timeout, b), b
}

func TestGuardSuccess(t *testing.T) {
	g, _ := newGuard(stub(func(context.Context) (Verdict, error) { return Verdict{Benign: 1}, nil }), time.Second)
	v, err := g.Classify(context.Background(), &inspect.Request{}, nil)
	if err != nil || v.Benign != 1 {
		t.Errorf("v=%+v err=%v", v, err)
	}
}

func TestGuardTimeout(t *testing.T) {
	slow := stub(func(ctx context.Context) (Verdict, error) { <-ctx.Done(); return Verdict{}, ctx.Err() })
	g, b := newGuard(slow, 20*time.Millisecond)
	_, err := g.Classify(context.Background(), &inspect.Request{}, nil)
	if ReasonOf(err) != ReasonTimeout {
		t.Errorf("ReasonOf = %q (%v), want timeout", ReasonOf(err), err)
	}
	for i := 0; i < 4; i++ {
		_, _ = g.Classify(context.Background(), &inspect.Request{}, nil)
	}
	if b.State() != BreakerOpen {
		t.Errorf("breaker = %v after 5 timeouts, want open", b.State())
	}
}

func TestGuardPreservesInnerReason(t *testing.T) {
	g, _ := newGuard(stub(func(context.Context) (Verdict, error) { return Verdict{}, Errorf(ReasonRateLimited, "429") }), time.Second)
	if _, err := g.Classify(context.Background(), &inspect.Request{}, nil); ReasonOf(err) != ReasonRateLimited {
		t.Errorf("ReasonOf = %q, want rate_limited", ReasonOf(err))
	}
}

func TestGuardCircuitOpenSkipsBackend(t *testing.T) {
	calls := 0
	g, b := newGuard(stub(func(context.Context) (Verdict, error) { calls++; return Verdict{}, nil }), time.Second)
	trip(t, b)
	_, err := g.Classify(context.Background(), &inspect.Request{}, nil)
	if ReasonOf(err) != ReasonCircuitOpen || calls != 0 {
		t.Errorf("ReasonOf = %q, calls = %d; want circuit_open and no backend call", ReasonOf(err), calls)
	}
}

func TestGuardCallerCancelDoesNotTripBreaker(t *testing.T) {
	block := stub(func(ctx context.Context) (Verdict, error) { <-ctx.Done(); return Verdict{}, ctx.Err() })
	g, b := newGuard(block, time.Second)
	for i := 0; i < 10; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		go func() { time.Sleep(time.Millisecond); cancel() }()
		_, err := g.Classify(ctx, &inspect.Request{}, nil)
		if ReasonOf(err) != ReasonCanceled {
			t.Fatalf("ReasonOf = %q, want canceled", ReasonOf(err))
		}
	}
	if b.State() != BreakerClosed {
		t.Errorf("breaker = %v after caller cancellations, want closed", b.State())
	}
}

func TestGuardCallerDeadlineCountsAsTimeout(t *testing.T) {
	slow := stub(func(ctx context.Context) (Verdict, error) { <-ctx.Done(); return Verdict{}, ctx.Err() })
	g, b := newGuard(slow, time.Second)
	for i := 0; i < 5; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
		_, err := g.Classify(ctx, &inspect.Request{}, nil)
		cancel()
		if ReasonOf(err) != ReasonTimeout {
			t.Fatalf("call %d: ReasonOf = %q (%v), want timeout", i, ReasonOf(err), err)
		}
	}
	if b.State() != BreakerOpen {
		t.Errorf("breaker = %v after 5 caller deadlines, want open", b.State())
	}
}

func TestGuardRecoversPanic(t *testing.T) {
	g, b := newGuard(stub(func(context.Context) (Verdict, error) { panic("boom") }), time.Second)
	_, err := g.Classify(context.Background(), &inspect.Request{}, nil)
	if ReasonOf(err) != ReasonPanic {
		t.Errorf("ReasonOf = %q, want panic", ReasonOf(err))
	}
	var e *Error
	if !errors.As(err, &e) {
		t.Errorf("err %v is not *Error", err)
	}
	_ = b
}

func TestGuardBadOutputDoesNotTripBreaker(t *testing.T) {
	g, b := newGuard(stub(func(context.Context) (Verdict, error) {
		return Verdict{}, Errorf(ReasonBadOutput, "unknown category")
	}), time.Second)
	for range 20 {
		if _, err := g.Classify(context.Background(), &inspect.Request{}, nil); ReasonOf(err) != ReasonBadOutput {
			t.Fatalf("ReasonOf = %q, want bad_output", ReasonOf(err))
		}
	}
	if s := b.State(); s != BreakerClosed {
		t.Errorf("breaker = %v after 20 bad outputs, want closed", s)
	}
}

func TestGuardValidatesVerdicts(t *testing.T) {
	g, _ := newGuard(stub(func(context.Context) (Verdict, error) { return Verdict{Benign: 1.5}, nil }), time.Second)
	if _, err := g.Classify(context.Background(), &inspect.Request{}, nil); ReasonOf(err) != ReasonBadResponse {
		t.Errorf("ReasonOf = %q (%v), want bad_response", ReasonOf(err), err)
	}
}
