package classifier

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"

	"github.com/0x4272616E646F6E/decision-waf/internal/inspect"
	"github.com/0x4272616E646F6E/decision-waf/internal/policy"
)

var tracer = otel.Tracer("github.com/0x4272616E646F6E/decision-waf/internal/classifier")

type Guard struct {
	inner   Classifier
	timeout time.Duration
	breaker *Breaker
}

func NewGuard(inner Classifier, timeout time.Duration, b *Breaker) *Guard {
	return &Guard{inner: inner, timeout: timeout, breaker: b}
}

func (g *Guard) Classify(ctx context.Context, r *inspect.Request, cats []policy.Category) (Verdict, error) {
	ctx, span := tracer.Start(ctx, "decision_waf.classify")
	defer span.End()
	v, err := g.classify(ctx, r, cats)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, string(ReasonOf(err)))
	} else {
		span.SetAttributes(
			attribute.Float64("decision_waf.attack_score", v.AttackScore()),
			attribute.String("decision_waf.category", v.Category),
			attribute.Float64("decision_waf.confidence", v.Confidence),
		)
	}
	return v, err
}

func (g *Guard) classify(ctx context.Context, r *inspect.Request, cats []policy.Category) (v Verdict, err error) {
	ticket, ok := g.breaker.Allow()
	if !ok {
		return Verdict{}, &Error{Reason: ReasonCircuitOpen, Err: errors.New("circuit breaker open")}
	}
	defer func() {
		if p := recover(); p != nil {
			g.breaker.Failure(ticket)
			v, err = Verdict{}, &Error{Reason: ReasonPanic, Err: fmt.Errorf("classifier panic: %v", p)}
		}
	}()

	callCtx, cancel := context.WithTimeout(ctx, g.timeout)
	defer cancel()
	v, err = g.inner.Classify(callCtx, r, cats)
	if err == nil {
		if verr := v.Validate(); verr != nil {
			v, err = Verdict{}, verr
		}
	}
	switch {
	case err == nil:
		g.breaker.Success(ticket)
		return v, nil
	case errors.Is(ctx.Err(), context.Canceled):
		g.breaker.Abort(ticket)
		return Verdict{}, &Error{Reason: ReasonCanceled, Err: ctx.Err()}
	case errors.Is(callCtx.Err(), context.DeadlineExceeded):
		g.breaker.Failure(ticket)
		return Verdict{}, &Error{Reason: ReasonTimeout, Err: err}
	case ReasonOf(err) == ReasonBadOutput:
		g.breaker.Success(ticket)
		return Verdict{}, err
	default:
		g.breaker.Failure(ticket)
		return Verdict{}, err
	}
}
