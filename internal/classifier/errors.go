package classifier

import (
	"context"
	"errors"
	"fmt"
	"net/http"
)

type Reason string

const (
	ReasonTimeout       Reason = "timeout"
	ReasonUpstream5xx   Reason = "upstream_5xx"
	ReasonUpstream4xx   Reason = "upstream_4xx"
	ReasonRateLimited   Reason = "rate_limited"
	ReasonConnection    Reason = "connection"
	ReasonCircuitOpen   Reason = "circuit_open"
	ReasonBadOutput     Reason = "bad_output"
	ReasonBadResponse   Reason = "bad_response"
	ReasonUpstreamOther Reason = "upstream_other"
	ReasonInternal      Reason = "internal"
	ReasonPanic         Reason = "panic"
	ReasonCanceled      Reason = "canceled"
	ReasonProtocol      Reason = "protocol_error"
)

type Error struct {
	Reason Reason
	Status int
	Err    error
}

func (e *Error) Error() string { return string(e.Reason) + ": " + e.Err.Error() }
func (e *Error) Unwrap() error { return e.Err }

func Errorf(reason Reason, format string, args ...any) error {
	return &Error{Reason: reason, Err: fmt.Errorf(format, args...)}
}

func ReasonOf(err error) Reason {
	var e *Error
	switch {
	case errors.As(err, &e):
		return e.Reason
	case errors.Is(err, context.DeadlineExceeded):
		return ReasonTimeout
	case errors.Is(err, context.Canceled):
		return ReasonCanceled
	}
	return ReasonConnection
}

func StatusReason(code int) Reason {
	switch {
	case code == http.StatusTooManyRequests:
		return ReasonRateLimited
	case code >= 500:
		return ReasonUpstream5xx
	case code >= 400:
		return ReasonUpstream4xx
	}
	return ReasonUpstreamOther
}
