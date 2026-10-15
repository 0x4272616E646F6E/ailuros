package telemetry

import (
	"cmp"
	"context"
	"fmt"
	"os"
	"strings"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

func SetupTracing(ctx context.Context) (func(context.Context) error, error) {
	noop := func(context.Context) error { return nil }
	if os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT") == "" && os.Getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT") == "" ||
		strings.EqualFold(os.Getenv("OTEL_SDK_DISABLED"), "true") || strings.EqualFold(os.Getenv("OTEL_TRACES_EXPORTER"), "none") {
		return noop, nil
	}
	prop, err := propagators(os.Getenv("OTEL_PROPAGATORS"))
	if err != nil {
		return nil, err
	}
	var exp sdktrace.SpanExporter
	switch p := cmp.Or(os.Getenv("OTEL_EXPORTER_OTLP_TRACES_PROTOCOL"), os.Getenv("OTEL_EXPORTER_OTLP_PROTOCOL"), "http/protobuf"); p {
	case "http/protobuf":
		exp, err = otlptracehttp.New(ctx)
	case "grpc":
		exp, err = otlptracegrpc.New(ctx)
	default:
		return nil, fmt.Errorf("OTLP protocol %q is not supported (want http/protobuf or grpc)", p)
	}
	if err != nil {
		return nil, err
	}
	tp := sdktrace.NewTracerProvider(sdktrace.WithBatcher(exp))
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(prop)
	return tp.Shutdown, nil
}

func propagators(spec string) (propagation.TextMapPropagator, error) {
	if strings.TrimSpace(spec) == "" {
		spec = "tracecontext,baggage"
	}
	var ps []propagation.TextMapPropagator
	for name := range strings.SplitSeq(spec, ",") {
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "tracecontext":
			ps = append(ps, propagation.TraceContext{})
		case "baggage":
			ps = append(ps, propagation.Baggage{})
		case "none":
			return propagation.NewCompositeTextMapPropagator(), nil
		default:
			return nil, fmt.Errorf("OTEL_PROPAGATORS: %q is not supported (want tracecontext, baggage, or none)", name)
		}
	}
	return propagation.NewCompositeTextMapPropagator(ps...), nil
}
