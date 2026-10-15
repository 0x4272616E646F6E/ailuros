package telemetry

import (
	"context"
	"testing"
	"time"
)

func TestSetupTracingNoopWithoutEndpoint(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "")
	shutdown, err := SetupTracing(context.Background())
	if err != nil || shutdown(context.Background()) != nil {
		t.Errorf("SetupTracing without endpoint: %v", err)
	}
}

func TestSetupTracingWithEndpoint(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:4318")
	t.Setenv("OTEL_EXPORTER_OTLP_PROTOCOL", "http/protobuf")
	shutdown, err := SetupTracing(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := shutdown(ctx); err != nil {
		t.Errorf("shutdown: %v", err)
	}
}

func TestSetupTracingProtocols(t *testing.T) {
	for _, c := range []struct {
		env     map[string]string
		wantErr bool
	}{
		{map[string]string{"OTEL_EXPORTER_OTLP_PROTOCOL": "grpc", "OTEL_EXPORTER_OTLP_ENDPOINT": "http://127.0.0.1:4317"}, false},
		{map[string]string{"OTEL_EXPORTER_OTLP_TRACES_PROTOCOL": "grpc", "OTEL_EXPORTER_OTLP_PROTOCOL": "http/json", "OTEL_EXPORTER_OTLP_ENDPOINT": "http://127.0.0.1:4317"}, false},
		{map[string]string{"OTEL_EXPORTER_OTLP_PROTOCOL": "http/json", "OTEL_EXPORTER_OTLP_ENDPOINT": "http://127.0.0.1:4318"}, true},
	} {
		for k, v := range c.env {
			t.Setenv(k, v)
		}
		shutdown, err := SetupTracing(context.Background())
		if (err != nil) != c.wantErr {
			t.Errorf("%v: err = %v, want error %v", c.env, err, c.wantErr)
		}
		if err == nil {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			_ = shutdown(ctx)
			cancel()
		}
		for k := range c.env {
			t.Setenv(k, "")
		}
	}
}

func TestSetupTracingOffSwitches(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:4318")
	for _, kv := range [][2]string{{"OTEL_TRACES_EXPORTER", "none"}, {"OTEL_SDK_DISABLED", "true"}} {
		t.Setenv(kv[0], kv[1])
		t.Setenv("OTEL_EXPORTER_OTLP_PROTOCOL", "http/json")
		if _, err := SetupTracing(context.Background()); err != nil {
			t.Errorf("%s=%s: %v, want a no-op", kv[0], kv[1], err)
		}
		t.Setenv(kv[0], "")
	}
}

func TestPropagators(t *testing.T) {
	for spec, fields := range map[string]int{"": 3, "tracecontext": 2, "baggage": 1, "none": 0, "TraceContext, Baggage": 3} {
		p, err := propagators(spec)
		if err != nil || len(p.Fields()) != fields {
			t.Errorf("%q: fields %v, err %v; want %d fields", spec, p.Fields(), err, fields)
		}
	}
	if _, err := propagators("b3"); err == nil {
		t.Error("b3: want an error, it is not supported")
	}
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:4318")
	t.Setenv("OTEL_TRACES_EXPORTER", "NONE")
	t.Setenv("OTEL_EXPORTER_OTLP_PROTOCOL", "http/json")
	if _, err := SetupTracing(context.Background()); err != nil {
		t.Errorf("OTEL_TRACES_EXPORTER=NONE: %v, want a no-op", err)
	}
}
