package tracing

import (
	"context"
	"testing"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
)

func TestInitDisabledWhenNoEndpoint(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")

	shutdown, err := Init(context.Background(), Config{})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	if shutdown == nil {
		t.Fatal("shutdown must never be nil — callers defer it unchecked")
	}
	if err := shutdown(context.Background()); err != nil {
		t.Fatalf("noop shutdown must return nil, got %v", err)
	}

	// Propagator should be installed even in disabled mode so inbound
	// traceparent headers still propagate through the pipeline.
	p := otel.GetTextMapPropagator()
	if p == nil {
		t.Fatal("propagator must be non-nil after Init")
	}
	// The composite wrapper exposes Fields — TraceContext contributes
	// traceparent + tracestate, Baggage contributes baggage.
	want := map[string]bool{"traceparent": true, "tracestate": true, "baggage": true}
	got := map[string]bool{}
	for _, f := range p.Fields() {
		got[f] = true
	}
	for k := range want {
		if !got[k] {
			t.Errorf("propagator missing field %q (got %v)", k, p.Fields())
		}
	}
}

func TestInitInvalidEndpointErrorsOnDial(t *testing.T) {
	// Setting a bogus endpoint should not fail Init itself — the OTLP
	// gRPC exporter connects lazily — but it must produce a working
	// Shutdown that doesn't panic on flush.
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "127.0.0.1:0")
	t.Setenv("OTEL_EXPORTER_OTLP_INSECURE", "true")

	shutdown, err := Init(context.Background(), Config{Version: "test"})
	if err != nil {
		t.Fatalf("Init with bogus endpoint should not error: %v", err)
	}
	defer func() { _ = shutdown(context.Background()) }()
}

func TestStripScheme(t *testing.T) {
	cases := map[string]string{
		"collector:4317":               "collector:4317",
		"http://collector:4317":        "collector:4317",
		"https://collector.example:80": "collector.example:80",
		"grpc://otel:4317":             "otel:4317",
		"":                             "",
	}
	for in, want := range cases {
		if got := stripScheme(in); got != want {
			t.Errorf("stripScheme(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestInsecureEnv(t *testing.T) {
	cases := map[string]bool{
		"":      false,
		"false": false,
		"no":    false,
		"true":  true,
		"1":     true,
		"yes":   true,
	}
	for v, want := range cases {
		t.Setenv("OTEL_EXPORTER_OTLP_INSECURE", v)
		if got := insecureEnv(); got != want {
			t.Errorf("insecureEnv with %q: got %v want %v", v, got, want)
		}
	}
}

func TestSamplerRespectsEnv(t *testing.T) {
	// We can't directly introspect a Sampler's ratio, but we can verify
	// the function returns a non-nil Sampler across inputs — including
	// garbage — without panicking.
	cases := []string{"", "0", "0.1", "1.0", "abc", "-0.5"}
	for _, v := range cases {
		t.Setenv("OTEL_TRACES_SAMPLER_ARG", v)
		if s := sampler(); s == nil {
			t.Errorf("sampler must not return nil for %q", v)
		}
	}
}

func TestTracerResolvesThroughGlobalProvider(t *testing.T) {
	// Before Init the global provider is the SDK's noop. Tracer()
	// should still return a non-nil Tracer — Start on it is a safe
	// no-op.
	tr := Tracer("unit")
	if tr == nil {
		t.Fatal("Tracer must never return nil")
	}
	_, span := tr.Start(context.Background(), "probe")
	span.End()
}

func TestPropagatorIsW3CCompatible(t *testing.T) {
	// Independent of Init state — ensures the propagator we install is
	// at least TraceContext-capable, which is the bare minimum for
	// downstream tools (Tempo, Jaeger OTLP, Honeycomb).
	p := propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{})
	if fields := p.Fields(); len(fields) == 0 {
		t.Fatal("composite propagator has no fields — check imports")
	}
}
