// Package tracing wires OpenTelemetry into the API process.
//
// Layout:
//   - Init builds a trace provider based on OTEL_EXPORTER_OTLP_ENDPOINT;
//     if that env var is empty, Init returns a no-op Shutdown and
//     installs a noop tracer (the SDK's default). The caller still
//     emits spans but they go nowhere — production stays silent
//     until a collector endpoint is configured.
//   - Tracer returns a named tracer bound to the shared provider so
//     packages can create spans without re-importing otel.
//
// Env contract:
//   OTEL_EXPORTER_OTLP_ENDPOINT — target for OTLP/gRPC (e.g.
//     "otel-collector:4317"). Empty disables tracing entirely.
//   OTEL_SERVICE_NAME           — service.name resource attribute;
//     defaults to "nexushub".
//   OTEL_TRACES_SAMPLER_ARG     — float 0..1 ratio for TraceIDRatio
//     sampler; defaults to 1.0 (trace everything — suitable for
//     staging/dev, operators should lower for production).
//   OTEL_EXPORTER_OTLP_INSECURE — "true" to disable TLS on the
//     exporter connection; defaults to secure.
package tracing

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
)

// defaultServiceName is what we report when OTEL_SERVICE_NAME is
// unset. Keeping the default in one place makes it easy to align
// Grafana / Loki queries across environments.
const defaultServiceName = "nexushub"

// Shutdown is the hook main.go calls on graceful exit. It flushes
// in-flight spans to the collector with the supplied context as the
// upper deadline. A nil return means the provider was not installed
// (tracing disabled), which is a benign no-op.
type Shutdown func(context.Context) error

// Config shapes the Init call for tests; production normally passes a
// zero value and lets Init read everything from the environment.
type Config struct {
	// Version surfaces as service.version on every span. Empty string
	// omits the attribute.
	Version string
}

// Init configures the global OpenTelemetry provider + propagator.
// Returns a Shutdown closure even when tracing is disabled — callers
// always `defer shutdown(ctx)` without a nil check.
func Init(ctx context.Context, cfg Config) (Shutdown, error) {
	endpoint := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	if endpoint == "" {
		// No collector configured — install only the W3C propagator so
		// inbound traceparent headers still flow through the logger,
		// and return a no-op shutdown. The global TracerProvider stays
		// at otel's default (a no-op) so any span created by handlers
		// is silently dropped.
		otel.SetTextMapPropagator(defaultPropagator())
		return func(context.Context) error { return nil }, nil
	}

	opts := []otlptracegrpc.Option{
		otlptracegrpc.WithEndpoint(stripScheme(endpoint)),
		otlptracegrpc.WithTimeout(10 * time.Second),
	}
	if insecureEnv() {
		opts = append(opts, otlptracegrpc.WithInsecure())
	}
	exporter, err := otlptrace.New(ctx, otlptracegrpc.NewClient(opts...))
	if err != nil {
		return nil, fmt.Errorf("otlp exporter: %w", err)
	}

	res, err := resource.New(ctx,
		resource.WithFromEnv(),      // OTEL_SERVICE_NAME / OTEL_RESOURCE_ATTRIBUTES
		resource.WithTelemetrySDK(), // sdk.{name,language,version}
		resource.WithAttributes(buildAttrs(cfg)...),
	)
	if err != nil {
		return nil, fmt.Errorf("resource: %w", err)
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sampler()),
	)
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(defaultPropagator())

	return tp.Shutdown, nil
}

// Tracer returns a named tracer from the global provider. Callers
// should use a stable name (package path or subsystem) so span queries
// stay predictable.
func Tracer(name string) trace.Tracer {
	return otel.Tracer(name)
}

func defaultPropagator() propagation.TextMapPropagator {
	// W3C traceparent + baggage — the defaults every modern collector
	// understands. Adding B3 later is additive if Jaeger consumers show
	// up.
	return propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	)
}

// buildAttrs composes resource attributes layered on top of whatever
// OTEL_RESOURCE_ATTRIBUTES + OTEL_SERVICE_NAME already provide. Only
// attributes not expressible via the standard env vars go here — we
// don't want to fight operators who've set these upstream.
func buildAttrs(cfg Config) []attribute.KeyValue {
	var attrs []attribute.KeyValue
	if os.Getenv("OTEL_SERVICE_NAME") == "" {
		attrs = append(attrs, semconv.ServiceName(defaultServiceName))
	}
	if cfg.Version != "" {
		attrs = append(attrs, semconv.ServiceVersion(cfg.Version))
	}
	return attrs
}

func sampler() sdktrace.Sampler {
	raw := os.Getenv("OTEL_TRACES_SAMPLER_ARG")
	if raw == "" {
		// Staging-friendly default. Operators knock this down to 0.01-
		// 0.1 in prod via env, matching OTel's standard config knob.
		return sdktrace.ParentBased(sdktrace.AlwaysSample())
	}
	ratio, err := strconv.ParseFloat(raw, 64)
	if err != nil || ratio < 0 {
		return sdktrace.ParentBased(sdktrace.AlwaysSample())
	}
	return sdktrace.ParentBased(sdktrace.TraceIDRatioBased(ratio))
}

func insecureEnv() bool {
	switch os.Getenv("OTEL_EXPORTER_OTLP_INSECURE") {
	case "true", "1", "yes":
		return true
	}
	return false
}

// stripScheme lets operators pass either "collector:4317" or
// "http://collector:4317" — otlptracegrpc.WithEndpoint wants the
// host:port form.
func stripScheme(s string) string {
	for _, p := range []string{"http://", "https://", "grpc://"} {
		if len(s) > len(p) && s[:len(p)] == p {
			return s[len(p):]
		}
	}
	return s
}
