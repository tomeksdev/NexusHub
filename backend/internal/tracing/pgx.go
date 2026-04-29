package tracing

import (
	"context"

	"github.com/jackc/pgx/v5"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// PgxTracer implements pgx v5's QueryTracer interface so every SQL
// statement lands as an OTEL span. Attach via:
//
//	cfg.ConnConfig.Tracer = tracing.NewPgxTracer()
//
// Hot-path cost on the noop provider is negligible (otel.Tracer on a
// noop provider returns a pre-allocated noop tracer; Start returns a
// trivial span). On an enabled provider each query pays one span
// lifecycle.
type PgxTracer struct {
	tracer trace.Tracer
}

// NewPgxTracer constructs a tracer bound to the global provider. Safe
// to call before tracing.Init — the first spans will be noop, and
// once Init swaps the global provider in the tracer picks it up
// because otel.Tracer resolves lazily through a proxy.
func NewPgxTracer() *PgxTracer {
	return &PgxTracer{tracer: Tracer("pgx")}
}

type pgxSpanKey struct{}

// TraceQueryStart opens a span and stashes it on the returned context.
// Span naming uses "pgx.Query"; the actual SQL goes on the
// db.statement attribute so Jaeger / Tempo can group by template.
func (p *PgxTracer) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	ctx, span := p.tracer.Start(ctx, "pgx.Query",
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(
			attribute.String("db.system", "postgresql"),
			attribute.String("db.statement", data.SQL),
			attribute.Int("db.args.count", len(data.Args)),
		),
	)
	return context.WithValue(ctx, pgxSpanKey{}, span)
}

// TraceQueryEnd closes the span opened by TraceQueryStart, recording
// the error if any. Missing span on the context means Start was never
// called — typically a mis-plumbed context; we don't panic, just
// short-circuit.
func (p *PgxTracer) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryEndData) {
	raw := ctx.Value(pgxSpanKey{})
	if raw == nil {
		return
	}
	span, ok := raw.(trace.Span)
	if !ok {
		return
	}
	if data.Err != nil {
		span.SetStatus(codes.Error, data.Err.Error())
		span.RecordError(data.Err)
	}
	span.End()
}
