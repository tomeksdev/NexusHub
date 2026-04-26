package middleware

import (
	"context"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// RequestIDHeader is the inbound/outbound name we accept and emit. Clients
// that already have a trace ID (e.g. a browser extension or an upstream
// proxy) can supply one here; we validate it's a UUID and fall back to a
// fresh one if not. Non-UUID inbound values are ignored rather than
// rejected so curl invocations with short debug strings still work.
const RequestIDHeader = "X-Request-ID"

// CorrelationIDHeader propagates a caller-supplied end-to-end identifier.
// Unlike RequestID we do NOT generate one when absent — it only exists
// when a chain of services is deliberately tying calls together, and an
// auto-minted value would be noise.
const CorrelationIDHeader = "X-Correlation-ID"

type ctxKey int

const (
	ctxKeyRequestID ctxKey = iota
	ctxKeyCorrelationID
)

// RequestID is a Gin middleware that ensures every request has a stable
// request ID. The ID is:
//
//   - read from the inbound X-Request-ID header if it parses as a UUID;
//   - otherwise freshly generated;
//   - stored in the gin context AND the request's context.Context, so both
//     gin-aware handlers (via c.GetString) and plain http handlers (via
//     ctx.Value) can read it;
//   - echoed in the response header before any writes happen.
//
// Install this BEFORE the access logger so log lines carry the id.
func RequestID() gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.GetHeader(RequestIDHeader)
		if _, err := uuid.Parse(id); err != nil {
			id = uuid.NewString()
		}
		c.Set(string(requestIDKey), id)
		c.Writer.Header().Set(RequestIDHeader, id)

		ctx := context.WithValue(c.Request.Context(), ctxKeyRequestID, id)
		if corr := c.GetHeader(CorrelationIDHeader); corr != "" {
			c.Set(string(correlationIDKey), corr)
			c.Writer.Header().Set(CorrelationIDHeader, corr)
			ctx = context.WithValue(ctx, ctxKeyCorrelationID, corr)
		}
		c.Request = c.Request.WithContext(ctx)
		c.Next()
	}
}

// requestIDKey / correlationIDKey are the gin.Context lookup keys. They're
// strings (not typed) because gin itself stores values as map[string]any.
type ginKey string

const (
	requestIDKey     ginKey = "nexushub.request_id"
	correlationIDKey ginKey = "nexushub.correlation_id"
)

// RequestIDFromGin reads the ID off a gin context. Returns "" if
// middleware wasn't installed — callers that treat this as a required
// invariant should panic up front at wiring time, not here.
func RequestIDFromGin(c *gin.Context) string {
	return c.GetString(string(requestIDKey))
}

// RequestIDFromContext reads the ID off a plain context.Context. Intended
// for repository or service code that doesn't have the gin.Context.
func RequestIDFromContext(ctx context.Context) string {
	v, _ := ctx.Value(ctxKeyRequestID).(string)
	return v
}

// CorrelationIDFromContext returns the caller-supplied correlation id, or
// "" when none was sent.
func CorrelationIDFromContext(ctx context.Context) string {
	v, _ := ctx.Value(ctxKeyCorrelationID).(string)
	return v
}
