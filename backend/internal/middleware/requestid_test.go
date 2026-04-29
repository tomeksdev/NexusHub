package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

func newRouterWithRequestID() *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(RequestID())
	r.GET("/x", func(c *gin.Context) {
		c.String(http.StatusOK, RequestIDFromGin(c))
	})
	return r
}

func TestRequestIDGeneratesWhenAbsent(t *testing.T) {
	r := newRouterWithRequestID()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	got := w.Header().Get(RequestIDHeader)
	if got == "" {
		t.Fatal("expected generated request ID in response header")
	}
	if _, err := uuid.Parse(got); err != nil {
		t.Errorf("generated id not a UUID: %q", got)
	}
	if w.Body.String() != got {
		t.Errorf("body/header mismatch: %q vs %q", w.Body.String(), got)
	}
}

func TestRequestIDPreservesValidInbound(t *testing.T) {
	r := newRouterWithRequestID()
	incoming := uuid.NewString()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set(RequestIDHeader, incoming)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if got := w.Header().Get(RequestIDHeader); got != incoming {
		t.Errorf("expected inbound id to pass through: got %q want %q", got, incoming)
	}
}

func TestRequestIDRegeneratesGarbageInbound(t *testing.T) {
	r := newRouterWithRequestID()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set(RequestIDHeader, "not-a-uuid")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	got := w.Header().Get(RequestIDHeader)
	if _, err := uuid.Parse(got); err != nil {
		t.Errorf("should have regenerated id: %q", got)
	}
}

func TestCorrelationIDOnlyWhenSupplied(t *testing.T) {
	r := newRouterWithRequestID()

	// Absent → no header on response.
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if got := w.Header().Get(CorrelationIDHeader); got != "" {
		t.Errorf("expected no correlation header, got %q", got)
	}

	// Present → echoed.
	req = httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set(CorrelationIDHeader, "trace-abc")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if got := w.Header().Get(CorrelationIDHeader); got != "trace-abc" {
		t.Errorf("correlation echo mismatch: %q", got)
	}
}
