package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/tomeksdev/NexusHub/backend/internal/middleware"
)

func newRouter(t *testing.T, cfg middleware.RateLimitConfig) (*gin.Engine, *middleware.RateLimiter) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	rl := middleware.NewRateLimiter(cfg)
	t.Cleanup(rl.Stop)
	r.GET("/t", rl.Middleware(), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})
	return r, rl
}

func hit(r *gin.Engine, key string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/t", nil)
	// gin's ClientIP derives from RemoteAddr — the default KeyFunc uses it.
	req.RemoteAddr = key + ":1111"
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func TestRateLimitBurstThenReject(t *testing.T) {
	r, _ := newRouter(t, middleware.RateLimitConfig{
		Name:      "t",
		PerMinute: 60, // 1/s steady state
		Burst:     3,
	})

	// First three consume the burst.
	for i := 0; i < 3; i++ {
		if w := hit(r, "10.0.0.1"); w.Code != http.StatusOK {
			t.Fatalf("burst #%d: got %d, want 200", i+1, w.Code)
		}
	}
	// Fourth exceeds.
	w := hit(r, "10.0.0.1")
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", w.Code)
	}
	ra := w.Header().Get("Retry-After")
	if ra == "" {
		t.Error("missing Retry-After header")
	}
	secs, err := strconv.Atoi(ra)
	if err != nil || secs < 1 {
		t.Errorf("bad Retry-After %q", ra)
	}
}

func TestRateLimitPerKeyIsolation(t *testing.T) {
	r, _ := newRouter(t, middleware.RateLimitConfig{
		Name: "t", PerMinute: 60, Burst: 2,
	})

	// Exhaust key A.
	for i := 0; i < 2; i++ {
		hit(r, "1.1.1.1")
	}
	if w := hit(r, "1.1.1.1"); w.Code != http.StatusTooManyRequests {
		t.Fatalf("A should be limited, got %d", w.Code)
	}
	// Key B must still get its full burst.
	for i := 0; i < 2; i++ {
		if w := hit(r, "2.2.2.2"); w.Code != http.StatusOK {
			t.Fatalf("B #%d: got %d, want 200", i+1, w.Code)
		}
	}
}

func TestRateLimitDisabledWhenPerMinuteZero(t *testing.T) {
	r, _ := newRouter(t, middleware.RateLimitConfig{
		Name: "t", PerMinute: 0, Burst: 1,
	})
	for i := 0; i < 50; i++ {
		if w := hit(r, "9.9.9.9"); w.Code != http.StatusOK {
			t.Fatalf("disabled limiter blocked request #%d", i+1)
		}
	}
}

func TestRateLimitOnDenyCallback(t *testing.T) {
	calls := 0
	r, _ := newRouter(t, middleware.RateLimitConfig{
		Name: "t", PerMinute: 60, Burst: 1,
		OnDeny: func(c *gin.Context) { calls++ },
	})

	hit(r, "3.3.3.3") // allowed
	hit(r, "3.3.3.3") // denied #1
	hit(r, "3.3.3.3") // denied #2
	if calls != 2 {
		t.Errorf("OnDeny called %d times, want 2", calls)
	}
}

func TestRateLimitRefills(t *testing.T) {
	// PerMinute=600 → 10 tokens/s. With Burst=1 the bucket refills in ~100ms.
	r, _ := newRouter(t, middleware.RateLimitConfig{
		Name: "t", PerMinute: 600, Burst: 1,
	})
	if w := hit(r, "4.4.4.4"); w.Code != http.StatusOK {
		t.Fatalf("first: %d", w.Code)
	}
	if w := hit(r, "4.4.4.4"); w.Code != http.StatusTooManyRequests {
		t.Fatalf("second (immediate): %d", w.Code)
	}
	time.Sleep(150 * time.Millisecond)
	if w := hit(r, "4.4.4.4"); w.Code != http.StatusOK {
		t.Fatalf("after refill: %d", w.Code)
	}
}
