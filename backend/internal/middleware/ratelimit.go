package middleware

import (
	"fmt"
	"math"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"

	"github.com/tomeksdev/NexusHub/backend/internal/apierror"
)

// RateLimitConfig tunes a token-bucket limiter. A single instance covers
// one "bucket class" (e.g. login attempts) — create one per route-group you
// want to throttle independently.
type RateLimitConfig struct {
	// Name is used in 429 error messages + logs. Keep it short, stable.
	Name string

	// PerMinute is the steady-state replenish rate. 0 disables the limiter
	// entirely — useful for tests and for operators who want to turn it off.
	PerMinute int

	// Burst is the bucket size — the number of requests allowed in a burst
	// before the steady-state rate takes over. Must be >= 1 when PerMinute > 0.
	Burst int

	// KeyFunc derives the bucket key from the request. Typical choices:
	// client IP, user ID (post-auth), or "ip|path" for per-endpoint keys.
	KeyFunc func(c *gin.Context) string

	// GCInterval is how often we evict idle limiters from the map. Defaults
	// to 5 minutes. Idle = untouched for at least GCInterval.
	GCInterval time.Duration

	// OnDeny, if set, is invoked on every denied request just before the
	// 429 is written. Use it to emit an audit log row or metric. The gin
	// context is still mutable at this point.
	OnDeny func(c *gin.Context)
}

// RateLimiter is a reusable keyed token-bucket limiter. The zero value is
// not usable; construct via NewRateLimiter.
type RateLimiter struct {
	cfg      RateLimitConfig
	mu       sync.Mutex
	visitors map[string]*visitor
	stop     chan struct{}
}

type visitor struct {
	limiter *rate.Limiter
	lastHit time.Time
}

// NewRateLimiter builds a limiter and starts its GC goroutine. Caller
// should Stop() it at shutdown, though leaking it is harmless in tests.
func NewRateLimiter(cfg RateLimitConfig) *RateLimiter {
	if cfg.KeyFunc == nil {
		cfg.KeyFunc = func(c *gin.Context) string { return c.ClientIP() }
	}
	if cfg.GCInterval <= 0 {
		cfg.GCInterval = 5 * time.Minute
	}
	rl := &RateLimiter{
		cfg:      cfg,
		visitors: make(map[string]*visitor),
		stop:     make(chan struct{}),
	}
	if cfg.PerMinute > 0 {
		go rl.gc()
	}
	return rl
}

// Middleware returns a Gin handler that rejects requests exceeding the limit
// with HTTP 429 and a Retry-After header. Audit-logging is left to the
// caller (register a middleware *after* this one that inspects the status).
func (rl *RateLimiter) Middleware() gin.HandlerFunc {
	if rl.cfg.PerMinute <= 0 {
		// Disabled — pass-through. Still define the handler so routing is stable.
		return func(c *gin.Context) { c.Next() }
	}
	return func(c *gin.Context) {
		key := rl.cfg.KeyFunc(c)
		lim := rl.limiterFor(key)
		res := lim.Reserve()
		if !res.OK() {
			rl.deny(c, time.Minute) // should be unreachable — Reserve only fails on misconfig
			return
		}
		delay := res.Delay()
		if delay > 0 {
			res.Cancel()
			rl.deny(c, delay)
			return
		}
		c.Next()
	}
}

// Stop halts the GC goroutine. Safe to call multiple times.
func (rl *RateLimiter) Stop() {
	select {
	case <-rl.stop:
	default:
		close(rl.stop)
	}
}

func (rl *RateLimiter) limiterFor(key string) *rate.Limiter {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	v, ok := rl.visitors[key]
	if !ok {
		// PerMinute → per-second rate. Use float math so small values like
		// PerMinute=5 translate to 0.0833… and the bucket refills correctly.
		perSecond := rate.Limit(float64(rl.cfg.PerMinute) / 60.0)
		v = &visitor{
			limiter: rate.NewLimiter(perSecond, rl.cfg.Burst),
			lastHit: time.Now(),
		}
		rl.visitors[key] = v
	} else {
		v.lastHit = time.Now()
	}
	return v.limiter
}

func (rl *RateLimiter) gc() {
	t := time.NewTicker(rl.cfg.GCInterval)
	defer t.Stop()
	for {
		select {
		case <-rl.stop:
			return
		case <-t.C:
			cutoff := time.Now().Add(-rl.cfg.GCInterval)
			rl.mu.Lock()
			for k, v := range rl.visitors {
				if v.lastHit.Before(cutoff) {
					delete(rl.visitors, k)
				}
			}
			rl.mu.Unlock()
		}
	}
}

func (rl *RateLimiter) deny(c *gin.Context, retry time.Duration) {
	secs := int(math.Ceil(retry.Seconds()))
	if secs < 1 {
		secs = 1
	}
	c.Header("Retry-After", strconv.Itoa(secs))
	if rl.cfg.OnDeny != nil {
		rl.cfg.OnDeny(c)
	}
	apierror.Write(c, http.StatusTooManyRequests,
		apierror.CodeRateLimited,
		fmt.Sprintf("%s: too many requests", rl.cfg.Name),
	)
}
