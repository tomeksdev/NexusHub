// Package metrics owns the Prometheus collectors and a Gin middleware
// that records per-request counters + latency histograms. The registry
// is exposed via a standard promhttp handler at /api/v1/metrics.
//
// Separation of concerns:
//   - metric *definitions* live here (one source of truth for label
//     cardinality so we don't accidentally create per-peer-ID series);
//   - HTTP *observation* happens in Middleware (one place that touches
//     every route);
//   - DB pool stats are polled on scrape via a Collector wrapper around
//     pgxpool.Stat().
package metrics

import (
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Registry is exported so other packages (eBPF collectors in Phase 5,
// for example) can register their own collectors without pulling in a
// global registerer. Unit tests can also use a fresh registry.
var Registry = prometheus.NewRegistry()

// HTTP metrics. Labels are method + route template + status class —
// *not* the raw path, otherwise cardinality explodes on UUID-bearing
// routes.
var (
	httpRequestsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "nexushub_http_requests_total",
		Help: "Total HTTP requests by method, route template, and status code.",
	}, []string{"method", "route", "status"})

	httpRequestDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "nexushub_http_request_duration_seconds",
		Help:    "HTTP request duration in seconds.",
		Buckets: prometheus.DefBuckets,
	}, []string{"method", "route"})

	buildInfo = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "nexushub_build_info",
		Help: "Constant 1 gauge carrying build metadata as labels.",
	}, []string{"version", "commit"})
)

func init() {
	Registry.MustRegister(httpRequestsTotal, httpRequestDuration, buildInfo)
	Registry.MustRegister(prometheus.NewGoCollector())
	Registry.MustRegister(prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}))
}

// SetBuildInfo sets the static labels on the build_info gauge. Called
// once from main with values threaded through `-ldflags -X`.
func SetBuildInfo(version, commit string) {
	buildInfo.WithLabelValues(version, commit).Set(1)
}

// Middleware observes every request. We use c.FullPath() for the route
// label — gin returns the template ("/peers/:id") rather than the
// resolved path, which is what we want for bounded cardinality.
//
// Requests that don't match any route (404s) return an empty FullPath;
// we bucket those under "/unknown" so their count is still visible.
func Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()
		route := c.FullPath()
		if route == "" {
			route = "/unknown"
		}
		status := strconv.Itoa(c.Writer.Status())
		httpRequestsTotal.WithLabelValues(c.Request.Method, route, status).Inc()
		httpRequestDuration.WithLabelValues(c.Request.Method, route).
			Observe(time.Since(start).Seconds())
	}
}

// Handler returns the promhttp scrape handler bound to our registry.
// Caller decides the route and any auth (typically admin-only).
func Handler() gin.HandlerFunc {
	h := promhttp.HandlerFor(Registry, promhttp.HandlerOpts{Registry: Registry})
	return gin.WrapH(h)
}

// ----- DB pool collector ---------------------------------------------------

// RegisterPoolCollector attaches a pgxpool-backed collector to the
// registry. Gauges are sampled on scrape — we don't maintain a goroutine
// to update them.
func RegisterPoolCollector(pool *pgxpool.Pool) {
	Registry.MustRegister(&poolCollector{pool: pool})
}

type poolCollector struct {
	pool *pgxpool.Pool
}

var (
	poolAcquired = prometheus.NewDesc(
		"nexushub_db_pool_acquired_conns",
		"Currently acquired connections.", nil, nil)
	poolIdle = prometheus.NewDesc(
		"nexushub_db_pool_idle_conns",
		"Currently idle connections.", nil, nil)
	poolTotal = prometheus.NewDesc(
		"nexushub_db_pool_total_conns",
		"Total connections in the pool.", nil, nil)
	poolMax = prometheus.NewDesc(
		"nexushub_db_pool_max_conns",
		"Configured maximum pool size.", nil, nil)
)

func (c *poolCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- poolAcquired
	ch <- poolIdle
	ch <- poolTotal
	ch <- poolMax
}

func (c *poolCollector) Collect(ch chan<- prometheus.Metric) {
	s := c.pool.Stat()
	ch <- prometheus.MustNewConstMetric(poolAcquired, prometheus.GaugeValue, float64(s.AcquiredConns()))
	ch <- prometheus.MustNewConstMetric(poolIdle, prometheus.GaugeValue, float64(s.IdleConns()))
	ch <- prometheus.MustNewConstMetric(poolTotal, prometheus.GaugeValue, float64(s.TotalConns()))
	ch <- prometheus.MustNewConstMetric(poolMax, prometheus.GaugeValue, float64(s.MaxConns()))
}
