import { useEffect, useRef, useState } from 'react'
import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'

import { apiText } from '../lib/api'
import { parseProm, sum, value } from '../lib/prom'

// How often we scrape the backend. Deliberately coarse — the dashboard is
// meant for at-a-glance health, not millisecond-level tracing.
const SCRAPE_INTERVAL_MS = 5_000
// Rolling window for the rate chart. 60 points at 5s = 5 minutes.
const WINDOW = 60

interface Point {
  t: number
  reqRate: number
  errRate: number
}

interface Snapshot {
  reqTotal: number
  errTotal: number
  poolAcquired: number
  poolIdle: number
  poolTotal: number
  poolMax: number
  goGoroutines: number
  goMemBytes: number
  buildVersion: string
  buildCommit: string
}

export function MetricsPage() {
  const [snap, setSnap] = useState<Snapshot | null>(null)
  const [points, setPoints] = useState<Point[]>([])
  const [error, setError] = useState<string | null>(null)
  // Previous scrape — used to compute counter deltas. Live in a ref so the
  // polling effect doesn't resubscribe on every tick.
  const prevRef = useRef<{ reqTotal: number; errTotal: number; t: number } | null>(null)

  useEffect(() => {
    let cancelled = false
    async function tick() {
      try {
        const text = await apiText('/api/v1/metrics')
        if (cancelled) return
        const samples = parseProm(text)

        const reqTotal = sum(samples, 'nexushub_http_requests_total')
        const errTotal = sum(
          samples,
          'nexushub_http_requests_total',
          (l) => l.status !== undefined && l.status.startsWith('5'),
        )
        const build = samples.find((s) => s.name === 'nexushub_build_info')
        const next: Snapshot = {
          reqTotal,
          errTotal,
          poolAcquired: value(samples, 'nexushub_db_pool_acquired_conns') ?? 0,
          poolIdle: value(samples, 'nexushub_db_pool_idle_conns') ?? 0,
          poolTotal: value(samples, 'nexushub_db_pool_total_conns') ?? 0,
          poolMax: value(samples, 'nexushub_db_pool_max_conns') ?? 0,
          goGoroutines: value(samples, 'go_goroutines') ?? 0,
          goMemBytes: value(samples, 'go_memstats_alloc_bytes') ?? 0,
          buildVersion: build?.labels.version ?? 'unknown',
          buildCommit: build?.labels.commit ?? 'unknown',
        }
        setSnap(next)
        setError(null)

        const now = Date.now()
        const prev = prevRef.current
        if (prev) {
          const dt = Math.max(1, (now - prev.t) / 1000)
          const reqRate = Math.max(0, (reqTotal - prev.reqTotal) / dt)
          const errRate = Math.max(0, (errTotal - prev.errTotal) / dt)
          setPoints((pts) => {
            const out = [...pts, { t: now, reqRate, errRate }]
            return out.length > WINDOW ? out.slice(out.length - WINDOW) : out
          })
        }
        prevRef.current = { reqTotal, errTotal, t: now }
      } catch (e) {
        if (!cancelled) setError(e instanceof Error ? e.message : String(e))
      }
    }
    tick()
    const id = setInterval(tick, SCRAPE_INTERVAL_MS)
    return () => {
      cancelled = true
      clearInterval(id)
    }
  }, [])

  return (
    <div className="p-6 space-y-5">
      <header className="flex items-baseline justify-between">
        <h1 className="text-xl font-semibold">Metrics</h1>
        {snap && (
          <span className="text-xs text-slate-500 font-mono">
            {snap.buildVersion} · {snap.buildCommit.slice(0, 8)}
          </span>
        )}
      </header>

      {error && (
        <p className="text-rose-400 text-sm">Failed to scrape: {error}</p>
      )}

      {!snap ? (
        <p className="text-slate-400 text-sm">Loading…</p>
      ) : (
        <>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <Stat label="Requests / s" value={points.at(-1)?.reqRate.toFixed(2) ?? '—'} />
            <Stat
              label="5xx / s"
              value={points.at(-1)?.errRate.toFixed(2) ?? '—'}
              danger={(points.at(-1)?.errRate ?? 0) > 0}
            />
            <Stat
              label="DB pool"
              value={`${snap.poolAcquired}/${snap.poolMax}`}
              hint={`${snap.poolIdle} idle`}
            />
            <Stat
              label="Go memory"
              value={formatBytes(snap.goMemBytes)}
              hint={`${snap.goGoroutines} goroutines`}
            />
          </div>

          <section className="rounded-lg border border-slate-800 bg-slate-900/40 p-4">
            <h2 className="text-sm font-medium text-slate-300 mb-3">
              Request rate (last {Math.round((WINDOW * SCRAPE_INTERVAL_MS) / 60000)} min)
            </h2>
            <div className="h-60">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={points}>
                  <defs>
                    <linearGradient id="reqFill" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="#38bdf8" stopOpacity={0.6} />
                      <stop offset="100%" stopColor="#38bdf8" stopOpacity={0} />
                    </linearGradient>
                    <linearGradient id="errFill" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="#f43f5e" stopOpacity={0.6} />
                      <stop offset="100%" stopColor="#f43f5e" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid stroke="#1e293b" strokeDasharray="3 3" />
                  <XAxis
                    dataKey="t"
                    tickFormatter={(t) => new Date(t).toLocaleTimeString()}
                    stroke="#64748b"
                    fontSize={11}
                  />
                  <YAxis stroke="#64748b" fontSize={11} />
                  <Tooltip
                    contentStyle={{
                      background: '#0f172a',
                      border: '1px solid #1e293b',
                      borderRadius: 6,
                      fontSize: 12,
                    }}
                    labelFormatter={(t) => new Date(t as number).toLocaleTimeString()}
                    formatter={(v, name) => [
                      typeof v === 'number' ? v.toFixed(2) : String(v),
                      String(name),
                    ]}
                  />
                  <Area
                    type="monotone"
                    dataKey="reqRate"
                    name="req/s"
                    stroke="#38bdf8"
                    fill="url(#reqFill)"
                    strokeWidth={2}
                  />
                  <Area
                    type="monotone"
                    dataKey="errRate"
                    name="5xx/s"
                    stroke="#f43f5e"
                    fill="url(#errFill)"
                    strokeWidth={2}
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </section>
        </>
      )}
    </div>
  )
}

function Stat({
  label,
  value,
  hint,
  danger,
}: {
  label: string
  value: string
  hint?: string
  danger?: boolean
}) {
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900/40 p-4">
      <p className="text-xs text-slate-500">{label}</p>
      <p
        className={
          'text-2xl font-semibold mt-1 ' + (danger ? 'text-rose-400' : 'text-slate-100')
        }
      >
        {value}
      </p>
      {hint && <p className="text-xs text-slate-500 mt-1">{hint}</p>}
    </div>
  )
}

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  if (n < 1024 * 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(1)} MB`
  return `${(n / (1024 * 1024 * 1024)).toFixed(2)} GB`
}
