import { describe, expect, it } from 'vitest'

import { parseProm, sum, value } from './prom'

describe('parseProm', () => {
  it('skips HELP/TYPE comment lines', () => {
    const text = [
      '# HELP foo how many',
      '# TYPE foo counter',
      'foo 42',
    ].join('\n')
    expect(parseProm(text)).toEqual([{ name: 'foo', labels: {}, value: 42 }])
  })

  it('parses gauges and counters without labels', () => {
    const text = ['bar 3.14', 'baz 0'].join('\n')
    expect(parseProm(text)).toEqual([
      { name: 'bar', labels: {}, value: 3.14 },
      { name: 'baz', labels: {}, value: 0 },
    ])
  })

  it('parses labels with commas and spaces', () => {
    const text = 'nexushub_http_requests_total{method="GET",route="/peers",status="200"} 17'
    const [sample] = parseProm(text)
    expect(sample.name).toBe('nexushub_http_requests_total')
    expect(sample.labels).toEqual({ method: 'GET', route: '/peers', status: '200' })
    expect(sample.value).toBe(17)
  })

  it('handles escaped characters inside label values', () => {
    // Exposition format lets us escape backslash, quote, and newline.
    // A route containing quotes is realistic for path-carrying labels.
    const text = 'weird{label="a\\"b\\\\c\\nd"} 1'
    const [sample] = parseProm(text)
    expect(sample.labels.label).toBe('a"b\\c\nd')
  })

  it('ignores malformed lines rather than crashing', () => {
    const text = ['valid 1', 'this line is nonsense', 'another 2'].join('\n')
    const samples = parseProm(text)
    expect(samples.map((s) => s.name)).toEqual(['valid', 'another'])
  })

  it('parses NaN/Inf as non-finite and drops them', () => {
    const text = ['a NaN', 'b +Inf', 'c 2'].join('\n')
    const samples = parseProm(text)
    // JS Number('NaN') and Number('+Inf') → NaN/Infinity; parser filters both.
    expect(samples.map((s) => s.name)).toEqual(['c'])
  })
})

describe('sum', () => {
  const samples = parseProm(
    [
      'nexushub_http_requests_total{method="GET",status="200"} 10',
      'nexushub_http_requests_total{method="GET",status="500"} 2',
      'nexushub_http_requests_total{method="POST",status="201"} 5',
    ].join('\n'),
  )

  it('sums all samples when no predicate is given', () => {
    expect(sum(samples, 'nexushub_http_requests_total')).toBe(17)
  })

  it('filters by label predicate', () => {
    expect(
      sum(samples, 'nexushub_http_requests_total', (l) => l.status.startsWith('5')),
    ).toBe(2)
  })

  it('returns 0 for unknown metric', () => {
    expect(sum(samples, 'missing')).toBe(0)
  })
})

describe('value', () => {
  const samples = parseProm(
    [
      'nexushub_db_pool_acquired_conns 3',
      'nexushub_db_pool_max_conns 25',
    ].join('\n'),
  )

  it('returns the first match', () => {
    expect(value(samples, 'nexushub_db_pool_max_conns')).toBe(25)
  })

  it('returns undefined when absent', () => {
    expect(value(samples, 'not_there')).toBeUndefined()
  })
})
