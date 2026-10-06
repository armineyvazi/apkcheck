import React, { useEffect, useMemo, useRef, useState } from 'react'

const LEVELS = ['all', 'info', 'warn', 'error']
const MAX_KEEP = 800

function inferKind(e) {
  const t = String(e?.type || '').toUpperCase()
  if (t.includes('RECORD')) return 'recording'
  if (t.includes('VALIDATE') || t.includes('INSTALL') || t.includes('LAUNCH')) return 'validate'
  if (t.includes('SECURITY') || t.includes('OBSERVATION') || t.includes('HARNESS')) return 'security'
  if (t.includes('RUNTIME') || t.includes('EMULATOR') || t.includes('AVD') || t.includes('DEVICE')) return 'runtime'
  if (t.includes('PROXY') || t.includes('CERT') || t.includes('MITM')) return 'network'
  if (t.includes('SCENARIO') || t.includes('MCP') || t.includes('AI')) return 'mcp'
  if (t.includes('BUILD') || t.includes('SIGN') || t.includes('DECOMPILE') || t.includes('REBUILD') || t.includes('IMPORT')) return 'pipeline'
  if (t.includes('ASSERT') || t.includes('FAIL')) return 'assert'
  if (e?.level === 'error') return 'error'
  if (e?.level === 'warn') return 'warn'
  return 'system'
}

function fmtTime(at) {
  if (!at) return '--:--:--'
  const d = new Date(at)
  if (Number.isNaN(d.getTime())) {
    const s = String(at)
    return s.length >= 19 ? s.slice(11, 19) : s.slice(0, 8)
  }
  return d.toLocaleTimeString(undefined, { hour12: false })
}

function levelOf(e) {
  const l = String(e?.level || '').toLowerCase()
  if (l === 'error' || l === 'err' || l === 'fatal') return 'error'
  if (l === 'warn' || l === 'warning') return 'warn'
  const t = String(e?.type || '').toUpperCase()
  if (t.includes('FAIL') || t.includes('FATAL') || t.includes('ASSERT') || t.includes('CRASH')) return 'error'
  if (t.includes('EXPIRED') || t.includes('PARTIAL') || t.includes('WARN')) return 'warn'
  // Do not treat logcat "PREDICTION_ERROR" / similar as Lab failures.
  const msg = String(e?.message || '')
  if (/FrameTracker|PREDICTION_ERROR|IME_INSETS/i.test(msg)) return 'info'
  if (l === 'info' || l === '') return 'info'
  return 'info'
}

/**
 * Live Lab console — SSE events + optional local UI action lines.
 * compact: footer strip · full: Events tab studio
 */
export default function LiveLog({
  events = [],
  mode = 'compact', // compact | full
  busy = '',
  selected = '',
  streamOk = true,
  expandedCompact = false,
  onClear,
  onToggleExpand,
  height,
}) {
  const [query, setQuery] = useState('')
  const [level, setLevel] = useState('all')
  const [kind, setKind] = useState('all')
  const [paused, setPaused] = useState(false)
  const [follow, setFollow] = useState(true)
  const [expanded, setExpanded] = useState(null)
  const scroller = useRef(null)
  const freezeRef = useRef([])

  const source = paused ? freezeRef.current : events
  if (!paused) freezeRef.current = events

  const enriched = useMemo(() => {
    return (source || []).map((e, i) => ({
      ...e,
      _i: i,
      _level: levelOf(e),
      _kind: inferKind(e),
      _key: `${e.at || ''}-${e.type || ''}-${i}-${e.message || ''}`,
    }))
  }, [source])

  const kinds = useMemo(() => {
    const s = new Set(enriched.map((e) => e._kind))
    return ['all', ...[...s].sort()]
  }, [enriched])

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase()
    return enriched.filter((e) => {
      if (level !== 'all' && e._level !== level) return false
      if (kind !== 'all' && e._kind !== kind) return false
      if (!q) return true
      const blob = `${e.type || ''} ${e.message || ''} ${e.artifact_id || ''} ${e.run_id || ''} ${JSON.stringify(e.data || {})}`.toLowerCase()
      return blob.includes(q)
    })
  }, [enriched, query, level, kind])

  const visible = mode === 'compact' ? filtered.slice(-80) : filtered.slice(-MAX_KEEP)
  const stats = useMemo(() => {
    let info = 0, warn = 0, error = 0
    for (const e of enriched) {
      if (e._level === 'error') error++
      else if (e._level === 'warn') warn++
      else info++
    }
    return { info, warn, error, total: enriched.length }
  }, [enriched])

  useEffect(() => {
    if (!follow || paused) return
    const el = scroller.current
    if (!el) return
    el.scrollTop = el.scrollHeight
  }, [visible.length, follow, paused, mode])

  const copyAll = async () => {
    const text = visible.map((e) => `${fmtTime(e.at)}\t${e._level}\t${e.type}\t${e.message || ''}`).join('\n')
    try {
      await navigator.clipboard.writeText(text)
    } catch { /* ignore */ }
  }

  const shellClass = mode === 'full'
    ? 'live-log live-log-full'
    : `live-log live-log-compact${expandedCompact ? ' pinned' : ''}`

  return (
    <div className={shellClass} style={height ? { height } : undefined}>
      <header className="live-log-bar">
        <div className="live-log-title">
          <span className={`stream-dot ${streamOk ? 'on' : 'off'}`} title={streamOk ? 'SSE connected' : 'SSE reconnecting'} />
          <strong>{mode === 'full' ? 'Live Lab Log' : 'Live log'}</strong>
          <span className="empty">{stats.total} events</span>
          {busy ? <span className="busy-pill">busy · {busy}</span> : null}
        </div>
        <div className="live-log-stats">
          <span className="st info">{stats.info} info</span>
          <span className="st warn">{stats.warn} warn</span>
          <span className="st error">{stats.error} err</span>
        </div>
        <div className="live-log-controls">
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Filter type, message, artifact…"
            aria-label="Filter logs"
          />
          <select value={level} onChange={(e) => setLevel(e.target.value)} title="Level">
            {LEVELS.map((l) => <option key={l} value={l}>{l}</option>)}
          </select>
          <select value={kind} onChange={(e) => setKind(e.target.value)} title="Category">
            {kinds.map((k) => <option key={k} value={k}>{k}</option>)}
          </select>
          <button className={`ghost icon-btn ${paused ? 'on' : ''}`} onClick={() => setPaused((p) => !p)} title="Pause stream">
            {paused ? '▶' : '❚❚'}
          </button>
          <button className={`ghost icon-btn ${follow ? 'on' : ''}`} onClick={() => setFollow((f) => !f)} title="Follow tail">↓</button>
          {mode === 'compact' && (
            <button
              className={`ghost icon-btn ${expandedCompact ? 'on' : ''}`}
              onClick={() => onToggleExpand?.()}
              title="Expand log panel"
            >⧉</button>
          )}
          <button className="ghost icon-btn" onClick={copyAll} title="Copy visible">⎘</button>
          <button className="ghost icon-btn" onClick={() => onClear?.()} title="Clear view">⌫</button>
        </div>
      </header>

      {mode === 'full' && (
        <div className="live-log-context">
          <span>Selected artifact: <code>{selected || '—'}</code></span>
          <span>DEX/Smali = ground truth · Observations ≠ vulns · NOT OBSERVED ≠ ABSENT</span>
        </div>
      )}

      <div
        className="live-log-body"
        ref={scroller}
        onScroll={(e) => {
          const el = e.currentTarget
          const atBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 40
          if (!atBottom && follow) setFollow(false)
        }}
      >
        {!visible.length && (
          <div className="live-log-empty">
            Waiting for Lab events… Import, validate, security, MCP, and runtime actions appear here live.
          </div>
        )}
        {visible.map((e) => (
          <button
            key={e._key}
            type="button"
            className={`live-row ${e._level} kind-${e._kind} ${expanded === e._key ? 'open' : ''}`}
            onClick={() => setExpanded(expanded === e._key ? null : e._key)}
          >
            <span className="t">{fmtTime(e.at)}</span>
            <span className={`lvl ${e._level}`}>{e._level}</span>
            <span className={`kdg ${e._kind}`}>{e._kind}</span>
            <span className="typ">{e.type || 'EVENT'}</span>
            <span className="msg">{e.message || '—'}</span>
            {(e.artifact_id || e.run_id) && (
              <span className="ids">
                {e.artifact_id ? <code title="artifact">{String(e.artifact_id).slice(0, 18)}</code> : null}
                {e.run_id ? <code title="run">{String(e.run_id).slice(0, 14)}</code> : null}
              </span>
            )}
            {expanded === e._key && (
              <pre className="live-detail">{JSON.stringify({
                type: e.type, level: e.level, at: e.at,
                artifact_id: e.artifact_id, run_id: e.run_id, scenario_id: e.scenario_id,
                message: e.message, data: e.data,
              }, null, 2)}</pre>
            )}
          </button>
        ))}
      </div>
    </div>
  )
}

/** Append a local UI breadcrumb into the event list (client-only). */
export function uiEvent(type, message, level = 'info', extra = {}) {
  return {
    type: `UI_${type}`,
    at: new Date().toISOString(),
    message,
    level,
    ...extra,
  }
}
