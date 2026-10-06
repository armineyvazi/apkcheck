import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { api, post, throwIfErr } from './api'

const CATEGORIES = [
  { id: 'mcp', label: 'MCP' },
  { id: 'scenario', label: 'Scenario / UI' },
  { id: 'app', label: 'App logs' },
  { id: 'kernel', label: 'Kernel' },
  { id: 'process', label: 'Process' },
  { id: 'auth', label: 'Auth / OTP' },
  { id: 'network', label: 'Mitm / Net' },
  { id: 'runtime', label: 'Runtime' },
  { id: 'error', label: 'Error' },
  { id: 'screenshot', label: 'Shot' },
  { id: 'assertion', label: 'Assert' },
  { id: 'bookmark', label: '★' },
]

const TAG_PRESETS = [
  { id: 'all', label: 'All tags' },
  { id: 'mitm', label: 'Mitmproxy' },
  { id: 'app', label: 'App' },
  { id: 'kernel', label: 'Kernel' },
  { id: 'scenario', label: 'Scenario' },
  { id: 'attack', label: 'Attack' },
  { id: 'auth', label: 'Auth' },
]

function parseClock(s) {
  const t = String(s || '').trim()
  if (!t) return null
  if (/^\d+(\.\d+)?$/.test(t)) return Math.round(Number(t) * 1000)
  const m = t.match(/^(\d+):(\d+(?:\.\d+)?)$/)
  if (m) return Math.round((Number(m[1]) * 60 + Number(m[2])) * 1000)
  return null
}

function eventTags(e) {
  const tags = Array.isArray(e?.tags) ? e.tags.map((x) => String(x).toLowerCase()) : []
  const blob = `${e?.message || ''} ${e?.event_type || ''} ${e?.category || ''} ${JSON.stringify(e?.metadata || {})}`.toLowerCase()
  if (blob.includes('mitm') || e?.category === 'network' || e?.source === 'network') tags.push('mitm')
  if (e?.category === 'app' || e?.category === 'divar' || blob.includes('app_log')) tags.push('app')
  if (e?.category === 'kernel' || blob.includes('kernel') || e?.event_type === 'KERNEL_LOG') tags.push('kernel')
  if (e?.category === 'scenario' || e?.source === 'scenario') tags.push('scenario')
  if (e?.category === 'auth' || blob.includes('auth') || blob.includes('otp')) tags.push('auth')
  if (blob.includes('attack') || blob.includes('probe') || blob.includes('harness') || blob.includes('provider')) tags.push('attack')
  return [...new Set(tags)]
}

function fmtMS(ms) {
  const total = Math.max(0, Number(ms) || 0) / 1000
  const m = Math.floor(total / 60)
  const s = total % 60
  return `${m}:${s.toFixed(2).padStart(5, '0')}`
}

function shortId(id) {
  if (!id) return '—'
  if (id.length <= 18) return id
  return `${id.slice(0, 10)}…${id.slice(-6)}`
}

function runTitle(r) {
  const scenario = r.scenario_id
    ? r.scenario_id.replace(/^builtin-/, '').replace(/-/g, ' ')
    : ''
  const pkg = r.package ? r.package.split('.').pop() : ''
  const result = (r.result || r.status || '').toLowerCase()
  if (scenario) return `${scenario}${result ? ` · ${result}` : ''}`
  if (pkg) return `${pkg}${result ? ` · ${result}` : ''}`
  return shortId(r.id)
}

function resultTone(run) {
  const r = (run?.result || run?.status || '').toLowerCase()
  if (r.includes('pass') || r === 'completed' || r === 'ok') return 'ok'
  if (r.includes('fail') || r === 'failed' || r === 'error') return 'bad'
  if (r.includes('partial') || r.includes('warn')) return 'warn'
  return 'muted'
}

function mediaURL(detail) {
  const rec = detail?.recording
  const id = rec?.recording_id || detail?.run?.recording_id
  if (!id) return ''
  const status = (rec?.status || '').toLowerCase()
  if (status === 'failed' || status === 'partial') return ''
  // Prefer server playable flag when present; don't block if media_url exists and status is finalized.
  if (detail?.playable === false && rec?.playable === false) return ''
  if (typeof rec?.size_bytes === 'number' && rec.size_bytes > 0 && rec.size_bytes < 8192) return ''
  return `/api/recordings/${encodeURIComponent(id)}/media`
}

/**
 * Test Runs studio — device recording + synchronized timeline (§35).
 */
export default function RunsPanel({ onError, focusRunId, onOpenWorkspace }) {
  const [runs, setRuns] = useState([])
  const [selected, setSelected] = useState('')
  const [detail, setDetail] = useState(null)
  const [compareId, setCompareId] = useState('')
  const [compareDetail, setCompareDetail] = useState(null)
  const [cats, setCats] = useState(() => Object.fromEntries(CATEGORIES.map((c) => [c.id, true])))
  const [query, setQuery] = useState('')
  const [tagPreset, setTagPreset] = useState('all')
  const [tFrom, setTFrom] = useState('')
  const [tTo, setTTo] = useState('')
  const [speed, setSpeed] = useState(1)
  const [t, setT] = useState(0)
  const [timelineDur, setTimelineDur] = useState(0) // event/recording clock
  const [videoDur, setVideoDur] = useState(0) // actual <video> duration (ms)
  const [playing, setPlaying] = useState(false)
  const [mediaError, setMediaError] = useState('')
  const [mediaReady, setMediaReady] = useState(false)
  const [retention, setRetention] = useState('everything')
  const [loading, setLoading] = useState(false)
  const [filter, setFilter] = useState('all') // all | recorded | failed
  const [devtoolsTab, setDevtoolsTab] = useState('timeline') // timeline | network | context
  const videoRef = useRef(null)
  const videoBRef = useRef(null)
  const scrubRef = useRef(null)
  const eventListRef = useRef(null)
  const seekingRef = useRef(false)
  const pendingSeekRef = useRef(null)
  const scrubbingRef = useRef(false)

  const refresh = useCallback(async () => {
    try {
      const list = await api('/api/sessions')
      setRuns(Array.isArray(list) ? list : [])
      const ret = await api('/api/recordings/retention').catch(() => null)
      if (ret?.policy) setRetention(ret.policy)
    } catch (e) {
      onError?.(e.message || String(e))
    }
  }, [onError])

  useEffect(() => { refresh() }, [refresh])

  const openRun = useCallback(async (id) => {
    if (!id) return
    setSelected(id)
    setLoading(true)
    setMediaError('')
    setMediaReady(false)
    setPlaying(false)
    setT(0)
    setVideoDur(0)
    setTimelineDur(0)
    setCompareId('')
    setCompareDetail(null)
    pendingSeekRef.current = null
    seekingRef.current = false
    try {
      const d = await api(`/api/sessions/${encodeURIComponent(id)}`)
      setDetail(d)
      const hint = d?.recording?.duration_ms || 0
      const lastEv = (d?.events || []).reduce((m, e) => Math.max(m, e.offset_ms || 0), 0)
      setTimelineDur(Math.max(hint, lastEv, 0))
    } catch (e) {
      onError?.(e.message || String(e))
    } finally {
      setLoading(false)
    }
  }, [onError])

  // Auto-open focus run or first recorded run
  useEffect(() => {
    if (!runs.length) return
    if (focusRunId && runs.some((r) => r.id === focusRunId)) {
      if (selected !== focusRunId) openRun(focusRunId)
      return
    }
    if (!selected) {
      const withRec = runs.find((r) => r.recording_id) || runs[0]
      if (withRec) openRun(withRec.id)
    }
  }, [runs, focusRunId]) // eslint-disable-line react-hooks/exhaustive-deps

  const openCompare = async (id) => {
    setCompareId(id)
    if (!id) { setCompareDetail(null); return }
    try {
      setCompareDetail(await api(`/api/sessions/${encodeURIComponent(id)}`))
    } catch (e) {
      onError?.(e.message || String(e))
    }
  }

  const events = useMemo(() => {
    const raw = detail?.events || []
    const q = query.toLowerCase().trim()
    const fromMs = parseClock(tFrom)
    const toMs = parseClock(tTo)
    return raw.filter((e) => {
      if (e.category) {
        // treat legacy 'divar' category as 'app' for backward compat with older runs
        const cat = e.category === 'divar' ? 'app' : e.category
        if (cats[cat] === false) {
          return false
        }
      }
      if (e.level === 'error' && cats.error === false) return false
      const off = e.offset_ms || 0
      if (fromMs != null && off < fromMs) return false
      if (toMs != null && off > toMs) return false
      if (tagPreset !== 'all') {
        const tags = eventTags(e)
        if (!tags.includes(tagPreset)) return false
      }
      if (!q) return true
      const blob = `${e.message || ''} ${e.event_type || ''} ${e.source || ''} ${(e.tags || []).join(' ')} ${JSON.stringify(e.metadata || {})}`.toLowerCase()
      return blob.includes(q)
    })
  }, [detail, cats, query, tagPreset, tFrom, tTo])

  const mediaSrc = mediaURL(detail)
  const mediaB = mediaURL(compareDetail)
  const run = detail?.run
  // Scrubber uses the longer of timeline vs video so event marks stay reachable.
  const duration = Math.max(timelineDur, videoDur, 1)

  const applyVideoSeek = useCallback((ms) => {
    const targetMs = Math.max(0, Number(ms) || 0)
    for (const v of [videoRef.current, videoBRef.current]) {
      if (!v) continue
      const maxSec = (Number.isFinite(v.duration) && v.duration > 0) ? v.duration : (videoDur / 1000 || Infinity)
      const sec = Math.min(targetMs / 1000, maxSec)
      if (!Number.isFinite(sec)) continue
      try {
        if (Math.abs((v.currentTime || 0) - sec) < 0.04) continue
        seekingRef.current = true
        v.currentTime = sec
      } catch {
        pendingSeekRef.current = targetMs
      }
    }
  }, [videoDur])

  const seekTo = useCallback((ms) => {
    const maxClock = Math.max(timelineDur, videoDur, Number(ms) || 0, 0)
    const clamped = Math.max(0, Math.min(Number(ms) || 0, maxClock || 0))
    setT(clamped)
    const v = videoRef.current
    if (!v || !mediaReady || !Number.isFinite(v.duration)) {
      pendingSeekRef.current = clamped
      return
    }
    applyVideoSeek(clamped)
  }, [timelineDur, videoDur, mediaReady, applyVideoSeek])

  // Flush pending seek once metadata is ready (fixes jump-before-load).
  useEffect(() => {
    if (!mediaReady) return
    if (pendingSeekRef.current == null) return
    const ms = pendingSeekRef.current
    pendingSeekRef.current = null
    applyVideoSeek(ms)
  }, [mediaReady, applyVideoSeek, mediaSrc])

  const togglePlay = useCallback(() => {
    const v = videoRef.current
    if (!v || !mediaSrc) return
    if (v.paused) {
      v.play()?.catch?.(() => {})
      videoBRef.current?.play?.()?.catch?.(() => {})
    } else {
      v.pause()
      videoBRef.current?.pause?.()
    }
  }, [mediaSrc])

  const around = useMemo(() => {
    const windowMs = 2500
    return (detail?.events || []).filter((e) => Math.abs((e.offset_ms || 0) - t) <= windowMs)
  }, [detail, t])

  const activeEventId = useMemo(() => {
    if (!events.length) return ''
    let best = events[0]
    for (const e of events) {
      if ((e.offset_ms || 0) <= t + 50) best = e
      else break
    }
    return best?.event_id || ''
  }, [events, t])

  useEffect(() => {
    if (!activeEventId || !eventListRef.current) return
    const el = eventListRef.current.querySelector(`[data-eid="${activeEventId}"]`)
    el?.scrollIntoView?.({ block: 'nearest', behavior: 'smooth' })
  }, [activeEventId])

  const jumpEvent = useCallback((dir) => {
    if (!events.length) return
    const idx = events.findIndex((e) => (e.offset_ms || 0) >= t)
    let next
    if (dir > 0) {
      next = idx === -1 ? events.length - 1 : Math.min(events.length - 1, idx + ((events[idx]?.offset_ms || 0) === t ? 1 : 0))
    } else if (idx === -1) {
      next = events.length - 1
    } else {
      next = idx <= 0 ? 0 : idx - 1
    }
    seekTo(events[next]?.offset_ms || 0)
  }, [events, t, seekTo])

  useEffect(() => {
    const onKey = (e) => {
      if (!detail) return
      const tag = e.target?.tagName
      if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') return
      if (e.key === ' ' || e.key === 'k') {
        e.preventDefault()
        togglePlay()
      }
      if (e.key === 'ArrowRight' && e.shiftKey) { e.preventDefault(); jumpEvent(1) }
      else if (e.key === 'ArrowLeft' && e.shiftKey) { e.preventDefault(); jumpEvent(-1) }
      else if (e.key === 'ArrowRight') { e.preventDefault(); seekTo(t + 1000) }
      else if (e.key === 'ArrowLeft') { e.preventDefault(); seekTo(Math.max(0, t - 1000)) }
      else if (e.key === 'f' && run?.failure_at_ms > 0) { e.preventDefault(); seekTo(run.failure_at_ms) }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [detail, togglePlay, jumpEvent, seekTo, t, run])

  const filteredRuns = useMemo(() => {
    return runs.filter((r) => {
      if (filter === 'recorded') return !!r.recording_id
      if (filter === 'failed') {
        const s = `${r.result || ''} ${r.status || ''}`.toLowerCase()
        return s.includes('fail') || s.includes('error')
      }
      return true
    })
  }, [runs, filter])

  const marks = useMemo(() => {
    return events.filter((e) => e.bookmark || e.level === 'error' || e.category === 'mcp' || e.category === 'screenshot' || e.category === 'assertion')
  }, [events])

  const scrubFromClientX = useCallback((clientX) => {
    const el = scrubRef.current
    if (!el || !duration) return
    const rect = el.getBoundingClientRect()
    const ratio = Math.max(0, Math.min(1, (clientX - rect.left) / Math.max(rect.width, 1)))
    seekTo(ratio * duration)
  }, [duration, seekTo])

  const onScrubPointerDown = (e) => {
    scrubbingRef.current = true
    e.currentTarget.setPointerCapture?.(e.pointerId)
    scrubFromClientX(e.clientX)
  }
  const onScrubPointerMove = (e) => {
    if (!scrubbingRef.current) return
    scrubFromClientX(e.clientX)
  }
  const onScrubPointerUp = () => { scrubbingRef.current = false }

  const applySpeed = (sp) => {
    setSpeed(sp)
    if (videoRef.current) videoRef.current.playbackRate = sp
    if (videoBRef.current) videoBRef.current.playbackRate = sp
  }

  const tone = resultTone(run)
  const progress = duration > 0 ? Math.min(100, (t / duration) * 100) : 0
  const networkEvents = useMemo(
    () => (detail?.events || []).filter((e) => e.category === 'network' || eventTags(e).includes('mitm')),
    [detail],
  )

  return (
    <div className="studio">
      <aside className="studio-side">
        <div className="studio-side-head">
          <div>
            <h2>Test runs</h2>
            <p className="empty">Recording · timeline · evidence</p>
          </div>
          <button className="ghost icon-btn" onClick={refresh} title="Refresh">↻</button>
        </div>

        <div className="studio-filters">
          {['all', 'recorded', 'failed'].map((f) => (
            <button
              key={f}
              className={`chip ${filter === f ? 'on' : ''}`}
              onClick={() => setFilter(f)}
            >
              {f === 'all' ? 'All' : f === 'recorded' ? 'Recorded' : 'Failed'}
            </button>
          ))}
        </div>

        <div className="run-cards">
          {filteredRuns.map((r) => {
            const rt = resultTone(r)
            return (
              <button
                key={r.id}
                className={`run-card ${selected === r.id ? 'active' : ''}`}
                onClick={() => openRun(r.id)}
              >
                <div className="run-card-top">
                  <span className={`dot ${rt}`} />
                  <span className="run-card-kind">{r.kind || 'run'}</span>
                  {r.recording_id ? <span className="rec-badge" title="Has recording">● REC</span> : <span className="rec-badge off">no video</span>}
                </div>
                <div className="run-card-title">{runTitle(r)}</div>
                <div className="run-card-meta">
                  <span className="run-card-id-mini">{shortId(r.id)}</span>
                  <span>{r.artifact_id ? shortId(r.artifact_id) : '—'}</span>
                </div>
              </button>
            )
          })}
          {!filteredRuns.length && (
            <div className="studio-empty-side">
              <p>No runs yet</p>
              <span>Validate with <strong>Record device</strong> on Workspace to capture video + timeline.</span>
              {onOpenWorkspace && (
                <button className="primary" onClick={onOpenWorkspace}>Go to Workspace</button>
              )}
            </div>
          )}
        </div>

        <div className="studio-retention">
          <label className="empty">Retention</label>
          <select value={retention} onChange={async (e) => {
            const policy = e.target.value
            setRetention(policy)
            try {
              await post('/api/recordings/retention', { policy, cleanup: false })
            } catch (err) { onError?.(err.message) }
          }}>
            <option value="everything">Keep everything</option>
            <option value="7d">Last 7 days</option>
            <option value="30d">Last 30 days</option>
            <option value="failed_only">Failed only</option>
            <option value="saved_only">Saved / bookmarked</option>
          </select>
          <button className="ghost" onClick={() => post('/api/recordings/retention', { policy: retention, cleanup: true })
            .then(refresh).catch((e) => onError?.(e.message))}>Cleanup</button>
        </div>
      </aside>

      <main className="studio-main">
        {!detail && !loading && (
          <div className="studio-hero-empty">
            <div className="hero-glyph">▶</div>
            <h2>Recording studio</h2>
            <p>Select a run to watch device video locked to the shared timeline — kernel logs, app behavior, mitmproxy, scenario steps, auth, and MCP on one clock.</p>
            <ol>
              <li>Workspace → enable <strong>Record device</strong></li>
              <li>Validate (or run a scenario) with an emulator/device online</li>
              <li>Open the run here — scrub, jump events, bookmark failures</li>
            </ol>
            {onOpenWorkspace && <button className="primary" onClick={onOpenWorkspace}>Open Workspace</button>}
          </div>
        )}

        {loading && <div className="studio-loading">Loading run…</div>}

        {detail && !loading && (
          <>
            <header className="studio-toolbar">
              <div className="studio-title">
                <span className={`sev tone-${tone}`}>{run?.result || run?.status || 'run'}</span>
                <div>
                  <h2 title={run?.id}>
                    {detail?.recording?.title || run?.scenario_id || shortId(run?.id || selected)}
                  </h2>
                  <p className="empty">
                    {run?.artifact_id || 'no apk'}
                    {' · '}
                    {run?.runtime_serial || run?.runtime_avd || 'no device'}
                    {run?.package ? ` · ${run.package}` : ''}
                    {detail.recording?.file_name ? ` · ${detail.recording.file_name}` : ''}
                    {detail.recording?.profile ? ` · ${detail.recording.profile}` : ''}
                  </p>
                </div>
              </div>
              <div className="studio-actions">
                {run?.failure_at_ms > 0 && (
                  <button className="primary" onClick={() => seekTo(run.failure_at_ms)}>Jump to failure</button>
                )}
                <select value={compareId} onChange={(e) => openCompare(e.target.value)} title="Compare runs">
                  <option value="">Compare…</option>
                  {runs.filter((r) => r.id !== selected).map((r) => (
                    <option key={r.id} value={r.id}>{shortId(r.id)} · {r.result || r.kind}</option>
                  ))}
                </select>
              </div>
            </header>

            <div className={`player-stage ${mediaB ? 'split' : ''}`}>
              <div className="player-pane">
                {mediaB && <div className="player-label">A · {shortId(run?.artifact_id || selected)}</div>}
                {mediaSrc ? (
                  <div className="video-frame">
                    <video
                      key={mediaSrc}
                      ref={videoRef}
                      className="device-video"
                      src={mediaSrc}
                      playsInline
                      preload="auto"
                      onPlay={() => setPlaying(true)}
                      onPause={() => setPlaying(false)}
                      onEnded={() => setPlaying(false)}
                      onLoadedMetadata={(e) => {
                        const ms = Math.round((e.target.duration || 0) * 1000)
                        if (ms > 0) {
                          setVideoDur(ms)
                          setTimelineDur((d) => Math.max(d, ms))
                        }
                        setMediaReady(true)
                        if (pendingSeekRef.current != null) {
                          const want = pendingSeekRef.current
                          pendingSeekRef.current = null
                          applyVideoSeek(want)
                        }
                      }}
                      onSeeked={() => { seekingRef.current = false }}
                      onTimeUpdate={(e) => {
                        if (seekingRef.current || scrubbingRef.current || e.target.paused) return
                        setT(Math.round(e.target.currentTime * 1000))
                      }}
                      onRateChange={(e) => setSpeed(e.target.playbackRate)}
                      onError={() => {
                        setMediaReady(false)
                        seekingRef.current = false
                        setMediaError(
                          detail?.recording?.note
                            || 'Could not load recording media — truncated MP4 (missing moov), wrong workspace, or still finalizing. Prefer ≥60s recordings.',
                        )
                      }}
                      onClick={togglePlay}
                    />
                    {!mediaReady && !mediaError && <div className="video-overlay">Preparing video…</div>}
                    {mediaError && <div className="video-overlay bad">{mediaError}</div>}
                    {mediaReady && !playing && !mediaError && (
                      <button className="play-fab" onClick={togglePlay} aria-label="Play">▶</button>
                    )}
                  </div>
                ) : (
                  <div className="video-frame empty-frame">
                    <div className="video-overlay">
                      <strong>No device video</strong>
                      <span>
                        {run?.record_enabled
                          ? (detail.recording?.note
                            || 'Recording enabled but media is missing or unplayable. Keep record enabled for ≥60s and ensure the Lab workspace is mounted correctly.')
                          : 'This run was not recorded. Re-validate with Record device enabled, or run a scenario (e.g. app-bg-probe) with record=true.'}
                      </span>
                    </div>
                  </div>
                )}
              </div>
              {mediaB && (
                <div className="player-pane">
                  <div className="player-label">B · {shortId(compareDetail?.run?.artifact_id || compareId)}</div>
                  <div className="video-frame">
                    <video ref={videoBRef} className="device-video" src={mediaB} playsInline preload="metadata" />
                  </div>
                </div>
              )}
            </div>

            {detail.recording?.note && mediaSrc && (
              <p className="empty rec-note">{detail.recording.note}
                {detail.recording.status ? ` · ${detail.recording.status}` : ''}
                {detail.recording.size_bytes ? ` · ${(detail.recording.size_bytes / 1024 / 1024).toFixed(1)} MB` : ''}
              </p>
            )}

            <div className="transport">
              <div className="transport-btns">
                <button className="ghost icon-btn" onClick={() => jumpEvent(-1)} title="Previous event (⇧←)">⟵</button>
                <button className="primary play-btn" onClick={togglePlay} disabled={!mediaSrc} title="Play/Pause (Space)">
                  {playing ? '❚❚' : '▶'}
                </button>
                <button className="ghost icon-btn" onClick={() => jumpEvent(1)} title="Next event (⇧→)">⟶</button>
                <select value={speed} onChange={(e) => applySpeed(Number(e.target.value))} title="Speed">
                  {[0.25, 0.5, 1, 1.5, 2, 4].map((s) => <option key={s} value={s}>{s}×</option>)}
                </select>
                <span className="clock">{fmtMS(t)} <em>/</em> {fmtMS(duration)}</span>
                {videoDur > 0 && videoDur < timelineDur - 500 && (
                  <span className="empty tiny">video {fmtMS(videoDur)} · timeline {fmtMS(timelineDur)}</span>
                )}
              </div>

              <div
                className="scrubber devtools-ruler"
                ref={scrubRef}
                onPointerDown={onScrubPointerDown}
                onPointerMove={onScrubPointerMove}
                onPointerUp={onScrubPointerUp}
                onPointerCancel={onScrubPointerUp}
                role="slider"
                aria-valuemin={0}
                aria-valuemax={duration}
                aria-valuenow={t}
                tabIndex={0}
                onKeyDown={(e) => {
                  if (e.key === 'ArrowRight') { e.preventDefault(); seekTo(t + 1000) }
                  if (e.key === 'ArrowLeft') { e.preventDefault(); seekTo(Math.max(0, t - 1000)) }
                }}
              >
                <div className="scrubber-ticks" aria-hidden>
                  {Array.from({ length: 11 }, (_, i) => (
                    <span key={i} style={{ left: `${i * 10}%` }}>{fmtMS((duration * i) / 10)}</span>
                  ))}
                </div>
                <div className="scrubber-track">
                  {videoDur > 0 && videoDur < duration && (
                    <div
                      className="scrubber-video-span"
                      style={{ width: `${Math.min(100, (videoDur / duration) * 100)}%` }}
                      title="Playable video range"
                    />
                  )}
                  <div className="scrubber-fill" style={{ width: `${progress}%` }} />
                  <div className="scrubber-head" style={{ left: `${progress}%` }} />
                  {marks.map((e, i) => (
                    <button
                      key={e.event_id || `m-${i}-${e.offset_ms}`}
                      type="button"
                      className={`mark ${e.category || ''} ${e.level || ''} ${e.bookmark ? 'bookmark' : ''}`}
                      style={{ left: `${Math.min(100, ((e.offset_ms || 0) / Math.max(duration, 1)) * 100)}%` }}
                      title={`${fmtMS(e.offset_ms)} · ${e.message || e.event_type}`}
                      onClick={(ev) => { ev.stopPropagation(); seekTo(e.offset_ms) }}
                    />
                  ))}
                </div>
                <div className="scrubber-legend">
                  <span><i className="lg scenario" /> Scenario</span>
                  <span><i className="lg app" /> App</span>
                  <span><i className="lg kernel" /> Kernel</span>
                  <span><i className="lg network" /> Mitm</span>
                  <span><i className="lg mcp" /> MCP</span>
                  <span><i className="lg error" /> Error</span>
                  <span><i className="lg bookmark" /> Bookmark</span>
                </div>
              </div>
            </div>

            <div className="devtools-panel">
              <div className="devtools-tabs" role="tablist">
                {[
                  { id: 'timeline', label: `Timeline (${events.length})` },
                  { id: 'network', label: `Network (${networkEvents.length})` },
                  { id: 'context', label: 'Around playhead' },
                ].map((tab) => (
                  <button
                    key={tab.id}
                    type="button"
                    role="tab"
                    aria-selected={devtoolsTab === tab.id}
                    className={`devtools-tab ${devtoolsTab === tab.id ? 'on' : ''}`}
                    onClick={() => setDevtoolsTab(tab.id)}
                  >
                    {tab.label}
                  </button>
                ))}
                <div className="devtools-tools">
                  <button
                    className="ghost"
                    type="button"
                    onClick={() => post(`/api/sessions/${encodeURIComponent(selected)}/import-proxy`, {})
                      .then(throwIfErr).then(() => openRun(selected)).catch((e) => onError?.(e.message))}
                  >
                    Import mitm
                  </button>
                  <button
                    className="ghost"
                    type="button"
                    onClick={() => post(`/api/sessions/${encodeURIComponent(selected)}/import-logcat`, {
                      serial: run?.runtime_serial || '', package: run?.package || '',
                    }).then(throwIfErr).then(() => openRun(selected)).catch((e) => onError?.(e.message))}
                  >
                    Import logcat
                  </button>
                </div>
              </div>

              {devtoolsTab === 'timeline' && (
                <div className="studio-events">
                  <div className="events-panel">
                    <div className="events-head">
                      <h3>Events @ {fmtMS(t)}</h3>
                      <input
                        value={query}
                        onChange={(e) => setQuery(e.target.value)}
                        placeholder="Filter text / host / URL…"
                      />
                    </div>
                    <div className="time-filter-row">
                      <label>
                        From
                        <input value={tFrom} onChange={(e) => setTFrom(e.target.value)} placeholder="0:00" />
                      </label>
                      <label>
                        To
                        <input value={tTo} onChange={(e) => setTTo(e.target.value)} placeholder="1:30" />
                      </label>
                      <button className="ghost" type="button" onClick={() => { setTFrom(''); setTTo('') }}>Clear</button>
                    </div>
                    <div className="cat-toggles">
                      {TAG_PRESETS.map((p) => (
                        <button
                          key={p.id}
                          type="button"
                          className={`chip ${tagPreset === p.id ? 'on' : ''}`}
                          onClick={() => setTagPreset(p.id)}
                        >
                          {p.label}
                        </button>
                      ))}
                    </div>
                    <div className="cat-toggles">
                      {CATEGORIES.map((c) => (
                        <label key={c.id} className={`chip ${cats[c.id] ? 'on' : ''}`}>
                          <input
                            type="checkbox"
                            checked={!!cats[c.id]}
                            onChange={() => setCats({ ...cats, [c.id]: !cats[c.id] })}
                          />
                          {c.label}
                        </label>
                      ))}
                    </div>
                    <div className="event-list" ref={eventListRef}>
                      {events.map((e, i) => (
                        <button
                          key={e.event_id || `e-${i}-${e.offset_ms}-${e.event_type}`}
                          data-eid={e.event_id}
                          className={`event-row ${e.event_id === activeEventId ? 'now' : ''} ${e.level || ''}`}
                          onClick={() => seekTo(e.offset_ms)}
                        >
                          <span className="t">{fmtMS(e.offset_ms)}</span>
                          <span className={`kind ${e.category || ''}`}>{e.category || e.source || 'evt'}</span>
                          <span className="msg">{e.message || e.event_type}</span>
                        </button>
                      ))}
                      {!events.length && <p className="empty pad">No events match filters.</p>}
                    </div>
                  </div>
                  <div className="context-panel compact-hint">
                    <h3>Shortcuts</h3>
                    <p className="empty keys-hint">Space play · drag ruler · click event to jump · ←/→ 1s · ⇧←/⇧→ event · F failure</p>
                    <p className="empty">Click a timeline row to seek video + playhead together. Marks on the ruler jump the same clock.</p>
                  </div>
                </div>
              )}

              {devtoolsTab === 'network' && (
                <div className="events-panel full-tab">
                  <div className="event-list">
                    {networkEvents.map((e, i) => (
                      <button
                        key={e.event_id || `n-${i}`}
                        className={`event-row ${e.event_id === activeEventId ? 'now' : ''}`}
                        onClick={() => seekTo(e.offset_ms)}
                      >
                        <span className="t">{fmtMS(e.offset_ms)}</span>
                        <span className="kind network">net</span>
                        <span className="msg">{e.message || e.event_type}</span>
                      </button>
                    ))}
                    {!networkEvents.length && (
                      <p className="empty pad">No mitm / network events — start proxy + Import mitm after a recorded run.</p>
                    )}
                  </div>
                </div>
              )}

              {devtoolsTab === 'context' && (
                <div className="context-panel full-tab">
                  <h3>Around playhead</h3>
                  <p className="empty">{fmtMS(t)} ± 2.5s · {around.length} events</p>
                  <div className="context-cards">
                    {around.slice(0, 12).map((e, i) => (
                      <button key={e.event_id || `c-${i}`} className="context-card" onClick={() => seekTo(e.offset_ms)}>
                        <span className="t">{fmtMS(e.offset_ms)}</span>
                        <strong>{e.event_type || e.category}</strong>
                        <span>{e.message}</span>
                      </button>
                    ))}
                    {!around.length && <p className="empty">Nothing near this time — scrub or jump events.</p>}
                  </div>
                  <div className="row context-actions">
                    <button className="ghost" onClick={() => post(`/api/sessions/${selected}/bookmark`, {
                      title: 'Manual note', description: `At ${fmtMS(t)}`, tags: ['manual'],
                    }).then(() => openRun(selected)).catch((e) => onError?.(e.message))}>★ Bookmark</button>
                    <button className="ghost" onClick={() => post(`/api/sessions/${selected}/screenshot`, {})
                      .then(throwIfErr).then(() => openRun(selected)).catch((e) => onError?.(e.message))}>Screenshot</button>
                  </div>
                </div>
              )}
            </div>
          </>
        )}
      </main>
    </div>
  )
}
