import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { api, post, settle, asArray, throwIfErr, ApiError } from './api'
import RunsPanel from './RunsPanel'
import LiveLog, { uiEvent } from './LiveLog'
import AuthGate from './AuthGate'
import LiveDevice from './LiveDevice'

// ─── Navigation ─────────────────────────────────────────────────────────────

const NAV_MAIN = [
  { id: 'new-run',  label: 'New Run' },
  { id: 'history',  label: 'History' },
  { id: 'devices',  label: 'Devices' },
]
const NAV_TOOLS = [
  { id: 'security',  label: 'Security' },
  { id: 'proxy',     label: 'Proxy' },
  { id: 'certs',     label: 'Certificates' },
  { id: 'manifest',  label: 'Manifest' },
  { id: 'findings',  label: 'Findings' },
  { id: 'live-log',  label: 'Live Log' },
]

const BUILTIN_SCENARIOS = [
  { id: 'quick',      label: 'Quick security scan',      desc: 'Exported components, deep links, network audit' },
  { id: 'background', label: 'Background behavior',       desc: 'Observe app when backgrounded or screen-off' },
  { id: 'exported',   label: 'Exported components',       desc: 'Test all exported activities and services' },
  { id: 'deeplink',   label: 'Deep link audit',           desc: 'Enumerate and test all registered deep links' },
  { id: 'custom',     label: 'Custom scenario',           desc: 'Build your own step-by-step workflow' },
]

const DEFAULT_STEPS = [
  { kind: 'launch_app',      label: 'Launch App' },
  { kind: 'wait',            label: 'Wait 5s' },
  { kind: 'background_app',  label: 'Move to Background' },
  { kind: 'capture_logs',    label: 'Capture Logs' },
  { kind: 'record_observation', label: 'Record Observation' },
]

// ─── Helpers ─────────────────────────────────────────────────────────────────

// Map ABI string to the slug used in frida-server release filenames.
function archSlug(abi) {
  const m = { 'arm64-v8a': 'arm64', 'armeabi-v7a': 'arm', 'armeabi': 'arm', 'x86_64': 'x86_64', 'x86': 'x86' }
  return m[abi] || abi
}

// Build a GitHub releases download URL for a frida-server binary.
function fridaDownloadUrl(version, abi) {
  const slug = archSlug(abi)
  const file = `frida-server-${version}-android-${slug}.xz`
  return `https://github.com/frida/frida/releases/download/${version}/${file}`
}

function stepsToActions(steps) {
  return steps.map((s) => {
    switch (s.kind) {
      case 'launch_app':         return { launch: true }
      case 'background_app':     return { shell: 'input keyevent KEYCODE_HOME' }
      case 'capture_logs':       return { shell: 'logcat -d -t 80' }
      case 'capture_network':    return { shell: 'dumpsys connectivity | head -40' }
      case 'record_observation': return { shell: 'echo OBSERVATION_CHECKPOINT' }
      case 'wait': {
        const m = String(s.label || '').match(/(\d+)/)
        return { wait: Math.max(1, m ? Number(m[1]) : 5) * 1e9 }
      }
      default: return { shell: `echo ${s.kind}` }
    }
  })
}

function avdForInstance(inst) {
  const n = (inst?.name || '').trim()
  if (!n || n.startsWith('(')) return ''
  return n
}

function eventKey(e) {
  const id = e?.data?.event_id || e?.event_id || ''
  if (id) return `id:${id}`
  return `${e?.at || ''}|${e?.type || ''}|${e?.run_id || ''}|${e?.message || ''}`
}

function mergeEvents(prev, incoming, max = 700) {
  const map = new Map()
  for (const e of prev || []) map.set(eventKey(e), e)
  for (const e of incoming || []) {
    if (!e || (!e.type && !e.message)) continue
    map.set(eventKey(e), e)
  }
  return [...map.values()]
    .sort((a, b) => (Date.parse(a.at || '') || 0) - (Date.parse(b.at || '') || 0))
    .slice(-max)
}

// ─── App ─────────────────────────────────────────────────────────────────────

export default function App() {
  // — navigation —
  const [tab, setTab] = useState('new-run')
  const [historyTab, setHistoryTab] = useState('runs')
  const [historyRunId, setHistoryRunId] = useState(null) // when set, RunsPanel is open

  // — wizard state —
  const [wizardStep, setWizardStep]       = useState(0)
  const [wApkId, setWApkId]               = useState('')
  const [wDecompilers]                     = useState({ jadx: true, apktool: true })
  const [wAvd, setWAvd]                   = useState('Pixel_8_API_34')
  const [wRecord, setWRecord]             = useState(true)
  const [wProfile, setWProfile]           = useState('balanced')
  const [wFresh, setWFresh]               = useState(true)
  const [wScenarioType, setWScenarioType] = useState('quick')
  const [wSteps, setWSteps]               = useState(DEFAULT_STEPS.map((s) => ({ ...s })))
  const [wPkg, setWPkg]                   = useState('')
  const [wRunResult, setWRunResult]       = useState(null)
  const [wRunError, setWRunError]         = useState('')
  const wizardRunFired = useRef(false)

  // — data —
  const [health, setHealth]         = useState(false)
  const [artifacts, setArtifacts]   = useState([])
  const [events, setEvents]         = useState([])
  const [selected, setSelected]     = useState('')
  const [left, setLeft]             = useState('')
  const [right, setRight]           = useState('')
  const [busy, setBusy]             = useState('')
  const [validate, setValidate]     = useState(null)
  const [compare, setCompare]       = useState(null)
  const [proxy, setProxy]           = useState(null)
  const [certs, setCerts]           = useState(null)
  const [err, setErr]               = useState('')
  const [warns, setWarns]           = useState([])
  const [catalog, setCatalog]       = useState([])
  const [presets, setPresets]       = useState([])
  const [observations, setObservations] = useState([])
  const [secRuns, setSecRuns]       = useState([])
  const [manifest, setManifest]     = useState(null)
  const [harness, setHarness]       = useState(null)
  const [lastSecRun, setLastSecRun] = useState(null)
  const [commands, setCommands]     = useState([])
  const [runtimes, setRuntimes]     = useState(null)
  const [scenarios, setScenarios]   = useState([])
  const [lastLabRun, setLastLabRun] = useState(null)
  const [streamOk, setStreamOk]     = useState(true)
  const [logTall, setLogTall]       = useState(false)
  const [paletteOpen, setPaletteOpen] = useState(false)
  const [paletteQ, setPaletteQ]     = useState('')
  const [path, setPath]             = useState('')
  const [importErr, setImportErr]   = useState('')
  const [iocResult, setIocResult]   = useState(null)
  const [fridaStatus, setFridaStatus] = useState(null)
  const [fridaSerial, setFridaSerial] = useState('')
  const [fridaPkg, setFridaPkg]       = useState('')
  const [fridaPattern, setFridaPattern] = useState('')
  const [fridaHostPath, setFridaHostPath] = useState('')
  const [fridaEvents, setFridaEvents] = useState([])

  // Persisted live serial
  const [liveSerial, setLiveSerial] = useState(() => {
    try { return localStorage.getItem('apkcheck-live-serial') || '' } catch { return '' }
  })

  // ─ refresh ─
  const refresh = useCallback(async () => {
    const r = await settle({
      health:       () => api('/api/health'),
      artifacts:    () => api('/api/artifacts'),
      events:       () => api('/api/events'),
      proxy:        () => api('/api/proxy/status'),
      certs:        () => api('/api/certs'),
      catalog:      () => api('/api/security/catalog'),
      presets:      () => api('/api/security/presets'),
      observations: () => api('/api/security/observations'),
      runs:         () => api('/api/security/runs'),
      harness:      () => api('/api/security/harness'),
      commands:     () => api('/api/commands'),
      runtimes:     () => api('/api/runtimes'),
      scenarios:    () => api('/api/scenarios'),
    })
    const soft = []
    const take = (key, fallback = null) => {
      const item = r[key]
      if (!item) return fallback
      if (!item.ok) { soft.push(`${key}: ${item.error}`); return fallback }
      return item.data
    }
    const h = take('health', { ok: false })
    setHealth(!!h?.ok)
    setArtifacts(asArray(take('artifacts', [])))
    const evItem = r.events
    if (evItem?.ok) setEvents((prev) => mergeEvents(prev, asArray(evItem.data)))
    setProxy(take('proxy'))
    setCerts(take('certs'))
    setCatalog(asArray(take('catalog', [])))
    setPresets(asArray(take('presets', [])))
    setObservations(asArray(take('observations', [])))
    setSecRuns(asArray(take('runs', [])))
    setHarness(take('harness'))
    setCommands(asArray(take('commands', [])))
    setRuntimes(take('runtimes'))
    setScenarios(asArray(take('scenarios', [])))
    setWarns(soft)
    if (!h?.ok) {
      setErr(soft.find((s) => s.startsWith('health:')) || soft[0] || 'API health check failed')
    } else if (soft.some((s) => s.includes('/api/runtimes') || s.startsWith('runtimes:'))) {
      setErr('Devices API missing — restart lab server: apkcheck lab ui')
    } else {
      setErr('')
    }
  }, [])

  // Track active serial
  useEffect(() => {
    const running = (runtimes?.instances || []).find((i) => i.serial && (i.status === 'running' || i.status === 'device'))
    if (running?.serial) {
      setLiveSerial(running.serial)
      try { localStorage.setItem('apkcheck-live-serial', running.serial) } catch { /* ignore */ }
    }
  }, [runtimes])

  // Auto-fill package from selected artifact
  useEffect(() => {
    if (wPkg.trim()) return
    const a = artifacts.find((x) => x.id === wApkId)
    if (a?.package) setWPkg(a.package)
  }, [wApkId, artifacts, wPkg])

  // Boot: poll + SSE
  useEffect(() => {
    refresh()
    let alive = true
    const es = new EventSource('/api/events/stream')
    es.onopen  = () => { if (alive) setStreamOk(true) }
    es.onmessage = (msg) => {
      try {
        const e = JSON.parse(msg.data)
        setEvents((prev) => mergeEvents(prev, [e]))
        if (alive) setStreamOk(true)
      } catch { /* ignore */ }
    }
    es.onerror = () => { if (alive) setStreamOk(false) }
    const pullEvents = async () => {
      try {
        const feed = asArray(await api('/api/events'))
        if (!alive) return
        setEvents((prev) => mergeEvents(prev, feed))
        setStreamOk(true)
      } catch { if (alive) setStreamOk(false) }
    }
    const evTimer = setInterval(pullEvents, 2000)
    const t = setInterval(refresh, 10000)
    return () => { alive = false; es.close(); clearInterval(t); clearInterval(evTimer) }
  }, [refresh])

  // Command palette keyboard
  useEffect(() => {
    const onKey = (e) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault(); setPaletteOpen((v) => !v); setPaletteQ('')
      }
      if (e.key === 'Escape') setPaletteOpen(false)
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [])

  const originals = useMemo(() => artifacts.filter((a) => a.kind === 'original_apk'), [artifacts])

  // ─ run helper ─
  const run = async (label, fn) => {
    setBusy(label)
    setErr('')
    setEvents((prev) => mergeEvents(prev, [uiEvent('ACTION', `started: ${label}`, 'info')]))
    try {
      await fn()
      setEvents((prev) => mergeEvents(prev, [uiEvent('ACTION', `finished: ${label}`, 'info')]))
      await refresh()
    } catch (e) {
      const msg = e instanceof ApiError ? e.message : String(e?.message || e)
      setErr(msg)
      setEvents((prev) => mergeEvents(prev, [uiEvent('ACTION', `failed: ${label} — ${msg}`, 'error')]))
    } finally {
      setBusy('')
    }
  }

  // ─ wizard run ─
  const startWizardRun = useCallback(async () => {
    if (wizardRunFired.current) return
    wizardRunFired.current = true
    setWRunError('')
    setBusy('wizard-run')
    setEvents((prev) => mergeEvents(prev, [uiEvent('ACTION', 'started: wizard-run', 'info')]))
    try {
      // Decompile first
      await post('/api/decompile', { id: wApkId }).then(throwIfErr)

      const serial = (runtimes?.instances || []).find(
        (i) => i.serial && (i.status === 'running' || i.status === 'device'),
      )?.serial || ''
      const pkg = wPkg.trim() || artifacts.find((a) => a.id === wApkId)?.package || ''

      let result
      if (wScenarioType === 'custom') {
        if (!serial) throw new Error('No running emulator/device. Start one in Devices first.')
        if (!pkg) throw new Error('Package name required for custom scenario.')
        const scen = await post('/api/scenarios', {
          name: 'Wizard custom scenario',
          actions: stepsToActions(wSteps),
        })
        throwIfErr(scen)
        result = await post('/api/scenarios/run', {
          scenario_id: scen.id, artifact_id: wApkId, package: pkg,
          serial, record: wRecord, profile: wProfile,
          avd: wAvd, fresh_emulator: wFresh,
        }, { timeoutMs: 900_000 })
      } else if (wScenarioType === 'quick') {
        result = await post('/api/security/preset', {
          artifact_id: wApkId, preset_id: 'quick-android-security',
        })
      } else {
        const templateMap = {
          background: 'background-behavior',
          exported:   'exported-components',
          deeplink:   'deep-link-audit',
        }
        result = await post('/api/security/run', {
          artifact_id: wApkId,
          template_id: templateMap[wScenarioType] || wScenarioType,
          duration_sec: 30,
        })
      }
      throwIfErr(result)
      setWRunResult(result)
      if (result?.lab_run_id) { setLastLabRun(result.lab_run_id) }
      setEvents((prev) => mergeEvents(prev, [uiEvent('ACTION', 'finished: wizard-run', 'info')]))
      await refresh()
    } catch (e) {
      const msg = e instanceof ApiError ? e.message : String(e?.message || e)
      setWRunError(msg)
      setEvents((prev) => mergeEvents(prev, [uiEvent('ACTION', `failed: wizard-run — ${msg}`, 'error')]))
    } finally {
      setBusy('')
    }
  }, [wApkId, wScenarioType, wSteps, wPkg, wRecord, wProfile, wAvd, wFresh, runtimes, artifacts, refresh])

  useEffect(() => {
    if (tab === 'new-run' && wizardStep === 3 && !wRunResult && !wRunError) {
      startWizardRun()
    }
  }, [tab, wizardStep, wRunResult, wRunError, startWizardRun])

  // ─ security template ─
  const runTemplate = (templateId) => run(templateId, async () => {
    if (!selected) throw new Error('select an artifact first')
    const r = await post('/api/security/run', { artifact_id: selected, template_id: templateId, duration_sec: 12 })
    if (r.error && !r.report) throw new Error(r.error)
    setLastSecRun(r.report || r)
    setTab('security')
  })

  // ─ palette ─
  const filteredCmds = useMemo(() => {
    const q = paletteQ.toLowerCase().trim()
    return q ? commands.filter((c) => (c.title + c.cli + c.id).toLowerCase().includes(q)) : commands
  }, [commands, paletteQ])

  const execCommand = async (cmd) => {
    setPaletteOpen(false)
    switch (cmd.id) {
      case 'import':           setTab('new-run'); setWizardStep(0); break
      case 'rebuild':          if (selected) await run('rebuild', async () => { const r = await post('/api/rebuild', { id: selected }); throwIfErr(r); setSelected(r.id) }); break
      case 'validate':         if (selected) await run('validate', async () => {
        const r = await post('/api/validate', { id: selected, emulator: wAvd, duration_sec: 12, record: wRecord, profile: wProfile })
        setValidate(r.result || r)
        if (r.lab_run_id) setLastLabRun(r.lab_run_id)
      }); break
      case 'proxy-start':      await run('proxy', async () => { setProxy(await post('/api/proxy/start', {})); setTab('proxy') }); break
      case 'proxy-stop':       await run('proxy', async () => { await post('/api/proxy/stop', {}); setProxy(await api('/api/proxy/status')) }); break
      case 'certs':            setTab('certs'); break
      case 'sec-exported':     await runTemplate('exported-components'); break
      case 'sec-background':   await runTemplate('background-behavior'); break
      case 'sec-deeplink':     await runTemplate('deep-link-audit'); break
      case 'sec-network':      await runTemplate('network-audit'); break
      case 'sec-quick':        await run('preset', async () => {
        if (!selected) throw new Error('select artifact')
        await post('/api/security/preset', { artifact_id: selected, preset_id: 'quick-android-security' })
        setTab('findings')
      }); break
      case 'manifest':         if (selected) await run('manifest', async () => {
        setManifest(await api(`/api/security/manifest?artifact_id=${encodeURIComponent(selected)}`))
        setTab('manifest')
      }); break
      case 'observations':     setTab('findings'); break
      case 'harness':          setTab('security'); break
      case 'runtime-list':     setTab('devices'); break
      case 'runtime-start':    await run('start-emu', async () => {
        await post('/api/runtimes/start', { avd: wAvd, timeout_sec: 600 }, { timeoutMs: 700_000 })
        setTab('devices')
      }); break
      case 'runtime-stop-all': await run('stop-all', async () => { await post('/api/runtimes/stop-all', {}); setTab('devices') }); break
      case 'events': case 'live log': case 'log': setTab('live-log'); break
      case 'runs':             setTab('history'); setHistoryTab('runs'); break
      default:                 setTab('new-run')
    }
  }

  // ─ delete helpers ─
  const deleteArtifact = async (id) => {
    try {
      await fetch(`/api/artifacts/${encodeURIComponent(id)}`, { method: 'DELETE' })
      await refresh()
    } catch (e) {
      setErr(String(e?.message || e))
    }
  }

  const deleteSession = async (id) => {
    try {
      await fetch(`/api/sessions/${encodeURIComponent(id)}`, { method: 'DELETE' })
      await refresh()
    } catch (e) {
      setErr(String(e?.message || e))
    }
  }

  // ─ derived layout flags ─
  const isRunsStudio = tab === 'history' && historyTab === 'runs' && !!historyRunId
  const isLogFull    = tab === 'live-log'

  return (
    <div className={`app${isRunsStudio ? ' runs-mode' : ''}${isLogFull ? ' log-mode' : ''}${logTall ? ' log-tall' : ''}`}>

      {/* ── Header ── */}
      <header className="top">
        <div className="brand-block">
          <div className="brand-row">
            <span className="brand-mark" aria-hidden="true" />
            <div className="brand">APKCheck <em>Lab</em></div>
          </div>
          <div className="brand-sub">Android security workbench · v0.1</div>
        </div>
        <div className="top-actions">
          {busy && <div className="busy-pill"><span className="busy-dot" />{busy}</div>}
          <button className="ghost icon-btn" onClick={() => refresh()} title="Refresh" aria-label="Refresh">↻</button>
          <button className="ghost" onClick={() => setPaletteOpen(true)} title="Command palette (⌘K)">⌘K</button>
          <button
            className={`ghost stream-btn ${streamOk ? 'ok' : 'warn'}`}
            onClick={() => setTab('live-log')}
            title="Open live log"
          >
            <span className={`stream-dot ${streamOk ? 'on' : 'off'}`} />
            {streamOk ? 'Live' : 'Reconnect'}
          </button>
          <div className={health ? 'pill on' : 'pill'}>{health ? 'API ok' : 'API offline'}</div>
        </div>
      </header>

      {/* ── Command palette ── */}
      {paletteOpen && (
        <div className="palette-backdrop" onClick={() => setPaletteOpen(false)}>
          <div className="palette" onClick={(e) => e.stopPropagation()}>
            <input autoFocus value={paletteQ} onChange={(e) => setPaletteQ(e.target.value)} placeholder="Run a command…" />
            <div className="palette-list">
              {filteredCmds.map((c) => (
                <button key={c.id} onClick={() => execCommand(c)}>
                  <strong>{c.title}</strong>
                  <span>{c.cli}</span>
                </button>
              ))}
            </div>
          </div>
        </div>
      )}

      <div className="main">
        {/* ── Sidebar nav ── */}
        <nav className="side">
          <div className="nav-items">
            {NAV_MAIN.map((n) => (
              <button
                key={n.id}
                aria-current={tab === n.id ? 'page' : undefined}
                className={tab === n.id ? 'active' : ''}
                onClick={() => { setTab(n.id); if (n.id === 'new-run') { setWizardStep(0); setWRunResult(null); setWRunError(''); wizardRunFired.current = false } }}
              >
                {n.label}
              </button>
            ))}
          </div>
          <div className="nav-tools">
            <div className="nav-label">Tools</div>
            {NAV_TOOLS.map((n) => (
              <button key={n.id} aria-current={tab === n.id ? 'page' : undefined} className={tab === n.id ? 'active' : ''} onClick={() => setTab(n.id)}>{n.label}</button>
            ))}
          </div>
        </nav>

        {/* ── Workspace ── */}
        <section className="workspace">
          {err && <div className="card alert" role="alert">{err}</div>}
          {!!warns.length && !err && (
            <div className="card alert soft">Partial refresh: {warns.slice(0, 3).join(' · ')}</div>
          )}

          {/* ── NEW RUN WIZARD ── */}
          {tab === 'new-run' && (
            <div className="wizard">
              <WizardProgress step={wizardStep} />

              {wizardStep === 0 && (
                <div className="wizard-step">
                  <h2 className="wizard-title">Select APK</h2>
                  <p className="empty">Choose an existing APK or import a new one from disk.</p>

                  <div className="wizard-section">
                    <div className="wizard-section-label">Import from path</div>
                    <div className="row">
                      <input
                        value={path}
                        onChange={(e) => { setPath(e.target.value); setImportErr('') }}
                        placeholder="/absolute/path/to/app.apk"
                        aria-label="APK file path"
                      />
                      <button
                        className="primary"
                        disabled={!!busy || !path.trim()}
                        onClick={() => run('import', async () => {
                          setImportErr('')
                          const a = await post('/api/import', { path })
                          throwIfErr(a)
                          setWApkId(a.id)
                          setWizardStep(1)
                        })}
                      >
                        Import
                      </button>
                    </div>
                    {importErr && <p className="empty" style={{ color: 'var(--bad)' }}>{importErr}</p>}
                  </div>

                  {originals.length > 0 && (
                    <div className="wizard-section">
                      <div className="wizard-section-label">Or select existing</div>
                      <div className="apk-list">
                        {originals.map((a) => (
                          <button
                            key={a.id}
                            className={`apk-card${wApkId === a.id ? ' selected' : ''}`}
                            onClick={() => setWApkId(a.id)}
                          >
                            <span className="apk-card-id">{a.id}</span>
                            <span className="apk-card-meta">{a.label || a.package || a.kind}</span>
                            {wApkId === a.id && <span className="apk-check">✓</span>}
                          </button>
                        ))}
                      </div>
                    </div>
                  )}

                  {originals.length === 0 && !path.trim() && (
                    <p className="empty" style={{ marginTop: '1rem' }}>No APKs imported yet. Enter a path above to get started.</p>
                  )}

                  <div className="wizard-actions">
                    <button className="primary" disabled={!wApkId} onClick={() => setWizardStep(1)}>
                      Continue →
                    </button>
                  </div>
                </div>
              )}

              {wizardStep === 1 && (
                <div className="wizard-step">
                  <h2 className="wizard-title">Analysis setup</h2>
                  <p className="empty">Configure decompilers, emulator, and recording options.</p>

                  <div className="wizard-section">
                    <div className="wizard-section-label">Decompilers</div>
                    <div className="wizard-checks">
                      {[
                        { id: 'jadx',       label: 'JADX',       recommended: true },
                        { id: 'apktool',    label: 'Apktool',    recommended: true },
                        { id: 'cfr',        label: 'CFR',        recommended: false },
                        { id: 'fernflower', label: 'FernFlower', recommended: false },
                      ].map((d) => (
                        <label key={d.id} className={`wizard-check${wDecompilers[d.id] ? ' on' : ''}`}>
                          <input
                            type="checkbox"
                            defaultChecked={!!wDecompilers[d.id]}
                            onChange={() => { /* future: toggle wDecompilers */ }}
                          />
                          {d.label}
                          {d.recommended && <span className="rec-tag">recommended</span>}
                        </label>
                      ))}
                    </div>
                  </div>

                  <div className="wizard-section">
                    <div className="wizard-section-label">Emulator</div>
                    <div className="row" style={{ maxWidth: 360 }}>
                      <input value={wAvd} onChange={(e) => setWAvd(e.target.value)} placeholder="AVD name" aria-label="AVD name" />
                    </div>
                    {(runtimes?.emulators_running || 0) > 0 && (
                      <p className="empty" style={{ color: 'var(--ok)' }}>
                        ● {runtimes.emulators_running} emulator running
                      </p>
                    )}
                    {(runtimes?.emulators_running || 0) === 0 && (
                      <p className="empty" style={{ color: 'var(--warn)' }}>
                        No emulator running — you can still run static security templates without one.
                      </p>
                    )}
                  </div>

                  <div className="wizard-section">
                    <div className="wizard-section-label">Recording</div>
                    <div className="wizard-checks">
                      <label className={`wizard-check${wRecord ? ' on' : ''}`}>
                        <input type="checkbox" checked={wRecord} onChange={(e) => setWRecord(e.target.checked)} />
                        Record screen
                      </label>
                      <label className={`wizard-check${wFresh ? ' on' : ''}`}>
                        <input type="checkbox" checked={wFresh} onChange={(e) => setWFresh(e.target.checked)} />
                        Fresh emulator (wipe + reboot)
                      </label>
                    </div>
                    {wRecord && (
                      <div className="row" style={{ maxWidth: 200, marginTop: 'var(--sp-2)' }}>
                        <select value={wProfile} onChange={(e) => setWProfile(e.target.value)} aria-label="Recording quality">
                          <option value="low">Low quality</option>
                          <option value="balanced">Balanced</option>
                          <option value="high">High quality</option>
                        </select>
                      </div>
                    )}
                  </div>

                  <div className="wizard-actions">
                    <button className="ghost" onClick={() => setWizardStep(0)}>← Back</button>
                    <button className="primary" onClick={() => setWizardStep(2)}>Continue →</button>
                  </div>
                </div>
              )}

              {wizardStep === 2 && (
                <div className="wizard-step">
                  <h2 className="wizard-title">Scenario</h2>
                  <p className="empty">Choose what to test. The system handles the rest.</p>

                  <div className="wizard-section">
                    <div className="scenario-cards">
                      {BUILTIN_SCENARIOS.map((s) => (
                        <button
                          key={s.id}
                          className={`scenario-card${wScenarioType === s.id ? ' selected' : ''}`}
                          onClick={() => setWScenarioType(s.id)}
                        >
                          <span className="scenario-card-title">{s.label}</span>
                          <span className="scenario-card-desc">{s.desc}</span>
                          {wScenarioType === s.id && <span className="apk-check">✓</span>}
                        </button>
                      ))}
                    </div>
                  </div>

                  {wScenarioType === 'custom' && (
                    <div className="wizard-section">
                      <div className="wizard-section-label">Package name</div>
                      <div className="row" style={{ maxWidth: 360 }}>
                        <input
                          value={wPkg}
                          onChange={(e) => setWPkg(e.target.value)}
                          placeholder="com.example.app"
                          aria-label="Package name"
                        />
                        {wApkId && artifacts.find((a) => a.id === wApkId)?.package && (
                          <button className="ghost" onClick={() => {
                            const a = artifacts.find((x) => x.id === wApkId)
                            if (a?.package) setWPkg(a.package)
                          }}>Use APK pkg</button>
                        )}
                      </div>
                      <div className="wizard-section-label" style={{ marginTop: 'var(--sp-4)' }}>Steps</div>
                      <div className="builder">
                        {wSteps.map((s, i) => (
                          <div key={i} className="builder-step">
                            <span className="kind">{s.kind}</span>
                            <input
                              value={s.label}
                              onChange={(e) => {
                                const next = [...wSteps]; next[i] = { ...s, label: e.target.value }; setWSteps(next)
                              }}
                            />
                            <button className="ghost" onClick={() => setWSteps(wSteps.filter((_, j) => j !== i))}>✕</button>
                          </div>
                        ))}
                      </div>
                      <div className="row" style={{ marginTop: 'var(--sp-2)' }}>
                        {['launch_app', 'wait', 'background_app', 'capture_logs', 'capture_network', 'record_observation'].map((k) => (
                          <button key={k} className="ghost" style={{ fontSize: 'var(--t-xs)' }}
                            onClick={() => setWSteps([...wSteps, { kind: k, label: k === 'wait' ? 'Wait 5s' : k }])}>
                            + {k}
                          </button>
                        ))}
                      </div>
                    </div>
                  )}

                  <div className="wizard-actions">
                    <button className="ghost" onClick={() => setWizardStep(1)}>← Back</button>
                    <button
                      className="primary"
                      disabled={!!busy}
                      onClick={() => {
                        wizardRunFired.current = false
                        setWRunResult(null)
                        setWRunError('')
                        setWizardStep(3)
                      }}
                    >
                      Start Run →
                    </button>
                  </div>
                </div>
              )}

              {wizardStep === 3 && (
                <div className="wizard-step">
                  <h2 className="wizard-title">
                    {wRunResult ? 'Run complete' : wRunError ? 'Run failed' : 'Running…'}
                  </h2>

                  {!wRunResult && !wRunError && (
                    <div className="run-progress">
                      <div className="run-progress-row"><span className="busy-dot" style={{ flexShrink: 0 }} />Decompiling APK</div>
                      <div className="run-progress-row dim">Running {BUILTIN_SCENARIOS.find((s) => s.id === wScenarioType)?.label || wScenarioType}</div>
                      <div className="run-progress-row dim">Collecting results</div>
                      <p className="empty" style={{ marginTop: 'var(--sp-4)' }}>
                        This may take 30–120 seconds. Watch the Live Log below for real-time progress.
                      </p>
                    </div>
                  )}

                  {wRunError && (
                    <div className="card alert" role="alert" style={{ margin: '0 0 var(--sp-4)' }}>
                      {wRunError}
                    </div>
                  )}

                  {wRunResult && (
                    <div className="run-result">
                      <div className="run-result-summary">
                        <span className="stage ok">✓ Completed</span>
                        {wRunResult.lab_run_id && (
                          <span className="pill">Run ID: {wRunResult.lab_run_id}</span>
                        )}
                      </div>
                      {wRunResult.observations?.length > 0 && (
                        <p className="empty">{wRunResult.observations.length} observation(s) recorded</p>
                      )}
                      <div className="row" style={{ marginTop: 'var(--sp-4)' }}>
                        {lastLabRun && (
                          <button className="primary" onClick={() => {
                            setTab('history')
                            setHistoryTab('runs')
                            setHistoryRunId(lastLabRun)
                          }}>Watch recording</button>
                        )}
                        <button className="ghost" onClick={() => setTab('findings')}>View findings</button>
                        <button className="ghost" onClick={() => {
                          setWizardStep(0); setWRunResult(null); setWRunError('');
                          wizardRunFired.current = false
                        }}>New run</button>
                      </div>
                    </div>
                  )}

                  {(wRunError) && (
                    <div className="wizard-actions">
                      <button className="ghost" onClick={() => setWizardStep(2)}>← Back</button>
                      <button className="primary" onClick={() => {
                        wizardRunFired.current = false
                        setWRunResult(null)
                        setWRunError('')
                        setWizardStep(3)
                      }}>Retry</button>
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

          {/* ── HISTORY ── */}
          {tab === 'history' && !isRunsStudio && (
            <div>
              <div className="history-tabs">
                {['runs', 'apks', 'compare'].map((t) => (
                  <button key={t} className={`history-tab${historyTab === t ? ' active' : ''}`}
                    onClick={() => { setHistoryTab(t); setHistoryRunId(null) }}>
                    {t === 'runs' ? 'Runs' : t === 'apks' ? 'APKs' : 'Compare'}
                  </button>
                ))}
              </div>

              {historyTab === 'runs' && (
                <div className="card">
                  <h2>Recorded runs</h2>
                  <p className="empty">Click a run to open the recording studio. Authorized testing only.</p>
                  {secRuns.length === 0 && <p className="empty">No runs yet — complete a New Run to see results here.</p>}
                  <table>
                    <thead><tr><th>ID</th><th>Template</th><th>Status</th><th>Started</th><th></th></tr></thead>
                    <tbody>
                      {secRuns.slice().reverse().map((r) => (
                        <tr key={r.id}>
                          <td style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--t-xs)' }}>{r.id || r.run_id}</td>
                          <td>{r.template_id || '—'}</td>
                          <td><span className={`stage ${r.status === 'ok' || r.status === 'done' ? 'ok' : ''}`}>{r.status || '—'}</span></td>
                          <td style={{ color: 'var(--text-3)', fontSize: 'var(--t-xs)' }}>{r.started_at ? new Date(r.started_at).toLocaleString() : '—'}</td>
                          <td>
                            <div style={{ display: 'flex', gap: 'var(--sp-2)' }}>
                              <button className="ghost" onClick={() => {
                                setHistoryRunId(r.id || r.run_id)
                              }}>View</button>
                              <button className="ghost" title="Delete" onClick={() => deleteSession(r.id || r.run_id)} aria-label="Delete run">✕</button>
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  {lastLabRun && (
                    <div style={{ marginTop: 'var(--sp-3)' }}>
                      <button className="primary" onClick={() => setHistoryRunId(lastLabRun)}>
                        Open latest run · {lastLabRun}
                      </button>
                    </div>
                  )}
                </div>
              )}

              {historyTab === 'apks' && (
                <div className="card">
                  <h2>APK library</h2>
                  <p className="empty">All imported and generated artifacts. Decompiled projects are stored alongside their source.</p>
                  {artifacts.length === 0 && <p className="empty">No artifacts yet.</p>}
                  <table>
                    <thead><tr><th>ID</th><th>Kind</th><th>Label</th><th>Package</th><th></th></tr></thead>
                    <tbody>
                      {artifacts.map((a) => (
                        <tr key={a.id}>
                          <td style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--t-xs)' }}>{a.id}</td>
                          <td><span className="kind">{a.kind}</span></td>
                          <td>{a.label || '—'}</td>
                          <td style={{ fontSize: 'var(--t-xs)' }}>{a.package || '—'}</td>
                          <td>
                            <div style={{ display: 'flex', gap: 'var(--sp-2)' }}>
                              <button className="ghost" onClick={() => { setSelected(a.id); setTab('new-run') }}>Select</button>
                              <button className="ghost" title="Delete" onClick={() => deleteArtifact(a.id)} aria-label="Delete artifact">✕</button>
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}

              {historyTab === 'compare' && (
                <div className="card">
                  <h2>Compare variants</h2>
                  <div className="row">
                    <select value={left} onChange={(e) => setLeft(e.target.value)}>
                      <option value="">left…</option>
                      {artifacts.map((a) => <option key={a.id} value={a.id}>{a.id} · {a.kind}</option>)}
                    </select>
                    <select value={right} onChange={(e) => setRight(e.target.value)}>
                      <option value="">right…</option>
                      {artifacts.map((a) => <option key={a.id} value={a.id}>{a.id} · {a.kind}</option>)}
                    </select>
                    <button className="primary" disabled={!left || !right || !!busy} onClick={() => run('compare', async () => {
                      const r = await post('/api/compare', { left, right }); throwIfErr(r); setCompare(r)
                    })}>Compare</button>
                  </div>
                  {compare && (
                    <table style={{ marginTop: 'var(--sp-3)' }}>
                      <thead><tr><th>Metric</th><th>Left</th><th>Right</th><th>Match</th></tr></thead>
                      <tbody>
                        {(compare.metrics || []).map((m) => (
                          <tr key={m.name}>
                            <td>{m.name}</td><td>{m.left}</td><td>{m.right}</td>
                            <td className={m.equal ? 'stage ok' : 'stage bad'}>{m.equal ? '✓' : '✗'}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  )}
                </div>
              )}
            </div>
          )}

          {/* RunsPanel — opens when a run is selected in History */}
          {isRunsStudio && (
            <RunsPanel
              onError={(msg) => setErr(msg)}
              focusRunId={historyRunId}
              onOpenWorkspace={() => { setTab('history'); setHistoryRunId(null) }}
            />
          )}

          {/* ── DEVICES ── */}
          {tab === 'devices' && (
            <div className="grid devices-live-grid">
              <LiveDevice serial={liveSerial} title="Live Android" />
              <div>
                <div className="card" style={{ marginBottom: 'var(--sp-3)' }}>
                  <h2>Android runtimes</h2>
                  <p className="host-banner">
                    Emulator runs on the <strong>Lab host</strong> (Linux + KVM).
                    Set <code>APKCHECK_ADB_HOST</code> to reach a remote ADB server. Authorized testing only.
                  </p>
                  {!runtimes && <p className="empty">No runtime snapshot — rebuild &amp; redeploy Lab so /api/runtimes exists.</p>}
                  {(runtimes?.avd_configured ?? 0) === 0 && (
                    <div className="callout">
                      <strong>No AVDs on this host</strong>
                      <p>On the Lab host: <code>scripts/setup-laptop-emulator.sh</code></p>
                    </div>
                  )}
                  <p className="empty">Running: <strong>{runtimes?.emulators_running ?? 0}</strong> · AVDs: {runtimes?.avd_configured ?? 0} · Devices: {runtimes?.devices_online ?? 0}</p>
                  <table>
                    <thead><tr><th>Kind</th><th>Name</th><th>Serial</th><th>Status</th><th>API</th><th></th></tr></thead>
                    <tbody>
                      {(runtimes?.instances || []).map((inst, i) => {
                        const avd = avdForInstance(inst)
                        return (
                          <tr key={i}>
                            <td className="kind">{inst.kind}</td>
                            <td>{inst.name || '—'}</td>
                            <td style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--t-xs)' }}>{inst.serial || '—'}</td>
                            <td><span className={`stage ${inst.status === 'running' || inst.status === 'device' ? 'ok' : ''}`}>{inst.status}</span></td>
                            <td>{inst.api || '—'}</td>
                            <td>
                              {inst.kind === 'emulator' && inst.status === 'running' && (
                                <button className="ghost" onClick={() => run('stop', async () => {
                                  await post('/api/runtimes/stop', { serial: inst.serial || '', avd: avd || undefined })
                                })}>Stop</button>
                              )}
                              {inst.kind === 'emulator' && inst.status === 'stopped' && avd && (
                                <button className="ghost" onClick={() => run('start', async () => {
                                  await post('/api/runtimes/start', { avd, timeout_sec: 600 }, { timeoutMs: 700_000 })
                                })}>Start</button>
                              )}
                            </td>
                          </tr>
                        )
                      })}
                    </tbody>
                  </table>
                </div>
                <div className="card">
                  <h2>Controls</h2>
                  <div className="row">
                    <input value={wAvd} onChange={(e) => setWAvd(e.target.value)} placeholder="AVD name" />
                  </div>
                  <div className="row">
                    <button className="primary" disabled={!!busy} onClick={() => run('start', async () => {
                      await post('/api/runtimes/start', { avd: wAvd, timeout_sec: 600 }, { timeoutMs: 700_000 })
                    })}>{busy === 'start' ? 'Starting…' : 'Start'}</button>
                    <button className="ghost" disabled={!!busy} onClick={() => run('restart', async () => {
                      await post('/api/runtimes/restart', { avd: wAvd, timeout_sec: 600 }, { timeoutMs: 700_000 })
                    })}>Restart</button>
                    <button className="ghost" disabled={!!busy} onClick={() => run('stop-all', async () => {
                      if (!confirm('Stop all running emulators?')) return
                      await post('/api/runtimes/stop-all', {})
                    })}>Stop all</button>
                  </div>
                  <p className="empty">CLI: apkcheck lab runtime list|start|stop|restart</p>
                </div>
              </div>
            </div>
          )}

          {/* ── SECURITY ── */}
          {tab === 'security' && (
            <div className="grid">
              {/* ── Static security templates ── */}
              <div className="card">
                <h2>Security test library</h2>
                <p className="empty">Templates collect <em>observations</em> with evidence — never auto-claimed vulnerabilities. Authorized testing only.</p>
                <ArtifactSelect artifacts={artifacts} value={selected} onChange={setSelected} />
                <div className="sec-list">
                  {catalog.map((t) => (
                    <div key={t.id} className="sec-item">
                      <div>
                        <strong>{t.name}</strong>
                        <div className="empty">{t.category} · {t.description}</div>
                      </div>
                      <button className="primary" disabled={!selected || !!busy} onClick={() => runTemplate(t.id)}>Run</button>
                    </div>
                  ))}
                </div>
              </div>

              {/* ── Presets + harness ── */}
              <div className="card">
                <h2>Presets</h2>
                {presets.map((p) => (
                  <div key={p.id} className="sec-item">
                    <div>
                      <strong>{p.name}</strong>
                      <div className="empty">{(p.template_ids || []).join(', ')}</div>
                    </div>
                    <button className="ghost" disabled={!selected || !!busy} onClick={() => run('preset', async () => {
                      await post('/api/security/preset', { artifact_id: selected, preset_id: p.id })
                      setTab('findings')
                    })}>Run</button>
                  </div>
                ))}
                <h2 style={{ marginTop: '1rem' }}>Test harness</h2>
                <pre className="mini">{JSON.stringify(harness, null, 2)}</pre>
                <div className="row">
                  <button className="ghost" disabled={!!busy} onClick={() => run('harness-seed', async () => {
                    setHarness(await post('/api/security/harness', { action: 'seed' }))
                  })}>Seed</button>
                  <button className="ghost" disabled={!!busy} onClick={() => run('harness-build', async () => {
                    const r = await post('/api/security/harness', { action: 'build' })
                    setHarness(r.status || r)
                  })}>Build</button>
                </div>
                {lastSecRun && (
                  <>
                    <h2 style={{ marginTop: '1rem' }}>Last run timeline</h2>
                    <Timeline events={lastSecRun.timeline || []} />
                  </>
                )}
              </div>

              {/* ── IOC Scanner ── */}
              <div className="card" style={{ gridColumn: '1 / -1' }}>
                <h2>Static IOC Scanner</h2>
                <p className="empty">
                  Grep decompiled sources for hardcoded secrets, public IPs, URLs, base64 blobs, DexClassLoader, SSL bypass patterns, C2 keywords, telephony leaks.
                  All findings are observations — review before acting.
                </p>
                <div className="row" style={{ alignItems: 'flex-end', gap: '0.75rem', flexWrap: 'wrap' }}>
                  <ArtifactSelect artifacts={artifacts} value={selected} onChange={setSelected} />
                  <button className="primary" disabled={!selected || !!busy} onClick={() => run('ioc-scan', async () => {
                    const r = await post('/api/scan/ioc', { artifact_id: selected })
                    setIocResult(r)
                  })}>Scan</button>
                </div>
                {iocResult && (
                  <div style={{ marginTop: '1rem' }}>
                    <div className="row" style={{ gap: '1rem', flexWrap: 'wrap', marginBottom: '0.5rem' }}>
                      <span className="empty">Files scanned: <strong>{iocResult.files_scanned}</strong></span>
                      <span className="empty">Findings: <strong>{(iocResult.findings || []).length}</strong></span>
                      {Object.entries(iocResult.summary || {}).map(([cat, n]) => (
                        <span key={cat} className="sec-chip" style={{
                          background: 'var(--bg-secondary)', border: '1px solid var(--border)',
                          borderRadius: '4px', padding: '2px 8px', fontSize: 'var(--text-xs)'
                        }}>{cat}: {n}</span>
                      ))}
                    </div>
                    {iocResult.error && <p className="err-msg">{iocResult.error}</p>}
                    <div className="sec-list" style={{ maxHeight: '360px', overflowY: 'auto' }}>
                      {(iocResult.findings || []).map((f) => (
                        <div key={f.id} className="sec-item" style={{ flexDirection: 'column', alignItems: 'flex-start', gap: '0.25rem' }}>
                          <div className="row" style={{ gap: '0.5rem', width: '100%' }}>
                            <span style={{
                              fontSize: 'var(--text-xs)', padding: '1px 6px', borderRadius: '3px',
                              background: f.severity === 'needs_review' ? 'rgba(239,68,68,0.15)' :
                                          f.severity === 'potential'    ? 'rgba(251,191,36,0.15)' : 'rgba(148,163,184,0.15)',
                              color: f.severity === 'needs_review' ? '#f87171' :
                                     f.severity === 'potential'    ? '#fbbf24' : 'var(--text-muted)',
                            }}>{f.severity}</span>
                            <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>{f.category}</span>
                            <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginLeft: 'auto' }}>{f.file}:{f.line}</span>
                          </div>
                          <code style={{ fontSize: 'var(--text-xs)', color: 'var(--accent)', wordBreak: 'break-all' }}>{f.match}</code>
                          <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>{f.context}</span>
                        </div>
                      ))}
                      {!(iocResult.findings || []).length && !iocResult.error && (
                        <p className="empty">No IOC matches found.</p>
                      )}
                    </div>
                  </div>
                )}
              </div>

              {/* ── Frida ── */}
              <div className="card" style={{ gridColumn: '1 / -1' }}>
                <h2>Frida — Dynamic Instrumentation</h2>
                <p className="empty">
                  SSL pinning bypass · method tracing · DEX loader detection · network interception.{' '}
                  <strong>Authorized testing only.</strong>
                </p>

                {/* Setup checklist */}
                <details style={{ marginBottom: '1rem' }}>
                  <summary style={{ cursor: 'pointer', fontSize: 'var(--text-sm)', color: 'var(--text-muted)', userSelect: 'none' }}>
                    ▶ First-time setup (expand)
                  </summary>
                  <ol style={{ margin: '0.5rem 0 0 1.25rem', fontSize: 'var(--text-sm)', lineHeight: 1.7, color: 'var(--text-secondary)' }}>
                    <li>Install Frida CLI on the <strong>host</strong>: <code>pip install frida-tools</code></li>
                    <li>
                      Enter the device serial below and click <strong>Check status</strong> →
                      note the <code>device_arch</code> (e.g. <code>arm64-v8a</code>).
                      {fridaStatus?.device_arch && (
                        <span style={{ color: 'var(--accent)', marginLeft: '0.4rem' }}>
                          Detected: <strong>{fridaStatus.device_arch}</strong>
                        </span>
                      )}
                    </li>
                    <li>
                      Download the matching <code>frida-server</code> binary.
                      {fridaStatus?.frida_version && fridaStatus?.device_arch ? (
                        <span style={{ marginLeft: '0.4rem' }}>
                          <a
                            href={fridaDownloadUrl(fridaStatus.frida_version, fridaStatus.device_arch)}
                            target="_blank" rel="noopener noreferrer"
                            style={{ color: 'var(--accent)' }}
                          >
                            Download frida-server-{fridaStatus.frida_version}-android-{archSlug(fridaStatus.device_arch)}.xz ↗
                          </a>
                          {' '}then: <code>xz -d frida-server-*.xz</code>
                        </span>
                      ) : (
                        <span style={{ color: 'var(--text-muted)', marginLeft: '0.4rem' }}>
                          Check status first to get the download link.
                        </span>
                      )}
                    </li>
                    <li>
                      Push the extracted binary to the device:{' '}
                      <div style={{ display: 'inline-flex', gap: '0.4rem', alignItems: 'center', marginTop: '0.25rem', flexWrap: 'wrap' }}>
                        <input className="input" style={{ width: '280px' }} placeholder="/tmp/frida-server (local path)"
                          value={fridaHostPath} onChange={(e) => setFridaHostPath(e.target.value)} />
                        <button className="ghost" style={{ fontSize: 'var(--text-xs)' }} disabled={!fridaHostPath || !!busy}
                          onClick={() => run('frida-push', async () => {
                            await post('/api/frida/push', { serial: fridaSerial, host_path: fridaHostPath })
                            const r = await api(`/api/frida/status${fridaSerial ? '?serial=' + encodeURIComponent(fridaSerial) : ''}`)
                            setFridaStatus(r)
                          })}>Push server</button>
                      </div>
                    </li>
                    <li>
                      Start <code>frida-server</code> on the device (requires root or debuggable APK):
                      <code style={{ marginLeft: '0.4rem' }}>adb shell su -c /data/local/tmp/frida-server &amp;</code>
                    </li>
                    <li>Fill Package below and run a hook.</li>
                  </ol>
                </details>

                {/* Inputs + status row */}
                <div className="row" style={{ gap: '0.5rem', flexWrap: 'wrap', alignItems: 'flex-end' }}>
                  <label style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem', fontSize: 'var(--text-sm)' }}>
                    Serial
                    <input className="input" style={{ width: '160px' }} placeholder="e.g. emulator-5554"
                      value={fridaSerial} onChange={(e) => setFridaSerial(e.target.value)} />
                  </label>
                  <label style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem', fontSize: 'var(--text-sm)' }}>
                    Package
                    <input className="input" style={{ width: '240px' }} placeholder="com.example.app"
                      value={fridaPkg} onChange={(e) => setFridaPkg(e.target.value)} />
                  </label>
                  <label style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem', fontSize: 'var(--text-sm)' }}>
                    Method pattern <span style={{ color: 'var(--text-muted)' }}>(trace)</span>
                    <input className="input" style={{ width: '180px' }} placeholder="login, verify, …"
                      value={fridaPattern} onChange={(e) => setFridaPattern(e.target.value)} />
                  </label>
                  <button className="ghost" disabled={!!busy} onClick={() => run('frida-status', async () => {
                    const r = await api(`/api/frida/status${fridaSerial ? '?serial=' + encodeURIComponent(fridaSerial) : ''}`)
                    setFridaStatus(r)
                  })}>Check status</button>
                </div>

                {/* Status card */}
                {fridaStatus && (
                  <div style={{
                    marginTop: '0.5rem', padding: '0.5rem 0.75rem',
                    background: 'var(--bg-secondary)', borderRadius: '6px',
                    border: '1px solid var(--border)', fontSize: 'var(--text-sm)',
                  }}>
                    <div className="row" style={{ gap: '1rem', flexWrap: 'wrap' }}>
                      <span style={{ color: fridaStatus.frida_cli ? 'var(--accent)' : 'var(--status-fail)' }}>
                        {fridaStatus.frida_cli ? '✓' : '✗'} frida CLI{fridaStatus.frida_version ? ' v' + fridaStatus.frida_version : ''}
                      </span>
                      {fridaStatus.device_arch && (
                        <span style={{ color: 'var(--text-muted)' }}>arch: {fridaStatus.device_arch}</span>
                      )}
                      <span style={{ color: fridaStatus.server_on_device ? 'var(--accent)' : 'var(--text-muted)' }}>
                        {fridaStatus.server_on_device ? '✓' : '○'} server on device
                      </span>
                      <span style={{ color: fridaStatus.server_running ? 'var(--accent)' : 'var(--text-muted)' }}>
                        {fridaStatus.server_running ? '✓' : '○'} server running
                      </span>
                    </div>
                    {fridaStatus.error && (
                      <div style={{ marginTop: '0.25rem', color: 'var(--status-fail)', fontSize: 'var(--text-xs)' }}>
                        {fridaStatus.error}
                      </div>
                    )}
                  </div>
                )}

                {/* Server management */}
                <div className="row" style={{ gap: '0.5rem', marginTop: '0.75rem', flexWrap: 'wrap' }}>
                  <button className="ghost" disabled={!!busy} onClick={() => run('frida-start-srv', async () => {
                    await post('/api/frida/start-server', { serial: fridaSerial })
                    const r = await api(`/api/frida/status${fridaSerial ? '?serial=' + encodeURIComponent(fridaSerial) : ''}`)
                    setFridaStatus(r)
                  })}>Start server</button>
                  <button className="ghost" disabled={!!busy} onClick={() => run('frida-stop-srv', async () => {
                    await post('/api/frida/stop-server', { serial: fridaSerial })
                    const r = await api(`/api/frida/status${fridaSerial ? '?serial=' + encodeURIComponent(fridaSerial) : ''}`)
                    setFridaStatus(r)
                  })}>Stop server</button>
                </div>

                {/* Hook buttons */}
                <div style={{
                  marginTop: '0.75rem', paddingTop: '0.75rem',
                  borderTop: '1px solid var(--border)',
                  display: 'flex', gap: '0.5rem', flexWrap: 'wrap', alignItems: 'center',
                }}>
                  <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginRight: '0.25rem' }}>Hooks:</span>
                  <button className="primary" disabled={!fridaPkg || !!busy} title="Bypass TrustManager, OkHttp3, Conscrypt, HostnameVerifier — combine with Proxy→Start to capture traffic"
                    onClick={() => run('frida-ssl', async () => {
                      const r = await post('/api/frida/ssl-unpin', { serial: fridaSerial, package: fridaPkg, timeout_sec: 30 })
                      setFridaEvents(r.events || [])
                    })}>SSL Unpin</button>
                  <button className="ghost" disabled={!fridaPkg || !!busy} title="Hook all methods matching the pattern and log args + return values"
                    onClick={() => run('frida-trace', async () => {
                      const r = await post('/api/frida/method-trace', { serial: fridaSerial, package: fridaPkg, method_pattern: fridaPattern || undefined, timeout_sec: 30 })
                      setFridaEvents(r.events || [])
                    })}>Method Trace</button>
                  <button className="ghost" disabled={!fridaPkg || !!busy} title="Detect DexClassLoader / InMemoryDexClassLoader / PathClassLoader (packing / obfuscation signal)"
                    onClick={() => run('frida-dex', async () => {
                      const r = await post('/api/frida/dex-loader', { serial: fridaSerial, package: fridaPkg, timeout_sec: 30 })
                      setFridaEvents(r.events || [])
                    })}>DEX Loader</button>
                  <button className="ghost" disabled={!fridaPkg || !!busy} title="Intercept Socket, URL.openConnection, OkHttp3 — surfaces undocumented endpoints"
                    onClick={() => run('frida-net', async () => {
                      const r = await post('/api/frida/network-trace', { serial: fridaSerial, package: fridaPkg, timeout_sec: 30 })
                      setFridaEvents(r.events || [])
                    })}>Network Trace</button>
                  {fridaEvents.length > 0 && (
                    <button className="ghost" style={{ marginLeft: 'auto' }}
                      onClick={() => setFridaEvents([])}>Clear events</button>
                  )}
                </div>

                {/* Events */}
                {fridaEvents.length > 0 && (
                  <div style={{ marginTop: '0.75rem' }}>
                    <div className="empty" style={{ marginBottom: '0.25rem' }}>{fridaEvents.length} event(s)</div>
                    <div className="sec-list" style={{ maxHeight: '280px', overflowY: 'auto' }}>
                      {fridaEvents.map((ev, i) => (
                        <div key={i} className="sec-item" style={{ flexDirection: 'column', alignItems: 'flex-start', gap: '0.25rem' }}>
                          <span style={{ fontSize: 'var(--text-xs)', color: 'var(--accent)', fontWeight: 600 }}>{ev.type}</span>
                          {ev.payload && (
                            <pre style={{ margin: 0, fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
                              {JSON.stringify(ev.payload, null, 2)}
                            </pre>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* ── PROXY ── */}
          {tab === 'proxy' && (
            <div className="card">
              <h2>mitmproxy</h2>
              <pre className="mini">{JSON.stringify(proxy, null, 2)}</pre>
              <div className="row">
                <button className="primary" disabled={!!busy} onClick={() => run('proxy-start', async () => {
                  setProxy(await post('/api/proxy/start', {}))
                })}>Start</button>
                <button className="ghost" disabled={!!busy} onClick={() => run('proxy-stop', async () => {
                  await post('/api/proxy/stop', {})
                  setProxy(await api('/api/proxy/status'))
                })}>Stop</button>
              </div>
            </div>
          )}

          {/* ── CERTIFICATES ── */}
          {tab === 'certs' && (
            <div className="card">
              <h2>Certificates</h2>
              <pre className="mini">{JSON.stringify(certs, null, 2)}</pre>
              <p className="empty">Private keys never sent to UI.</p>
            </div>
          )}

          {/* ── MANIFEST ── */}
          {tab === 'manifest' && (
            <div className="card">
              <h2>Manifest security panel</h2>
              <ArtifactSelect artifacts={artifacts} value={selected} onChange={setSelected} />
              <button className="primary" disabled={!selected || !!busy} onClick={() => run('manifest', async () => {
                const r = await api(`/api/security/manifest?artifact_id=${encodeURIComponent(selected)}`)
                throwIfErr(r)
                setManifest(r)
              })}>Analyze</button>
              {manifest && (
                <>
                  <div className="stages" style={{ marginTop: '1rem' }}>
                    {(manifest.review_notes || []).map((n, i) => (
                      <span key={i} className="stage bad">{n}</span>
                    ))}
                  </div>
                  <pre className="mini">{JSON.stringify(manifest, null, 2)}</pre>
                </>
              )}
            </div>
          )}

          {/* ── FINDINGS ── */}
          {tab === 'findings' && (
            <div className="card">
              <h2>Observations</h2>
              <p className="empty">Severity = informational / potential / needs_review. Tester decides disclosure.</p>
              {(observations || []).slice().reverse().map((o) => (
                <div key={o.id} className="finding">
                  <div className="finding-head">
                    <strong>{o.title}</strong>
                    <span className={`sev ${o.severity}`}>{o.severity}</span>
                  </div>
                  <div className="empty">{o.summary}</div>
                  <div className="row">
                    <button className="ghost" onClick={() => run('export-md', async () => {
                      const r = await post('/api/security/export', { observation_id: o.id, format: 'markdown' })
                      throwIfErr(r)
                      alert('Exported: ' + r.path)
                    })}>Export MD</button>
                    <button className="ghost" onClick={() => run('export-zip', async () => {
                      const r = await post('/api/security/export', { observation_id: o.id, format: 'zip' })
                      throwIfErr(r)
                      alert('Exported: ' + r.path)
                    })}>Export ZIP</button>
                  </div>
                </div>
              ))}
              {!observations.length && <p className="empty">No observations yet — run a security template.</p>}
            </div>
          )}

          {/* ── LIVE LOG ── */}
          {tab === 'live-log' && (
            <LiveLog
              mode="full"
              events={events}
              busy={busy}
              selected={selected}
              streamOk={streamOk}
              onClear={() => setEvents([])}
            />
          )}
        </section>
      </div>

      {/* ── Footer live log + device ── */}
      {tab !== 'live-log' && (
        <footer className={`bottom live-footer${logTall ? ' tall' : ''}`}>
          <LiveLog
            mode="compact"
            events={events}
            busy={busy}
            selected={selected}
            streamOk={streamOk}
            expandedCompact={logTall}
            onToggleExpand={() => setLogTall((v) => !v)}
            onClear={() => setEvents([])}
          />
          <div className="live-footer-side">
            <LiveDevice compact serial={liveSerial} title="Android" />
            <h3>Session</h3>
            <div className="empty">Selected: {selected || 'none'}{busy ? ` · busy: ${busy}` : ''}</div>
            {lastLabRun && (
              <button className="ghost" onClick={() => { setTab('history'); setHistoryTab('runs'); setHistoryRunId(lastLabRun) }}>
                Open run · {lastLabRun}
              </button>
            )}
            <button className="ghost" onClick={() => setTab('devices')}>Full live screen</button>
            <button className="ghost" onClick={() => setLogTall((v) => !v)}>{logTall ? 'Collapse log' : 'Taller log'}</button>
            <button className="ghost" onClick={() => setTab('live-log')}>Full live log</button>
            <div className="empty tiny">DEX/Smali = truth · Observations ≠ vulns</div>
          </div>
        </footer>
      )}

      <AuthGate
        onError={(m) => setErr(m)}
        onFilled={() => {
          setEvents((prev) => mergeEvents(prev, [uiEvent('AUTH_FILLED', 'Login field submitted from UI', 'info')]))
        }}
      />
    </div>
  )
}

// ─── Sub-components ──────────────────────────────────────────────────────────

function WizardProgress({ step }) {
  const labels = ['APK', 'Setup', 'Scenario', 'Run']
  return (
    <div className="wizard-progress">
      {labels.map((label, i) => (
        <React.Fragment key={label}>
          <div className={`wiz-step${i === step ? ' current' : i < step ? ' done' : ''}`}>
            <span className="wiz-dot">{i < step ? '✓' : i + 1}</span>
            <span className="wiz-label">{label}</span>
          </div>
          {i < labels.length - 1 && <div className={`wiz-line${i < step ? ' done' : ''}`} />}
        </React.Fragment>
      ))}
    </div>
  )
}

function ArtifactSelect({ artifacts, value, onChange }) {
  return (
    <div className="row">
      <select value={value} onChange={(e) => onChange(e.target.value)}>
        <option value="">select artifact…</option>
        {artifacts.map((a) => <option key={a.id} value={a.id}>{a.id} · {a.kind} · {a.label || a.package}</option>)}
      </select>
    </div>
  )
}

function Stages({ result }) {
  return (
    <div className="stages">
      {(result.stages || []).map((s) => (
        <span key={s.name} className={`stage ${s.ok ? 'ok' : 'bad'}`}>{s.ok ? '✓' : '✗'} {s.name}</span>
      ))}
    </div>
  )
}

function Timeline({ events }) {
  return (
    <div className="timeline">
      {events.map((e, i) => (
        <div key={i} className="tl-row">
          <span className="t">{((e.offset_ms || 0) / 1000).toFixed(1)}s</span>
          <span className="kind">{e.type}</span>
          <span>{e.message}</span>
        </div>
      ))}
    </div>
  )
}
