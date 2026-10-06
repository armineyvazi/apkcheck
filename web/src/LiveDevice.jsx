import React, { useEffect, useMemo, useRef, useState } from 'react'

/**
 * Live Android screen from Lab host emulator (adb screencap → Lab UI).
 * Prefer MJPEG stream; fall back to polled PNG if stream fails.
 * Stream watchdog: if no frame arrives in 4s, force-reconnects the stream.
 */
export default function LiveDevice({ serial, compact = false, title = 'Live device' }) {
  const [mode, setMode] = useState('stream') // stream | poll | off
  const [tick, setTick] = useState(0)
  const [reconnect, setReconnect] = useState(0)
  const [err, setErr] = useState('')
  const [paused, setPaused] = useState(false)
  const lastFrameRef = useRef(Date.now())

  // Watchdog: if stream stalls (no onLoad in 4s), force-remount the <img>.
  useEffect(() => {
    if (mode !== 'stream' || paused || !serial) return undefined
    lastFrameRef.current = Date.now()
    const id = setInterval(() => {
      if (Date.now() - lastFrameRef.current > 4000) {
        lastFrameRef.current = Date.now()
        setReconnect((n) => n + 1)
      }
    }, 2000)
    return () => clearInterval(id)
  }, [mode, paused, serial])

  const streamSrc = useMemo(() => {
    if (!serial || paused || mode !== 'stream') return ''
    const q = new URLSearchParams({ serial })
    return `/api/runtimes/screen/stream?${q}`
  }, [serial, paused, mode])

  const pollSrc = useMemo(() => {
    if (!serial || paused || mode !== 'poll') return ''
    const q = new URLSearchParams({ serial, t: String(tick) })
    return `/api/runtimes/screen?${q}`
  }, [serial, paused, mode, tick])

  useEffect(() => {
    if (mode !== 'poll' || paused || !serial) return undefined
    const id = setInterval(() => setTick((n) => n + 1), 700)
    return () => clearInterval(id)
  }, [mode, paused, serial])

  if (!serial) {
    return (
      <div className={`live-device${compact ? ' compact' : ''}`}>
        <header className="live-device-bar">
          <strong>{title}</strong>
          <span className="empty">waiting for device</span>
        </header>
        <div className="live-device-empty">
          {compact ? 'No device' : 'Start the emulator on the Lab host — screen will appear here automatically.'}
        </div>
      </div>
    )
  }

  const src = mode === 'stream' ? streamSrc : pollSrc
  // Stream key includes reconnect counter so the watchdog can force-remount.
  const imgKey = mode === 'stream' ? `stream-${reconnect}` : src

  return (
    <div className={`live-device${compact ? ' compact' : ''}`}>
      <header className="live-device-bar">
        <div className="live-device-title">
          <span className={`stream-dot ${paused ? 'off' : 'on'}`} />
          <strong>{title}</strong>
          <span className="empty" style={{ fontFamily: 'var(--mono)', fontSize: '.7rem' }}>{serial}</span>
        </div>
        <div className="live-device-controls">
          <button className={`ghost icon-btn ${mode === 'stream' ? 'on' : ''}`} onClick={() => { setMode('stream'); setReconnect((n) => n + 1) }} title="MJPEG stream">Stream</button>
          <button className={`ghost icon-btn ${mode === 'poll' ? 'on' : ''}`} onClick={() => { setMode('poll'); setTick((n) => n + 1) }} title="Poll PNG">Poll</button>
          <button className={`ghost icon-btn ${paused ? 'on' : ''}`} onClick={() => setPaused((p) => !p)}>{paused ? 'Resume' : 'Pause'}</button>
        </div>
      </header>
      <div className="live-device-frame">
        {paused ? (
          <div className="live-device-empty">Paused</div>
        ) : (
          <img
            key={imgKey}
            src={src}
            alt="Android emulator"
            className="live-device-img"
            onError={() => {
              if (mode === 'stream') {
                setMode('poll')
                setErr('Stream unavailable — using poll')
              } else {
                setErr('Screen capture failed')
              }
            }}
            onLoad={() => {
              setErr('')
              lastFrameRef.current = Date.now()
            }}
          />
        )}
      </div>
      {err && <div className="empty tiny live-device-err">{err}</div>}
    </div>
  )
}
