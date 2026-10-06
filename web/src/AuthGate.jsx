import React, { useCallback, useEffect, useState } from 'react'
import { api, post, throwIfErr } from './api'

/**
 * Modal for interactive scenario prompts: phone, SMS OTP, PIN, text, and
 * Allow / Don't allow choices (notifications & system dialogs).
 */
export default function AuthGate({ onError, onFilled }) {
  const [pending, setPending] = useState([])
  const [values, setValues] = useState({})
  const [busy, setBusy] = useState('')

  const refresh = useCallback(async () => {
    try {
      const r = await api('/api/auth/pending')
      setPending(Array.isArray(r?.pending) ? r.pending : [])
    } catch {
      /* lab may be restarting */
    }
  }, [])

  useEffect(() => {
    refresh()
    const t = setInterval(refresh, 800)
    return () => clearInterval(t)
  }, [refresh])

  if (!pending.length) return null

  const submit = async (p, forcedValue) => {
    const value = String(forcedValue ?? values[p.id] ?? '').trim()
    if (!value) {
      onError?.('Enter a value before submit')
      return
    }
    setBusy(p.id)
    try {
      await post('/api/auth/submit', { run_id: p.run_id, kind: p.kind, value }).then(throwIfErr)
      setValues((v) => ({ ...v, [p.id]: '' }))
      onFilled?.(p)
      await refresh()
    } catch (e) {
      onError?.(e.message || String(e))
    } finally {
      setBusy('')
    }
  }

  const isChoice = (p) => p.kind === 'choice' || (Array.isArray(p.choices) && p.choices.length > 0)
  const title = pending.some(isChoice) && pending.some((p) => p.kind === 'phone' || p.kind === 'otp')
    ? 'Action required'
    : pending.every(isChoice)
      ? 'Choose next step'
      : 'Login required'

  return (
    <div className="auth-backdrop" role="presentation">
      <div className="auth-gate" role="dialog" aria-modal="true" aria-label={title}>
        <header>
          <div className="auth-head-copy">
            <span className="auth-kicker">Interactive auth</span>
            <strong>{title}</strong>
            <span className="empty">
              Lab waits for the real login field after clearing notification prompts. Submit here, or type the OTP on the device.
            </span>
          </div>
          <span className="auth-count" title="Pending prompts">{pending.length}</span>
        </header>
        {pending.map((p) => (
          <div key={p.id} className={`auth-prompt kind-${p.kind}`}>
            <div className="auth-meta">
              <span className={`kind ${p.kind}`}>{p.kind}</span>
              <span className="msg">{p.label || p.kind}</span>
              {p.package ? <span className="empty pkg">{p.package}</span> : null}
            </div>

            {isChoice(p) ? (
              <div className="auth-choices">
                {(p.choices || ['Allow', "Don't allow", 'Skip']).map((c) => (
                  <button
                    key={c}
                    type="button"
                    className={`choice-btn ${/allow|accept|اجازه/i.test(c) ? 'yes' : /don.?t|deny|رد|skip|not now/i.test(c) ? 'no' : ''}`}
                    disabled={busy === p.id}
                    onClick={() => submit(p, c)}
                  >
                    {busy === p.id ? '…' : c}
                  </button>
                ))}
              </div>
            ) : (
              <div className="row auth-input-row">
                <input
                  autoFocus
                  inputMode={p.kind === 'phone' || p.kind === 'otp' || p.kind === 'pin' ? 'numeric' : 'text'}
                  autoComplete={p.kind === 'otp' || p.kind === 'pin' ? 'one-time-code' : p.kind === 'phone' ? 'tel' : 'off'}
                  placeholder={
                    p.kind === 'otp'
                      ? 'SMS code — or type on device'
                      : p.kind === 'phone' ? 'Phone number' : p.kind === 'pin' ? 'PIN' : 'Value'
                  }
                  value={values[p.id] || ''}
                  onChange={(e) => setValues((v) => ({ ...v, [p.id]: e.target.value }))}
                  onKeyDown={(e) => { if (e.key === 'Enter') submit(p) }}
                />
                <button className="primary" disabled={busy === p.id} onClick={() => submit(p)}>
                  {busy === p.id ? '…' : 'Submit'}
                </button>
              </div>
            )}
            <div className="empty tiny mono">{p.run_id}</div>
          </div>
        ))}
      </div>
    </div>
  )
}
