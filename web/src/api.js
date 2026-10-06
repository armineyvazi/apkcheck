/** Robust Lab API client — never throws cryptic JSON SyntaxErrors. */

export class ApiError extends Error {
  constructor(message, { status = 0, path = '', body = null } = {}) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.path = path
    this.body = body
  }
}

function preview(text, n = 160) {
  const t = String(text || '').replace(/\s+/g, ' ').trim()
  return t.length > n ? `${t.slice(0, n)}…` : t
}

async function parseBody(res) {
  const text = await res.text()
  const trimmed = text.trim()
  if (!trimmed) {
    return { data: null, raw: text }
  }
  const ct = (res.headers.get('content-type') || '').toLowerCase()
  if (ct.includes('application/json') || trimmed.startsWith('{') || trimmed.startsWith('[')) {
    try {
      return { data: JSON.parse(trimmed), raw: text }
    } catch (e) {
      throw new ApiError(
        `Invalid JSON from ${res.url}: ${e.message}. Body: ${preview(trimmed)}`,
        { status: res.status, path: res.url, body: trimmed },
      )
    }
  }
  // Plain-text errors like Go's default "404 page not found"
  throw new ApiError(
    `Non-JSON response (${res.status}) from ${res.url}: ${preview(trimmed)}`,
    { status: res.status, path: res.url, body: trimmed },
  )
}

/**
 * @param {string} path
 * @param {{ method?: string, body?: any, timeoutMs?: number }} [opts]
 */
export async function request(path, opts = {}) {
  const method = opts.method || 'GET'
  const timeoutMs = opts.timeoutMs ?? 120_000
  const ctrl = new AbortController()
  const timer = setTimeout(() => ctrl.abort(), timeoutMs)
  try {
    const init = {
      method,
      signal: ctrl.signal,
      headers: {},
    }
    if (opts.body !== undefined) {
      init.headers['Content-Type'] = 'application/json'
      init.body = JSON.stringify(opts.body)
    }
    const res = await fetch(path, init)
    const { data } = await parseBody(res)
    if (!res.ok) {
      const msg = (data && (data.error || data.message)) || `HTTP ${res.status}`
      throw new ApiError(String(msg), { status: res.status, path, body: data })
    }
    if (data && typeof data === 'object' && data.error && !data.ok && !data.id && !data.result && !data.report) {
      // Soft API errors embedded in 200 responses
      throw new ApiError(String(data.error), { status: res.status, path, body: data })
    }
    return data
  } catch (e) {
    if (e instanceof ApiError) throw e
    if (e && e.name === 'AbortError') {
      throw new ApiError(`Request timed out after ${timeoutMs / 1000}s: ${path}`, { path })
    }
    throw new ApiError(e?.message || String(e), { path })
  } finally {
    clearTimeout(timer)
  }
}

export const api = (path, opts) => request(path, { ...opts, method: 'GET' })
export const post = (path, body, opts) => request(path, { ...opts, method: 'POST', body: body || {}, timeoutMs: opts?.timeoutMs ?? 600_000 })

/** Parallel fetch; failures become { error } instead of rejecting the whole refresh. */
export async function settle(entries) {
  const keys = Object.keys(entries)
  const results = await Promise.all(
    keys.map(async (k) => {
      try {
        const data = await entries[k]()
        return [k, { ok: true, data }]
      } catch (e) {
        return [k, { ok: false, error: e?.message || String(e), status: e?.status }]
      }
    }),
  )
  return Object.fromEntries(results)
}

export function asArray(v) {
  return Array.isArray(v) ? v : []
}

export function throwIfErr(r) {
  if (r && r.error) throw new ApiError(String(r.error), { body: r })
  return r
}
