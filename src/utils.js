import { createHmac } from 'node:crypto'

// Limiteur de tentatives en mémoire (par processus). Borné pour ne pas pouvoir être saturé par des clés aléatoires.
const attempts = new Map()
const MAX_TRACKED_KEYS = 10000
const SWEEP_INTERVAL_MS = 60 * 1000
let lastSweep = 0

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

export const parseDuration = (value, fallbackMs) => {
  if (typeof value === 'number') return value
  const match = /^(\d+)\s*(ms|s|m|h|d|w)?$/.exec(String(value || '').trim())
  if (!match) return fallbackMs
  const unit = { ms: 1, s: 1000, m: 60000, h: 3600000, d: 86400000, w: 604800000 }[match[2] || 'ms']
  return Number(match[1]) * unit
}

export const clamp = (value, min, max) => Math.min(Math.max(value, min), max)

export const isUuid = value => UUID_RE.test(String(value))

export const hit = (key, max, windowMs) => {
  const now = Date.now()
  if (now - lastSweep > SWEEP_INTERVAL_MS || attempts.size >= MAX_TRACKED_KEYS) {
    lastSweep = now
    for (const [k, v] of attempts) if (v.expiresAt <= now) attempts.delete(k)
    // Toujours saturé : les entrées les plus anciennes sont abandonnées
    for (const k of attempts.keys()) {
      if (attempts.size < MAX_TRACKED_KEYS) break
      attempts.delete(k)
    }
  }
  const current = attempts.get(key)
  if (!current || current.expiresAt <= now) {
    attempts.set(key, { count: 1, expiresAt: now + windowMs })
    return true
  }
  if (current.count >= max) return false
  current.count += 1
  return true
}

// Limite atteinte, sans compter de tentative (pour ne pénaliser que les échecs avec hit)
export const blocked = (key, max) => {
  const current = attempts.get(key)
  return Boolean(current) && current.expiresAt > Date.now() && current.count >= max
}

export const fail = (res, status, code, message, extensions = {}) =>
  res.status(status).json({ errors: [{ message, extensions: { code, ...extensions } }] })

const encode = value => Buffer.from(JSON.stringify(value)).toString('base64url')

// JWT HS256 signé avec le SECRET de Directus (même format que les jetons d'accès natifs)
export const signJwt = (payload, secret) => {
  const unsigned = `${encode({ alg: 'HS256', typ: 'JWT' })}.${encode(payload)}`
  const signature = createHmac('sha256', String(secret)).update(unsigned).digest('base64url')
  return `${unsigned}.${signature}`
}

// Payload d'un JWT déjà authentifié par Directus : la signature n'est pas revérifiée ici
export const decodeJwtPayload = (token) => {
  try {
    const payload = JSON.parse(Buffer.from(String(token).split('.')[1] || '', 'base64url').toString('utf8'))
    return payload && typeof payload === 'object' ? payload : null
  }
  catch {
    return null
  }
}
