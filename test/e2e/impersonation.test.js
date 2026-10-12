// Tests de bout en bout contre une instance Directus démarrée avec l'extension.
// Variables : DIRECTUS_URL, ADMIN_EMAIL, ADMIN_PASSWORD, IMPERSONATION_TTL (même valeur que le serveur, ex. 10m).
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { before, describe, it } from 'node:test'
import { createGuardrails, generateSync } from 'otplib'

const URL = (process.env.DIRECTUS_URL || 'http://localhost:8055').replace(/\/$/, '')
const EMAIL = process.env.ADMIN_EMAIL
const PASSWORD = process.env.ADMIN_PASSWORD
const TTL_SECONDS = { '10m': 600, '15m': 900 }[process.env.IMPERSONATION_TTL || '15m']
const MEMBER_PASSWORD = 'e2e-member-password-123'
const guardrails = createGuardrails({ MIN_SECRET_BYTES: 10 })

const api = async (method, path, { body, token, headers = {} } = {}) => {
  const res = await fetch(URL + path, {
    method,
    headers: {
      'content-type': 'application/json',
      ...(token && { authorization: `Bearer ${token}` }),
      ...headers,
    },
    body: body && JSON.stringify(body),
  })
  const text = await res.text()
  let json
  try { json = JSON.parse(text) }
  catch { json = text }
  return { status: res.status, json }
}

const login = async (email, password) => {
  const res = await api('POST', '/auth/login', { body: { email, password } })
  assert.equal(res.status, 200, JSON.stringify(res.json))
  return res.json.data
}

const reason = res => res.json?.errors?.[0]?.extensions?.reason
const errorCode = res => res.json?.errors?.[0]?.extensions?.code
const decode = token => JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf8'))

const until = async (check, timeoutMs = 45000) => {
  const end = Date.now() + timeoutMs
  for (;;) {
    const result = await check()
    if (result || Date.now() > end) return result
    await new Promise(resolve => setTimeout(resolve, 2000))
  }
}

let admin
let adminId
let adminRoleId
let otherAdmin
let tfaSecret
let hasPolicies
let member
const otp = () => generateSync({ secret: tfaSecret, guardrails })

// Utilisateur sans droit d'administration (Directus ≥ 11 : policy + rôle ; Directus 10 : drapeaux du rôle)
const createUser = async ({ role }) => {
  const label = randomUUID().slice(0, 8)
  const created = await api('POST', '/users', {
    token: admin.access_token,
    body: { email: `e2e-${label}@example.com`, password: MEMBER_PASSWORD, role, status: 'active', first_name: 'E2E', last_name: label },
  })
  assert.equal(created.status, 200, JSON.stringify(created.json))
  return { id: created.json.data.id, email: `e2e-${label}@example.com` }
}

const createMemberRole = async () => {
  const label = randomUUID().slice(0, 8)
  if (!hasPolicies) {
    const role = await api('POST', '/roles', { token: admin.access_token, body: { name: `e2e ${label}`, app_access: true, admin_access: false } })
    assert.equal(role.status, 200, JSON.stringify(role.json))
    return role.json.data.id
  }

  const policy = await api('POST', '/policies', { token: admin.access_token, body: { name: `e2e ${label}`, app_access: true, admin_access: false } })
  assert.equal(policy.status, 200, JSON.stringify(policy.json))
  const role = await api('POST', '/roles', { token: admin.access_token, body: { name: `e2e ${label}` } })
  assert.equal(role.status, 200, JSON.stringify(role.json))
  const access = await api('POST', '/access', { token: admin.access_token, body: { role: role.json.data.id, policy: policy.json.data.id } })
  assert.equal(access.status, 200, JSON.stringify(access.json))
  return role.json.data.id
}

const start = (body, token = admin.access_token, headers = {}) =>
  api('POST', '/impersonation/start', { token, body, headers })

before(async () => {
  assert.ok(EMAIL && PASSWORD, 'ADMIN_EMAIL and ADMIN_PASSWORD are required')
  admin = await login(EMAIL, PASSWORD)

  const me = await api('GET', '/users/me?fields=id,role', { token: admin.access_token })
  adminId = me.json.data.id
  adminRoleId = typeof me.json.data.role === 'object' ? me.json.data.role.id : me.json.data.role

  hasPolicies = (await api('GET', '/policies?limit=1', { token: admin.access_token })).status === 200

  // L'extension crée la collection en arrière-plan, après le démarrage du serveur
  await until(async () => (await api('GET', '/collections/impersonation_log', { token: admin.access_token })).status === 200, 60000)

  member = await createUser({ role: await createMemberRole() })
})

describe('setup', () => {
  it('creates the audit log collection', async () => {
    const { status, json } = await api('GET', '/fields/impersonation_log', { token: admin.access_token })
    assert.equal(status, 200)
    const fields = json.data.map(f => f.field).sort()
    assert.deepEqual(fields, ['admin_id', 'ended_at', 'expires_at', 'id', 'ip', 'reason', 'started_at', 'target_id', 'user_agent'])
  })
})

describe('authentication guard', () => {
  it('requires a user', async () => {
    const res = await api('POST', '/impersonation/start', { body: { user_id: member.id, reason: 'support ticket', otp: '123456' } })
    assert.equal(res.status, 401)
    assert.equal(errorCode(res), 'INVALID_CREDENTIALS')
    assert.equal(reason(res), 'unauthenticated')
  })

  it('answers in English by default and in the Accept-Language otherwise', async () => {
    const en = await api('POST', '/impersonation/start', { body: {} })
    assert.equal(en.json.errors[0].message, 'Authentication required.')
    const fr = await api('POST', '/impersonation/start', { body: {}, headers: { 'accept-language': 'fr-BE,fr;q=0.9' } })
    assert.equal(fr.json.errors[0].message, 'Authentification requise.')
  })

  it('is reserved to administrators', async () => {
    const session = await login(member.email, MEMBER_PASSWORD)
    const res = await start({ user_id: adminId, reason: 'support ticket', otp: '123456' }, session.access_token)
    assert.equal(res.status, 403)
    assert.equal(errorCode(res), 'FORBIDDEN')
    assert.equal(reason(res), 'admin_required')
  })
})

describe('start requirements', () => {
  it('requires 2FA on the administrator', async () => {
    const res = await start({ user_id: member.id, reason: 'support ticket', otp: '123456' })
    assert.equal(res.status, 400)
    assert.equal(reason(res), 'tfa_required')
  })

  it('enables 2FA on the admin', async () => {
    const generated = await api('POST', '/users/me/tfa/generate', { token: admin.access_token, body: { password: PASSWORD } })
    assert.equal(generated.status, 200, JSON.stringify(generated.json))
    tfaSecret = generated.json.data.secret

    const enabled = await api('POST', '/users/me/tfa/enable', { token: admin.access_token, body: { secret: tfaSecret, otp: otp() } })
    assert.ok([200, 204].includes(enabled.status), JSON.stringify(enabled.json))
  })

  it('validates the payload', async () => {
    const invalid = await start({ user_id: 'nope', reason: 'support ticket', otp: otp() })
    assert.equal(invalid.status, 400)
    assert.equal(reason(invalid), 'invalid_user')

    const self = await start({ user_id: adminId, reason: 'support ticket', otp: otp() })
    assert.equal(self.status, 400)
    assert.equal(reason(self), 'self_impersonation')

    const short = await start({ user_id: member.id, reason: 'abc', otp: otp() })
    assert.equal(short.status, 400)
    assert.equal(reason(short), 'reason_required')
  })

  it('asks for the OTP, then rejects a wrong one', async () => {
    const missing = await start({ user_id: member.id, reason: 'support ticket' })
    assert.equal(missing.status, 401)
    assert.equal(reason(missing), 'reauthentication_required')
    assert.equal(missing.json.errors[0].extensions.method, 'otp')

    const wrong = await start({ user_id: member.id, reason: 'support ticket', otp: '000000' })
    assert.equal(wrong.status, 401)
    assert.equal(errorCode(wrong), 'INVALID_OTP')
    assert.equal(reason(wrong), 'invalid_otp')
  })

  it('refuses an unknown user', async () => {
    const res = await start({ user_id: randomUUID(), reason: 'support ticket', otp: otp() })
    assert.equal(res.status, 404)
    assert.equal(reason(res), 'user_not_found')
  })

  it('refuses to impersonate an administrator', async () => {
    otherAdmin = await createUser({ role: adminRoleId })
    const res = await start({ user_id: otherAdmin.id, reason: 'support ticket', otp: otp() })
    assert.equal(res.status, 403)
    assert.equal(reason(res), 'admin_target')
  })

  // L'administrateur existant est déplacé dans un rôle enfant plutôt qu'un utilisateur créé : Directus 12 limite les sièges
  it('refuses a user who inherits administrator access from a parent role', async (t) => {
    const nestable = await api('GET', '/fields/directus_roles/parent', { token: admin.access_token })
    if (nestable.status !== 200) return t.skip('roles are not nestable on this Directus version')

    const child = await api('POST', '/roles', { token: admin.access_token, body: { name: `e2e child ${randomUUID().slice(0, 8)}`, parent: adminRoleId } })
    assert.equal(child.status, 200, JSON.stringify(child.json))
    const moved = await api('PATCH', `/users/${otherAdmin.id}`, { token: admin.access_token, body: { role: child.json.data.id } })
    assert.equal(moved.status, 200, JSON.stringify(moved.json))

    const res = await start({ user_id: otherAdmin.id, reason: 'support ticket', otp: otp() })
    assert.equal(res.status, 403)
    assert.equal(reason(res), 'admin_target')
  })
})

describe('impersonation session', () => {
  let session

  it('issues a short-lived access token without refresh token', async () => {
    const res = await start({ user_id: member.id, reason: 'E2E support ticket', otp: otp() })
    assert.equal(res.status, 200, JSON.stringify(res.json))
    session = res.json.data

    assert.ok(session.access_token)
    assert.equal(session.refresh_token, undefined)
    assert.equal(session.expires, TTL_SECONDS * 1000)
    assert.equal(session.user.id, member.id)

    const claims = decode(session.access_token)
    assert.equal(claims.id, member.id)
    assert.equal(claims.imp, adminId)
    assert.equal(claims.jti, session.log_id)
    assert.equal(claims.admin_access, false)
    assert.equal(claims.exp - claims.iat, TTL_SECONDS)
  })

  it('acts as the impersonated user', async () => {
    const res = await api('GET', '/users/me?fields=id,email', { token: session.access_token })
    assert.equal(res.status, 200, JSON.stringify(res.json))
    assert.equal(res.json.data.id, member.id)
    assert.equal(res.json.data.email, member.email)
  })

  it('is not an administrator session', async () => {
    // Un administrateur verrait au moins 3 utilisateurs (lui-même, le membre et l'autre admin) ; le membre ne voit que lui
    const res = await api('GET', '/users?fields=id&limit=-1', { token: session.access_token })
    assert.ok(res.status === 403 || res.status === 200, `${res.status}`)
    if (res.status === 200) assert.deepEqual(res.json.data.map(user => user.id), [member.id])
  })

  it('is read-only', async () => {
    for (const [method, path, body] of [
      ['PATCH', '/users/me', { first_name: 'Hacked' }],
      ['POST', '/items/impersonation_log', {}],
      ['DELETE', `/users/${member.id}`],
    ]) {
      const res = await api(method, path, { token: session.access_token, body })
      assert.equal(res.status, 403, `${method} ${path}`)
      assert.equal(errorCode(res), 'FORBIDDEN')
      assert.equal(reason(res), 'read_only')
    }

    const me = await api('GET', '/users/me?fields=first_name', { token: session.access_token })
    assert.equal(me.json.data.first_name, 'E2E')
  })

  it('cannot start a nested impersonation', async () => {
    const res = await start({ user_id: adminId, reason: 'support ticket', otp: otp() }, session.access_token)
    assert.equal(res.status, 403)
  })

  it('does not accept the administrator token to stop', async () => {
    const res = await api('POST', '/impersonation/stop', { token: admin.access_token })
    assert.equal(res.status, 401)
  })

  it('is journaled, then closed on stop', async () => {
    const query = () => api('GET', `/items/impersonation_log?filter[id][_eq]=${session.log_id}`, { token: admin.access_token })

    const open = await query()
    assert.equal(open.status, 200, JSON.stringify(open.json))
    const [row] = open.json.data
    assert.equal(row.admin_id, adminId)
    assert.equal(row.target_id, member.id)
    assert.equal(row.reason, 'E2E support ticket')
    assert.ok(row.started_at)
    assert.equal(row.ended_at, null)
    assert.equal((new Date(row.expires_at) - new Date(row.started_at)) / 1000, TTL_SECONDS)

    const stop = await api('POST', '/impersonation/stop', { token: session.access_token })
    assert.equal(stop.status, 200, JSON.stringify(stop.json))

    const closed = await query()
    assert.ok(closed.json.data[0].ended_at)
  })
})

describe('translation strings', () => {
  it('override the built-in messages', async () => {
    const created = await api('POST', '/translations', {
      token: admin.access_token,
      body: { key: 'impersonation.unauthenticated', language: 'fr-FR', value: 'Connectez-vous pour continuer.' },
    })
    assert.equal(created.status, 200, JSON.stringify(created.json))

    // Les translation strings sont mises en cache 30 s par l'extension
    const message = await until(async () => {
      const res = await api('POST', '/impersonation/start', { body: {}, headers: { 'accept-language': 'fr-FR' } })
      return res.json.errors[0].message === 'Connectez-vous pour continuer.' && res.json.errors[0].message
    })
    assert.equal(message, 'Connectez-vous pour continuer.')
  })
})

// En dernier : bloque l'administrateur pendant 10 minutes
describe('rate limiting', () => {
  it('blocks the administrator after repeated wrong OTPs', async () => {
    let status
    for (let attempt = 0; attempt < 6; attempt++) {
      status = (await start({ user_id: member.id, reason: 'support ticket', otp: '000000' })).status
      if (status === 429) break
    }
    assert.equal(status, 429)

    const valid = await start({ user_id: member.id, reason: 'support ticket', otp: otp() })
    assert.equal(valid.status, 429)
    assert.equal(reason(valid), 'too_many_requests')
  })
})
