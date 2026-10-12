import assert from 'node:assert/strict'
import { beforeEach, describe, it } from 'node:test'
import extension from '../../src/index.js'
import { signJwt } from '../../src/utils.js'

const SECRET = 'unit-test-secret'
const ADMIN = '11111111-1111-4111-8111-111111111111'
const MEMBER = '22222222-2222-4222-8222-222222222222'

const impersonationToken = signJwt({ id: MEMBER, imp: ADMIN, jti: 'log', iss: 'directus' }, SECRET)
const regularToken = signJwt({ id: ADMIN, role: null, app_access: true, admin_access: true, iss: 'directus' }, SECRET)

// Enregistre l'extension sur de faux `init` et `app`, puis expose les middlewares et routes
const load = (env = {}) => {
  const database = () => { throw new Error('database not available in unit tests') }
  database.schema = { hasTable: async () => true, hasColumn: async () => false }

  const handlers = {}
  extension({ init: (event, handler) => { handlers[event] = handler } }, {
    database,
    env: { SECRET, IMPERSONATION_AUTO_SETUP: 'false', ...env },
    logger: { info() {}, warn() {}, error() {} },
  })

  const middlewares = []
  const routes = {}
  handlers['middlewares.after']({
    app: {
      use: fn => middlewares.push(fn),
      post: (path, fn) => { routes[path] = fn },
    },
  })

  return { middlewares, routes }
}

const request = ({ method = 'GET', path = '/', token, accountability = null, body } = {}) => ({
  method,
  path,
  token,
  accountability,
  body,
  ip: '127.0.0.1',
  get: () => undefined,
})

const response = () => {
  const res = {
    statusCode: 200,
    body: null,
    status(code) { res.statusCode = code; return res },
    json(body) { res.body = body; return res },
  }
  return res
}

const runGuard = async (middlewares, req) => {
  const res = response()
  let passed = false
  await middlewares[0](req, res, () => { passed = true })
  return { res, passed }
}

describe('registration', () => {
  it('registers on middlewares.after', () => {
    const registered = []
    extension({ init: event => registered.push(event) }, {
      database: Object.assign(() => ({}), { schema: {} }),
      env: { SECRET, IMPERSONATION_AUTO_SETUP: 'false' },
      logger: { info() {}, warn() {}, error() {} },
    })
    assert.deepEqual(registered, ['middlewares.after'])
  })

  it('exposes the start and stop routes', () => {
    const { routes } = load()
    assert.deepEqual(Object.keys(routes).sort(), ['/impersonation/start', '/impersonation/stop'])
  })
})

describe('read-only guard', () => {
  let middlewares
  beforeEach(() => { ({ middlewares } = load()) })

  for (const method of ['GET', 'HEAD', 'OPTIONS']) {
    it(`lets ${method} through for an impersonation token`, async () => {
      const { passed } = await runGuard(middlewares, request({ method, token: impersonationToken }))
      assert.equal(passed, true)
    })
  }

  for (const method of ['POST', 'PATCH', 'PUT', 'DELETE']) {
    it(`refuses ${method} for an impersonation token`, async () => {
      const { res, passed } = await runGuard(middlewares, request({ method, path: '/items/articles', token: impersonationToken }))
      assert.equal(passed, false)
      assert.equal(res.statusCode, 403)
      assert.equal(res.body.errors[0].extensions.code, 'FORBIDDEN')
      assert.equal(res.body.errors[0].extensions.reason, 'read_only')
    })
  }

  it('lets the impersonation token end its own session', async () => {
    const { passed } = await runGuard(middlewares, request({ method: 'POST', path: '/impersonation/stop', token: impersonationToken }))
    assert.equal(passed, true)
  })

  it('does not restrict regular tokens', async () => {
    const { passed } = await runGuard(middlewares, request({ method: 'POST', path: '/items/articles', token: regularToken }))
    assert.equal(passed, true)
  })

  it('does not restrict static tokens or anonymous requests', async () => {
    assert.equal((await runGuard(middlewares, request({ method: 'POST', token: 'static-token' }))).passed, true)
    assert.equal((await runGuard(middlewares, request({ method: 'POST' }))).passed, true)
  })
})

describe('POST /impersonation/start validation', () => {
  let start
  beforeEach(() => { start = load().routes['/impersonation/start'] })

  const admin = { user: ADMIN, admin: true }
  const body = { user_id: MEMBER, reason: 'Support ticket 1234', otp: '123456' }

  const run = async (options) => {
    const res = response()
    await start(request({ method: 'POST', path: '/impersonation/start', ...options }), res)
    return res
  }

  it('requires authentication', async () => {
    const res = await run({ body })
    assert.equal(res.statusCode, 401)
    assert.equal(res.body.errors[0].extensions.reason, 'unauthenticated')
  })

  it('is reserved to administrators', async () => {
    const res = await run({ body, token: regularToken, accountability: { user: MEMBER, admin: false } })
    assert.equal(res.statusCode, 403)
    assert.equal(res.body.errors[0].extensions.reason, 'admin_required')
  })

  it('refuses to nest an impersonation', async () => {
    const res = await run({ body, token: impersonationToken, accountability: admin })
    assert.equal(res.statusCode, 403)
    assert.equal(res.body.errors[0].extensions.reason, 'already_impersonating')
  })

  it('refuses an invalid user id', async () => {
    const res = await run({ body: { ...body, user_id: 'nope' }, token: regularToken, accountability: admin })
    assert.equal(res.statusCode, 400)
    assert.equal(res.body.errors[0].extensions.reason, 'invalid_user')
  })

  it('refuses to impersonate oneself', async () => {
    const res = await run({ body: { ...body, user_id: ADMIN.toUpperCase() }, token: regularToken, accountability: admin })
    assert.equal(res.statusCode, 400)
    assert.equal(res.body.errors[0].extensions.reason, 'self_impersonation')
  })

  it('requires a reason', async () => {
    for (const reason of [undefined, '   ', 'abc', 'x'.repeat(501)]) {
      const res = await run({ body: { ...body, reason }, token: regularToken, accountability: admin })
      assert.equal(res.statusCode, 400)
      assert.equal(res.body.errors[0].extensions.reason, 'reason_required')
    }
  })
})

describe('POST /impersonation/stop', () => {
  it('requires an impersonation token', async () => {
    const stop = load().routes['/impersonation/stop']
    const res = response()
    await stop(request({ method: 'POST', token: regularToken, accountability: { user: ADMIN, admin: true } }), res)
    assert.equal(res.statusCode, 401)
  })
})
