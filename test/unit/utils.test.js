import assert from 'node:assert/strict'
import { createHmac } from 'node:crypto'
import { describe, it } from 'node:test'
import { blocked, clamp, decodeJwtPayload, fail, hit, isUuid, parseDuration, signJwt } from '../../src/utils.js'

describe('parseDuration', () => {
  it('parses Directus duration strings', () => {
    assert.equal(parseDuration('15m', 0), 15 * 60000)
    assert.equal(parseDuration('1h', 0), 3600000)
    assert.equal(parseDuration('500', 0), 500)
    assert.equal(parseDuration(' 30 s ', 0), 30000)
  })

  it('keeps numbers and falls back on invalid input', () => {
    assert.equal(parseDuration(1234, 0), 1234)
    assert.equal(parseDuration(undefined, 42), 42)
    assert.equal(parseDuration('soon', 42), 42)
  })
})

describe('clamp', () => {
  it('keeps a value within bounds', () => {
    assert.equal(clamp(5, 1, 10), 5)
    assert.equal(clamp(0, 1, 10), 1)
    assert.equal(clamp(99, 1, 10), 10)
  })
})

describe('isUuid', () => {
  it('accepts uuids only', () => {
    assert.equal(isUuid('3e9514b5-8083-4e7b-8504-2f1e893ab6e6'), true)
    assert.equal(isUuid('3E9514B5-8083-4E7B-8504-2F1E893AB6E6'), true)
    assert.equal(isUuid('not-a-uuid'), false)
    assert.equal(isUuid(''), false)
    assert.equal(isUuid(undefined), false)
  })
})

describe('hit (rate limiter)', () => {
  it('allows up to max attempts per window', () => {
    const key = `test:${Math.random()}`
    assert.equal(hit(key, 2, 60000), true)
    assert.equal(hit(key, 2, 60000), true)
    assert.equal(hit(key, 2, 60000), false)
  })

  it('stays bounded under a flood of distinct keys', () => {
    for (let i = 0; i < 25000; i++) hit(`flood:${i}`, 1, 60000)
    const key = `test:${Math.random()}`
    assert.equal(hit(key, 1, 60000), true)
    assert.equal(hit(key, 1, 60000), false)
  })

  it('blocked reports the limit without counting an attempt', () => {
    const key = `test:${Math.random()}`
    assert.equal(blocked(key, 2), false)
    hit(key, 2, 60000)
    assert.equal(blocked(key, 2), false)
    hit(key, 2, 60000)
    assert.equal(blocked(key, 2), true)
  })

  it('resets after the window expires', async () => {
    const key = `test:${Math.random()}`
    assert.equal(hit(key, 1, 10), true)
    assert.equal(hit(key, 1, 10), false)
    await new Promise(resolve => setTimeout(resolve, 20))
    assert.equal(hit(key, 1, 10), true)
  })
})

describe('fail', () => {
  it('formats a Directus error', () => {
    let sent
    const res = { status(code) { sent = { code }; return this }, json(body) { sent.body = body } }
    fail(res, 403, 'FORBIDDEN', 'Nope.', { reason: 'read_only' })
    assert.equal(sent.code, 403)
    assert.deepEqual(sent.body, { errors: [{ message: 'Nope.', extensions: { code: 'FORBIDDEN', reason: 'read_only' } }] })
  })
})

describe('signJwt / decodeJwtPayload', () => {
  const payload = { id: 'user', role: null, app_access: true, admin_access: false, imp: 'admin', iss: 'directus', exp: 1893456000 }

  it('signs a verifiable HS256 token', () => {
    const token = signJwt(payload, 'secret')
    const [header, body, signature] = token.split('.')

    assert.deepEqual(JSON.parse(Buffer.from(header, 'base64url').toString()), { alg: 'HS256', typ: 'JWT' })
    assert.equal(signature, createHmac('sha256', 'secret').update(`${header}.${body}`).digest('base64url'))
  })

  it('round-trips the payload', () => {
    assert.deepEqual(decodeJwtPayload(signJwt(payload, 'secret')), payload)
  })

  it('returns null for anything that is not a JWT', () => {
    assert.equal(decodeJwtPayload(undefined), null)
    assert.equal(decodeJwtPayload('static-token'), null)
    assert.equal(decodeJwtPayload('a.!!!.c'), null)
    assert.equal(decodeJwtPayload(`a.${Buffer.from('"text"').toString('base64url')}.c`), null)
  })
})
