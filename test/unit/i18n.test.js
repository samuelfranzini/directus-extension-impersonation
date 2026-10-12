import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import { createTranslator, ERRORS, matchLanguage, MESSAGES, parseAcceptLanguage } from '../../src/i18n.js'

// Faux knex : directus_translations, directus_settings et directus_users
const fakeDatabase = ({ translations = [], defaultLanguage = 'en-US', users = {} } = {}) => table => ({
  where(...args) {
    if (table === 'directus_translations') return { select: async () => translations }
    const id = args[0]?.id
    return { first: async () => users[id] ?? null }
  },
  first: async () => (table === 'directus_settings' ? { default_language: defaultLanguage } : null),
})

const request = ({ acceptLanguage, user } = {}) => ({
  accountability: user ? { user } : null,
  get: name => (name === 'accept-language' ? acceptLanguage : undefined),
})

describe('parseAcceptLanguage', () => {
  it('orders languages by quality', () => {
    assert.deepEqual(parseAcceptLanguage('en;q=0.5, fr-BE, fr;q=0.9'), ['fr-BE', 'fr', 'en'])
  })

  it('ignores wildcards, invalid tags and empty headers', () => {
    assert.deepEqual(parseAcceptLanguage('*, <script>, de;q=0'), [])
    assert.deepEqual(parseAcceptLanguage(undefined), [])
  })
})

describe('matchLanguage', () => {
  it('prefers exact matches, then the base language', () => {
    assert.equal(matchLanguage('fr-FR', ['fr-BE', 'fr-FR']), 'fr-FR')
    assert.equal(matchLanguage('fr-CA', ['en-US', 'fr-FR']), 'fr-FR')
    assert.equal(matchLanguage('fr', ['fr-FR']), 'fr-FR')
    assert.equal(matchLanguage('de', ['en-US', 'fr-FR']), null)
  })
})

describe('messages', () => {
  it('translates every error reason in every built-in language', () => {
    for (const language of Object.keys(MESSAGES)) {
      for (const reason of Object.keys(ERRORS)) {
        assert.ok(MESSAGES[language][reason], `${language}.${reason}`)
      }
    }
  })

  it('has no message without a matching error', () => {
    for (const language of Object.keys(MESSAGES)) {
      for (const key of Object.keys(MESSAGES[language])) {
        assert.ok(ERRORS[key], `${language}.${key}`)
      }
    }
  })

  it('only uses standard Directus error codes', () => {
    const codes = new Set(Object.values(ERRORS).map(e => e.code))
    for (const code of codes) {
      assert.ok(['INVALID_CREDENTIALS', 'INVALID_OTP', 'FORBIDDEN', 'INVALID_PAYLOAD', 'ROUTE_NOT_FOUND', 'REQUESTS_EXCEEDED', 'INTERNAL_SERVER_ERROR'].includes(code), code)
    }
  })
})

describe('createTranslator', () => {
  it('answers in English by default', async () => {
    const translate = createTranslator({ database: fakeDatabase() })
    assert.equal(await translate(request(), 'unauthenticated'), 'Authentication required.')
  })

  it('uses the Accept-Language header', async () => {
    const translate = createTranslator({ database: fakeDatabase() })
    assert.equal(await translate(request({ acceptLanguage: 'fr-BE,fr;q=0.9' }), 'unauthenticated'), 'Authentification requise.')
  })

  it('prefers the user language over the header', async () => {
    const translate = createTranslator({ database: fakeDatabase({ users: { u1: { language: 'en-US' } } }) })
    assert.equal(await translate(request({ acceptLanguage: 'fr-FR', user: 'u1' }), 'unauthenticated'), 'Authentication required.')
  })

  it('falls back on the project default language', async () => {
    const translate = createTranslator({ database: fakeDatabase({ defaultLanguage: 'fr-FR' }) })
    assert.equal(await translate(request(), 'unauthenticated'), 'Authentification requise.')
  })

  it('lets translation strings override the built-in messages', async () => {
    const translations = [{ key: 'impersonation.unauthenticated', language: 'fr-FR', value: 'Connectez-vous.' }]
    const translate = createTranslator({ database: fakeDatabase({ translations }) })
    assert.equal(await translate(request({ acceptLanguage: 'fr' }), 'unauthenticated'), 'Connectez-vous.')
    assert.equal(await translate(request({ acceptLanguage: 'en' }), 'unauthenticated'), 'Authentication required.')
  })

  it('interpolates parameters', async () => {
    const translate = createTranslator({ database: fakeDatabase() })
    assert.equal(await translate(request(), 'reason_required', { min: 5, max: 500 }), 'A reason of 5 to 500 characters is required.')
  })

  it('falls back on built-in messages when the database is unavailable', async () => {
    const translate = createTranslator({ database: () => { throw new Error('down') } })
    assert.equal(await translate(request({ acceptLanguage: 'fr' }), 'unauthenticated'), 'Authentification requise.')
  })
})
