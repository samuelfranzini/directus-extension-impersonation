import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import { ensureSchema, LOG_COLLECTION } from '../../src/schema.js'

// Faux contexte d'extension : enregistre les appels aux services Directus
const fakeContext = ({ tables = [], missingColumns = [] } = {}) => {
  const calls = { collections: [], fields: [] }

  const database = () => ({})
  database.schema = {
    hasTable: async name => tables.includes(name),
    hasColumn: async (table, column) => !missingColumns.includes(`${table}.${column}`),
  }

  return {
    calls,
    context: {
      database,
      getSchema: async () => ({}),
      logger: { info() {} },
      services: {
        CollectionsService: class { async createOne(def) { calls.collections.push(def) } },
        FieldsService: class { async createField(collection, field) { calls.fields.push({ collection, ...field }) } },
      },
    },
  }
}

describe('ensureSchema', () => {
  it('creates the audit log collection on a fresh database', async () => {
    const { calls, context } = fakeContext()
    await ensureSchema(context)

    assert.deepEqual(calls.collections.map(c => c.collection), [LOG_COLLECTION])
    assert.deepEqual(calls.fields, [])
  })

  it('defines a uuid primary key and the audit fields', async () => {
    const { calls, context } = fakeContext()
    await ensureSchema(context)

    const [definition] = calls.collections
    const pk = definition.fields.find(f => f.schema?.is_primary_key)
    assert.equal(pk?.field, 'id')
    assert.equal(pk.type, 'uuid')
    assert.deepEqual(
      definition.fields.map(f => f.field).sort(),
      ['admin_id', 'expires_at', 'id', 'ip', 'reason', 'started_at', 'target_id', 'user_agent', 'ended_at'].sort(),
    )
  })

  it('keeps the audit log without a foreign key, so it survives user deletion', async () => {
    const { calls, context } = fakeContext()
    await ensureSchema(context)

    for (const field of calls.collections[0].fields) {
      assert.ok(!field.meta?.special?.includes('m2o'), field.field)
    }
  })

  it('never touches an existing collection', async () => {
    const { calls, context } = fakeContext({ tables: [LOG_COLLECTION] })
    await ensureSchema(context)

    assert.deepEqual(calls, { collections: [], fields: [] })
  })

  it('adds missing columns to an existing collection', async () => {
    const { calls, context } = fakeContext({ tables: [LOG_COLLECTION], missingColumns: [`${LOG_COLLECTION}.ended_at`] })
    await ensureSchema(context)

    assert.deepEqual(calls.collections, [])
    assert.deepEqual(calls.fields.map(f => `${f.collection}.${f.field}`), [`${LOG_COLLECTION}.ended_at`])
  })
})
