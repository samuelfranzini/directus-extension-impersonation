import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import { ensureSchema, LOG_COLLECTION } from '../../src/schema.js'

// Faux contexte d'extension : enregistre les appels aux services Directus
const fakeContext = ({ tables = [], missingColumns = [], registered = true, limitExceeded = false } = {}) => {
  const calls = { collections: [], fields: [], created: [], altered: [], warnings: [] }

  // Colonnes demandées à knex, sous forme « champ:type »
  const recorder = (into) => {
    const column = () => ({ primary: () => column(), notNullable: () => column() })
    const add = type => (field) => { into.push(`${field}:${type}`); return column() }
    return { uuid: add('uuid'), text: add('text'), string: add('string'), timestamp: add('timestamp') }
  }

  const database = () => ({ where: () => ({ first: async () => (registered ? {} : undefined) }) })
  database.schema = {
    hasTable: async name => tables.includes(name),
    hasColumn: async (table, column) => !missingColumns.includes(`${table}.${column}`),
    createTable: async (name, build) => { const cols = []; build(recorder(cols)); calls.created.push({ name, cols }) },
    alterTable: async (name, build) => { const cols = []; build(recorder(cols)); calls.altered.push({ name, cols }) },
  }

  return {
    calls,
    context: {
      database,
      getSchema: async () => ({}),
      logger: { info() {}, warn: m => calls.warnings.push(m) },
      services: {
        CollectionsService: class {
          async createOne(def) {
            if (limitExceeded) throw Object.assign(new Error('Collections limit exceeded.'), { code: 'LIMIT_EXCEEDED' })
            calls.collections.push(def)
          }
        },
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

    assert.deepEqual([calls.collections, calls.fields, calls.created, calls.altered], [[], [], [], []])
  })

  it('adds missing columns to an existing collection', async () => {
    const { calls, context } = fakeContext({ tables: [LOG_COLLECTION], missingColumns: [`${LOG_COLLECTION}.ended_at`] })
    await ensureSchema(context)

    assert.deepEqual(calls.collections, [])
    assert.deepEqual(calls.fields.map(f => `${f.collection}.${f.field}`), [`${LOG_COLLECTION}.ended_at`])
  })

  it('falls back to a database-only table when the collections limit is reached', async () => {
    const { calls, context } = fakeContext({ limitExceeded: true })
    await ensureSchema(context)

    assert.deepEqual(calls.collections, [])
    assert.equal(calls.created.length, 1)
    assert.equal(calls.created[0].name, LOG_COLLECTION)
    assert.deepEqual(
      calls.created[0].cols.sort(),
      ['admin_id:uuid', 'ended_at:timestamp', 'expires_at:timestamp', 'id:uuid', 'ip:string', 'reason:text',
        'started_at:timestamp', 'target_id:uuid', 'user_agent:string'],
    )
    assert.equal(calls.warnings.length, 1)
  })

  it('rethrows any other creation error', async () => {
    const { context } = fakeContext()
    context.services.CollectionsService = class { async createOne() { throw new Error('boom') } }

    await assert.rejects(ensureSchema(context), /boom/)
  })

  it('adds missing columns of an unregistered table with knex', async () => {
    const { calls, context } = fakeContext({
      tables: [LOG_COLLECTION], registered: false, missingColumns: [`${LOG_COLLECTION}.ended_at`],
    })
    await ensureSchema(context)

    assert.deepEqual(calls.fields, [])
    assert.deepEqual(calls.altered, [{ name: LOG_COLLECTION, cols: ['ended_at:timestamp'] }])
  })
})
