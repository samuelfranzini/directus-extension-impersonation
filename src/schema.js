// Collection nécessaire à l'extension, créée au démarrage si elle n'existe pas encore. Sur une collection
// existante, seules les colonnes manquantes sont ajoutées (rien n'est modifié ni supprimé).
// Désactivable avec IMPERSONATION_AUTO_SETUP=false.

const uuidPk = {
  field: 'id',
  type: 'uuid',
  meta: { hidden: true, readonly: true, special: ['uuid'] },
  schema: { is_primary_key: true, length: 36, has_auto_increment: false },
}

// Identifiants conservés tels quels, sans clé étrangère : le journal d'audit survit à la suppression d'un utilisateur
const uuid = (field, nullable = false) => ({
  field,
  type: 'uuid',
  meta: { readonly: true },
  schema: { is_nullable: nullable },
})

const string = (field, length = 255) => ({
  field,
  type: 'string',
  meta: { readonly: true },
  schema: { max_length: length },
})

const timestamp = (field, nullable = true) => ({
  field,
  type: 'timestamp',
  meta: { readonly: true, display: 'datetime' },
  schema: { is_nullable: nullable },
})

export const LOG_COLLECTION = 'impersonation_log'

const COLLECTIONS = [
  {
    collection: LOG_COLLECTION,
    meta: {
      icon: 'visibility',
      note: 'Impersonation: audit log of read-only account impersonation sessions',
      display_template: '{{started_at}} · {{reason}}',
      hidden: false,
      group: null,
    },
    schema: {},
    fields: [
      uuidPk,
      uuid('admin_id'),
      uuid('target_id'),
      { field: 'reason', type: 'text', meta: { readonly: true }, schema: { is_nullable: false } },
      string('ip', 64),
      string('user_agent', 512),
      timestamp('started_at', false),
      timestamp('expires_at', false),
      timestamp('ended_at'),
    ],
  },
]

// Directus plafonne le nombre de collections enregistrées (tier Core : 25). Les tables « database-only »,
// sans métadonnées Directus, ne sont pas comptées : on y retombe quand la limite est atteinte.
// L'extension n'écrit dans le journal qu'avec knex ; seule la consultation dans le Studio est perdue.
const isLimitError = err =>
  err?.code === 'LIMIT_EXCEEDED' || err?.extensions?.code === 'LIMIT_EXCEEDED' || /limit exceeded/i.test(err?.message ?? '')

const addColumn = (table, { field, type, schema = {} }) => {
  const column = field === 'id' && schema.is_primary_key
    ? table.uuid(field).primary()
    : type === 'uuid' ? table.uuid(field)
      : type === 'text' ? table.text(field)
        : type === 'timestamp' ? table.timestamp(field, { useTz: true })
          : table.string(field, schema.max_length ?? 255)
  if (!schema.is_primary_key && schema.is_nullable === false) column.notNullable()
}

const isRegistered = async (database, collection) =>
  Boolean(await database('directus_collections').where({ collection }).first())

export const ensureSchema = async ({ services, getSchema, database, logger }) => {
  const { CollectionsService, FieldsService } = services
  const freshSchema = () => getSchema({ database, bypassCache: true })

  for (const definition of COLLECTIONS) {
    if (await database.schema.hasTable(definition.collection)) {
      const missingColumns = []
      for (const field of definition.fields) {
        if (!(await database.schema.hasColumn(definition.collection, field.field))) missingColumns.push(field)
      }
      if (!missingColumns.length) continue

      if (await isRegistered(database, definition.collection)) {
        const fieldsService = new FieldsService({ knex: database, schema: await freshSchema() })
        for (const field of missingColumns) await fieldsService.createField(definition.collection, field)
      } else {
        await database.schema.alterTable(definition.collection, table => {
          for (const field of missingColumns) addColumn(table, field)
        })
      }
      logger.info(`[impersonation] fields added to ${definition.collection}: ${missingColumns.map(f => f.field).join(', ')}`)
      continue
    }

    try {
      await new CollectionsService({ knex: database, schema: await freshSchema() }).createOne(definition)
      logger.info(`[impersonation] collection ${definition.collection} created`)
    } catch (err) {
      if (!isLimitError(err)) throw err
      await database.schema.createTable(definition.collection, table => {
        for (const field of definition.fields) addColumn(table, field)
      })
      logger.warn(`[impersonation] collections limit reached: ${definition.collection} created as a database-only table `
        + '(not registered in Directus, so not visible in the Studio)')
    }
  }
}
