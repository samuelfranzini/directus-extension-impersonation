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

      const fieldsService = new FieldsService({ knex: database, schema: await freshSchema() })
      for (const field of missingColumns) await fieldsService.createField(definition.collection, field)
      logger.info(`[impersonation] fields added to ${definition.collection}: ${missingColumns.map(f => f.field).join(', ')}`)
      continue
    }

    await new CollectionsService({ knex: database, schema: await freshSchema() }).createOne(definition)
    logger.info(`[impersonation] collection ${definition.collection} created`)
  }
}
