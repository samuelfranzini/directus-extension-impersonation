import { randomUUID } from 'node:crypto'
import { createGuardrails, verifySync } from 'otplib'
import { createTranslator, ERRORS } from './i18n.js'
import { ensureSchema, LOG_COLLECTION } from './schema.js'
import { blocked, clamp, decodeJwtPayload, fail, hit, isUuid, parseDuration, signJwt } from './utils.js'

// Directus génère des secrets TFA de 10 octets (format historique Google Authenticator),
// alors que otplib v13 impose par défaut un minimum de 16 octets (RFC 4226).
const guardrails = createGuardrails({ MIN_SECRET_BYTES: 10 })

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS'])
const DEFAULT_TTL_MS = 15 * 60 * 1000
const MIN_TTL_MS = 60 * 1000
const MAX_TTL_MS = 60 * 60 * 1000
const REASON_MIN_LENGTH = 5
const REASON_MAX_LENGTH = 500
const MAX_ROLE_DEPTH = 20
const OTP_MAX_FAILURES = 5
const OTP_WINDOW_MS = 10 * 60 * 1000

export default ({ init, action }, context) => {
  const { database, env, logger } = context

  // Attendre le démarrage du serveur : la licence (LICENSE_KEY) n'est active qu'à ce moment, et Directus applique
  // les limites du tier Core tant qu'elle ne l'est pas (limite de collections).
  if (String(env.IMPERSONATION_AUTO_SETUP ?? 'true') !== 'false') {
    action('server.start', () => {
      ensureSchema(context).catch(err =>
        logger.error(`[impersonation] schema setup failed: ${err.message}`))
    })
  }

  const ttlMs = clamp(parseDuration(env.IMPERSONATION_TTL, DEFAULT_TTL_MS), MIN_TTL_MS, MAX_TTL_MS)

  const translate = createTranslator({ database })
  const sendError = async (req, res, reason, params, extensions = {}) => {
    const { status, code } = ERRORS[reason]
    return fail(res, status, code, await translate(req, reason, params), { reason, ...extensions })
  }

  // Directus ≥ 11 : droits portés par des policies (directus_access) ; Directus 10 : drapeaux du rôle.
  // Les rôles parents sont inclus (rôles imbriqués, Directus ≥ 11).
  let policiesSupported
  let roleParentSupported
  const hasPolicies = () => (policiesSupported ??= database.schema.hasTable('directus_policies'))
  const hasRoleParent = () => (roleParentSupported ??= database.schema.hasColumn('directus_roles', 'parent'))

  const roleTree = async (roleId) => {
    const ids = []
    const nested = await hasRoleParent()
    let current = roleId
    while (current && !ids.includes(current) && ids.length < MAX_ROLE_DEPTH) {
      ids.push(current)
      if (!nested) break
      current = (await database('directus_roles').where({ id: current }).first('parent'))?.parent
    }
    return ids
  }

  const getAccess = async (userId, roleId) => {
    const roles = await roleTree(roleId)
    let rows

    if (await hasPolicies()) {
      rows = await database('directus_access')
        .join('directus_policies', 'directus_policies.id', 'directus_access.policy')
        .where((query) => {
          query.where('directus_access.user', userId)
          if (roles.length) query.orWhereIn('directus_access.role', roles)
        })
        .select('directus_policies.admin_access', 'directus_policies.app_access')
    }
    else {
      rows = roles.length ? await database('directus_roles').whereIn('id', roles).select('admin_access', 'app_access') : []
    }

    return {
      admin: rows.some(row => Boolean(row.admin_access)),
      app: rows.some(row => Boolean(row.app_access)),
    }
  }

  init('middlewares.after', ({ app }) => {
    // Lecture seule : tout jeton portant la claim `imp` est refusé sur les méthodes d'écriture.
    app.use(async (req, res, next) => {
      try {
        if (SAFE_METHODS.has(req.method) || !decodeJwtPayload(req.token)?.imp || req.path === '/impersonation/stop') {
          return next()
        }
        return await sendError(req, res, 'read_only')
      }
      catch (error) {
        logger.error(error)
        return next(error)
      }
    })

    app.post('/impersonation/start', async (req, res) => {
      const adminId = req.accountability?.user
      if (!adminId) return sendError(req, res, 'unauthenticated')
      if (!req.accountability.admin) return sendError(req, res, 'admin_required')
      if (decodeJwtPayload(req.token)?.imp) return sendError(req, res, 'already_impersonating')

      try {
        const userId = String(req.body?.user_id || '').toLowerCase()
        const reason = String(req.body?.reason || '').trim()
        const otp = String(req.body?.otp || '').trim()

        if (!isUuid(userId)) return sendError(req, res, 'invalid_user')
        if (userId === String(adminId).toLowerCase()) return sendError(req, res, 'self_impersonation')
        if (reason.length < REASON_MIN_LENGTH || reason.length > REASON_MAX_LENGTH) {
          return sendError(req, res, 'reason_required', { min: REASON_MIN_LENGTH, max: REASON_MAX_LENGTH })
        }

        // Ré-authentification : un jeton d'accès volé ne suffit pas. Seuls les échecs comptent dans la limite.
        const rateKey = `impersonate:${adminId}`
        if (blocked(rateKey, OTP_MAX_FAILURES)) return sendError(req, res, 'too_many_requests')

        const admin = await database('directus_users').where({ id: adminId }).first('tfa_secret')
        if (!admin?.tfa_secret) return sendError(req, res, 'tfa_required')
        if (!otp) return sendError(req, res, 'reauthentication_required', {}, { method: 'otp' })

        const valid = /^\d{6}$/.test(otp)
          && verifySync({ token: otp, secret: admin.tfa_secret, epochTolerance: 30, guardrails }).valid
        if (!valid) {
          hit(rateKey, OTP_MAX_FAILURES, OTP_WINDOW_MS)
          return sendError(req, res, 'invalid_otp', {}, { method: 'otp' })
        }

        const target = await database('directus_users')
          .where({ id: userId })
          .first('id', 'role', 'status', 'first_name', 'last_name')
        if (!target || target.status !== 'active') return sendError(req, res, 'user_not_found')

        const access = await getAccess(target.id, target.role)
        if (access.admin) return sendError(req, res, 'admin_target')

        const logId = randomUUID()
        const now = Date.now()

        // Le jeton n'est émis qu'une fois l'emprunt journalisé
        await database(LOG_COLLECTION).insert({
          id: logId,
          admin_id: adminId,
          target_id: target.id,
          reason,
          ip: req.ip || null,
          user_agent: String(req.get('user-agent') || '').slice(0, 512) || null,
          started_at: new Date(now),
          expires_at: new Date(now + ttlMs),
        })

        // Mêmes claims qu'un jeton d'accès Directus, plus `imp` (administrateur) et `jti` (ligne de journal).
        // Aucun refresh token : la session s'arrête à l'expiration.
        const accessToken = signJwt({
          id: target.id,
          role: target.role,
          app_access: access.app,
          admin_access: false,
          imp: adminId,
          jti: logId,
          iss: 'directus',
          iat: Math.floor(now / 1000),
          exp: Math.floor((now + ttlMs) / 1000),
        }, env.SECRET)

        res.json({
          data: {
            access_token: accessToken,
            expires: ttlMs,
            log_id: logId,
            user: { id: target.id, first_name: target.first_name, last_name: target.last_name },
          },
        })
      }
      catch (error) {
        logger.error(error)
        sendError(req, res, 'internal_error')
      }
    })

    // Appelée avec le jeton d'emprunt lui-même : horodate la fin dans le journal.
    app.post('/impersonation/stop', async (req, res) => {
      const payload = decodeJwtPayload(req.token)
      if (!payload?.imp || !payload.jti || req.accountability?.user !== payload.id) {
        return sendError(req, res, 'unauthenticated')
      }

      try {
        await database(LOG_COLLECTION)
          .where({ id: payload.jti, admin_id: payload.imp })
          .whereNull('ended_at')
          .update({ ended_at: new Date() })
        res.json({ data: { ok: true } })
      }
      catch (error) {
        logger.error(error)
        sendError(req, res, 'internal_error')
      }
    })
  })
}
