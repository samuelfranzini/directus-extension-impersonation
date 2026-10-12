# directus-extension-impersonation

[![CI](https://github.com/samuelfranzini/directus-extension-impersonation/actions/workflows/ci.yml/badge.svg)](https://github.com/samuelfranzini/directus-extension-impersonation/actions/workflows/ci.yml)

Directus hook extension that lets an **administrator see what a user sees**, safely:

- **Read-only**: every write made with the impersonation token is refused, whatever the client
- **Short-lived**: a signed access token for the target user, 15 minutes by default, with no refresh token
- **Re-authenticated**: the administrator must give a valid one-time password (2FA) and a written reason
- **Audited**: each session is recorded in an `impersonation_log` collection (who, whom, why, from where, when)
- **Contained**: administrator accounts cannot be impersonated

Compatible with Directus `^10.10.0 || ^11.0.0 || ^12.0.0`.

## How it works

1. The administrator calls `POST /impersonation/start` with the target `user_id`, a `reason` and an `otp`.
2. The extension checks the requirements, writes the audit row, then signs an access token for the target with the Directus `SECRET`. The token carries the usual Directus claims plus `imp` (the administrator's id) and `jti` (the audit row id).
3. The client uses that token instead of its own. Requests made with it act as the target user, with the target's permissions.
4. A middleware refuses every request using a token that carries `imp` unless its method is `GET`, `HEAD` or `OPTIONS`.
5. `POST /impersonation/stop` closes the audit row. The token expires on its own anyway.

## Installation

From npm, in the Directus project that should load the extension:

```bash
npm install directus-extension-impersonation
```

Then restart Directus. Alternatively, take the archive attached to a [GitHub release](../../releases) and unpack it into the Directus `extensions` directory, or build it from source:

```bash
git clone git@github.com:samuelfranzini/directus-extension-impersonation.git
cd directus-extension-impersonation
npm install
npm run build        # produces dist/index.js (otplib is bundled)
```

Copy `package.json` and `dist/` into a `directus-extension-impersonation` folder inside the Directus `extensions` directory, then restart Directus. The release archive already unpacks to that folder.

## Database

Once the server has started (so that the license is active), the extension creates the collection it needs if it doesn't exist yet (an existing collection only gets missing columns). Set `IMPERSONATION_AUTO_SETUP=false` to manage it yourself.

| Collection | Purpose |
| --- | --- |
| `impersonation_log` | One row per session: `admin_id`, `target_id`, `reason`, `ip`, `user_agent`, `started_at`, `expires_at`, `ended_at` |

The identifiers are plain UUIDs with no foreign key, so the log survives the deletion of a user. Give **no permission** on this collection: only administrators can read it (Content → Impersonation Log) and only the extension writes to it.

Directus limits the number of registered collections (25 on the Core tier of Directus 12). When that limit is reached, the extension logs a warning and creates `impersonation_log` as a **database-only table**: it is not registered in Directus, so it doesn't count toward the limit, but it isn't visible in the Studio and must be read directly in the database. Sessions are audited either way.

## Configuration

| Environment variable | Description | Default |
| --- | --- | --- |
| `IMPERSONATION_TTL` | Lifetime of an impersonation token (`90s`, `15m`, `1h`…), bounded between 1 minute and 1 hour | `15m` |
| `IMPERSONATION_AUTO_SETUP` | Create the missing collection on startup | `true` |
| `SECRET` | Reused from the Directus configuration, signs the token | — |

## Security notes

- The administrator **must have 2FA enabled** and gives a fresh one-time password on every start. Only failed attempts count towards the limit (5 per 10 minutes per administrator).
- A target is refused when any of its policies — directly, through its role or through a parent role — grants `admin_access`.
- The token is **stateless**: it cannot be revoked before it expires, hence the short lifetime. There is no refresh token.
- The audit row is written **before** the token is issued: no session exists without a log entry.
- Directus' own activity log attributes what the token reads to the target user. The `impersonation_log` collection is the source of truth.
- GraphQL requests are `POST`, so they are refused for impersonation tokens (queries included). Use the REST API.
- WebSocket messages are not covered by the read-only middleware. Directus keeps WebSockets disabled by default (`WEBSOCKETS_ENABLED`); leave it that way if you use this extension.
- Rate limiting is kept in memory per Directus process. When running several instances, also enable the Directus rate limiter (`RATE_LIMITER_ENABLED`, with Redis) and set `IP_TRUST_PROXY` correctly behind a proxy so client IPs are accurate.

## Errors & translations

Errors follow the [Directus error format](https://directus.com/docs/guides/connect/errors). Branch on `extensions.code` (a standard Directus code); `extensions.reason` tells the exact case:

```json
{ "errors": [{ "message": "Invalid one-time password.", "extensions": { "code": "INVALID_OTP", "reason": "invalid_otp", "method": "otp" } }] }
```

| `reason` | `code` | HTTP |
| --- | --- | --- |
| `unauthenticated` | `INVALID_CREDENTIALS` | 401 |
| `reauthentication_required` | `INVALID_CREDENTIALS` | 401 |
| `invalid_otp` | `INVALID_OTP` | 401 |
| `admin_required` | `FORBIDDEN` | 403 |
| `admin_target` | `FORBIDDEN` | 403 |
| `already_impersonating` | `FORBIDDEN` | 403 |
| `read_only` | `FORBIDDEN` | 403 |
| `tfa_required` | `INVALID_PAYLOAD` | 400 |
| `invalid_user` | `INVALID_PAYLOAD` | 400 |
| `self_impersonation` | `INVALID_PAYLOAD` | 400 |
| `reason_required` | `INVALID_PAYLOAD` | 400 |
| `user_not_found` | `ROUTE_NOT_FOUND` | 404 |
| `too_many_requests` | `REQUESTS_EXCEEDED` | 429 |
| `internal_error` | `INTERNAL_SERVER_ERROR` | 500 |

`reauthentication_required` and `invalid_otp` carry `extensions.method: "otp"`. `read_only` is what any write attempted with an impersonation token receives, on any Directus route.

Messages are generic and translatable. The language is the Directus user's language, then the `Accept-Language` header, then the project default language. English and French are built in; to translate or reword a message, create a translation string in **Settings → Translation Strings** with the key `impersonation.<reason>` (for example `impersonation.read_only`). Translation strings apply within 30 seconds.

## API reference

Both routes are mounted at the root of the Directus API and exchange JSON.

### `POST /impersonation/start`

Requires an administrator access token (`Authorization: Bearer …`).

```json
{ "user_id": "3e9514b5-8083-4e7b-8504-2f1e893ab6e6", "reason": "Support ticket 1234", "otp": "123456" }
```

| Field | Description |
| --- | --- |
| `user_id` | UUID of an active, non-administrator user |
| `reason` | 5 to 500 characters, stored in the audit log |
| `otp` | Current one-time password of the calling administrator |

```json
{
  "data": {
    "access_token": "…",
    "expires": 900000,
    "log_id": "0b7f0c6e-5a3d-4f6a-9a3e-0f7d7d7a1c11",
    "user": { "id": "3e9514b5-8083-4e7b-8504-2f1e893ab6e6", "first_name": "Jane", "last_name": "Doe" }
  }
}
```

`expires` is in milliseconds, like the Directus login response.

### `POST /impersonation/stop`

Called with the **impersonation token** itself (the only write it is allowed to make). Stamps `ended_at` on the audit row.

```json
{ "data": { "ok": true } }
```

## Using the token from a web app

- Keep the administrator's own session aside (for example in an `httpOnly` cookie) and put the impersonation token where the app expects the access token. Remove the refresh token while impersonating.
- Detect a session by decoding the token payload: `imp` is the administrator's id.
- To leave, call `/impersonation/stop`, then restore the administrator's session.
- The extension refuses the writes whatever the client does, but also refuse them in the app's own server routes if some of them write with a service key.

## Development

```bash
npm install
npm test             # unit tests
npm run build        # bundle to dist/
npm run dev          # rebuild on change
```

End-to-end tests run against a real Directus instance that has the built extension installed (CI does this for Directus 10, 11 and 12). With a server running:

```bash
DIRECTUS_URL=http://localhost:8055 ADMIN_EMAIL=admin@example.com ADMIN_PASSWORD=… IMPERSONATION_TTL=10m npm run test:e2e
```

Run them on a throw-away database: the tests enable 2FA on the administrator and create users and roles.

Commits follow [Conventional Commits](https://www.conventionalcommits.org) (checked by a `commit-msg` hook and in CI); the changelog is generated with git-cliff.

## Releasing

```bash
npm version minor    # bumps package.json, updates CHANGELOG.md, tags vX.Y.Z
git push --follow-tags
```

Pushing the tag runs the tests, builds the extension, attaches `directus-extension-impersonation-vX.Y.Z.zip` to a GitHub release and publishes the package to npm (with provenance, through npm trusted publishing).
