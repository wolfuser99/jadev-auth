import { Hono } from 'hono'
import { getCookie, setCookie, deleteCookie } from 'hono/cookie'
import { generateAuthenticationOptions, generateRegistrationOptions, verifyAuthenticationResponse, verifyRegistrationResponse } from '@simplewebauthn/server'
import type { AppEnv, Env, User } from './types'
import { createAccessToken, createEmailToken, createRefreshToken, createSession, createUser, findRefreshToken, findRefreshTokenAny, findUser, findUserByEmail, revokeRefreshFamily, revokeRefreshToken, revokeSession, revokeUserRefreshTokens, revokeUserSessions, rotateRefreshToken, sessionUser, consumeEmailToken } from './db'
import { base64url, fromBase64url, hashPassword, now, randomToken, sha256, verifyPassword } from './security'
import { sendAuthEmail } from './email'

const app = new Hono<AppEnv>()
const SESSION_TTL = 60 * 60 * 24 * 30
const EMAIL_TTL = 60 * 60
const RESET_TTL = 60 * 15
const ACCESS_TTL = 60 * 15
const REFRESH_TTL = 60 * 60 * 24 * 30
const genericAuthMessage = 'Si los datos son válidos, recibirás instrucciones.'

const jsonError = (c: any, message: string, status = 400) => c.json({ error: message }, status)
const normalizeEmail = (value: unknown) => typeof value === 'string' && value.trim().toLowerCase().length <= 254 ? value.trim().toLowerCase() : null
const validPassword = (value: unknown) => typeof value === 'string' && value.length >= 12 && value.length <= 256
const body = async (c: any) => { try { return await c.req.json() as Record<string, unknown> } catch { return null } }

function queueEmail(c: any, to: string, purpose: string, token: string) {
  c.executionCtx.waitUntil(sendAuthEmail(c.env, to, purpose, token).catch((error: unknown) => {
    console.error(JSON.stringify({ event: 'auth_email_failed', purpose, error: error instanceof Error ? error.message : 'unknown_error' }))
  }))
}

async function rateLimit(env: Env, key: string, limit = 10, window = 60) {
  const bucket = Math.floor(Date.now() / 1000 / window)
  const storageKey = `rl:${key}:${bucket}`
  const current = Number(await env.RATE_LIMIT.get(storageKey) || '0') + 1
  await env.RATE_LIMIT.put(storageKey, String(current), { expirationTtl: window + 5 })
  return current <= limit
}
function setSession(c: any, token: string) {
  setCookie(c, c.env.SESSION_COOKIE || '__Host-session', token, { httpOnly: true, secure: true, sameSite: 'Lax', path: '/', maxAge: SESSION_TTL })
}
function bearerToken(c: any) {
  const value = c.req.header('Authorization')
  return value?.match(/^Bearer\s+(\S+)$/i)?.[1] || null
}
async function issueApiTokens(c: any, userId: string, setWebCookie = false) {
  const accessToken = randomToken(32), refreshToken = randomToken(48), familyId = crypto.randomUUID()
  await createSession(c.env.DB, userId, await sha256(accessToken), ACCESS_TTL)
  await createRefreshToken(c.env.DB, userId, familyId, await sha256(refreshToken), REFRESH_TTL)
  if (setWebCookie) setSession(c, accessToken)
  return { access_token: accessToken, refresh_token: refreshToken, token_type: 'Bearer', expires_in: ACCESS_TTL, refresh_token_expires_in: REFRESH_TTL }
}
async function requireUser(c: any, next: any) {
  const token = bearerToken(c) || getCookie(c, c.env.SESSION_COOKIE || '__Host-session')
  const user = token ? await sessionUser(c.env.DB, await sha256(token)) : null
  if (!user) return jsonError(c, 'No autenticado', 401)
  c.set('user', user)
  await next()
}
function sameOrigin(c: any) {
  const origin = c.req.header('Origin')
  return !origin || origin === c.env.APP_ORIGIN
}

app.use('*', async (c, next) => {
  c.header('Cache-Control', 'no-store')
  if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(c.req.method) && !sameOrigin(c)) return jsonError(c, 'Origen no permitido', 403)
  await next()
})
app.get('/health', (c) => c.json({ ok: true }))

app.post('/auth/register', async (c) => {
  if (!(await rateLimit(c.env, `register:${c.req.header('CF-Connecting-IP') || 'unknown'}`, 5))) return jsonError(c, 'Demasiadas solicitudes', 429)
  const data = await body(c), email = normalizeEmail(data?.email)
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || !validPassword(data?.password)) return jsonError(c, 'Email o contraseña inválidos')
  const existing = await findUserByEmail(c.env.DB, email)
  if (!existing) {
    const user = await createUser(c.env.DB, email, await hashPassword(data!.password as string))
    const token = randomToken()
    await createEmailToken(c.env.DB, user.id, 'verify_email', token, EMAIL_TTL)
    queueEmail(c, email, 'verify_email', token)
  }
  return c.json({ message: genericAuthMessage }, 202)
})

app.post('/auth/login', async (c) => {
  if (!(await rateLimit(c.env, `login:${c.req.header('CF-Connecting-IP') || 'unknown'}`, 10))) return jsonError(c, 'Demasiadas solicitudes', 429)
  const data = await body(c), email = normalizeEmail(data?.email), user = email ? await findUserByEmail(c.env.DB, email) : null
  const valid = await verifyPassword(typeof data?.password === 'string' ? data.password : '', user?.password_hash || null)
  if (!user || !valid) return jsonError(c, 'Credenciales inválidas', 401)
  const webToken = randomToken()
  await createSession(c.env.DB, user.id, await sha256(webToken), SESSION_TTL)
  setSession(c, webToken)
  return c.json({ user: { id: user.id, email: user.email, emailVerified: Boolean(user.email_verified_at) }, ...(await issueApiTokens(c, user.id)) })
})

app.post('/auth/logout', async (c) => {
  const token = bearerToken(c) || getCookie(c, c.env.SESSION_COOKIE || '__Host-session')
  const data = await body(c)
  if (token) await revokeSession(c.env.DB, await sha256(token))
  if (typeof data?.refresh_token === 'string') await revokeRefreshToken(c.env.DB, await sha256(data.refresh_token))
  deleteCookie(c, c.env.SESSION_COOKIE || '__Host-session', { path: '/' })
  return c.body(null, 204)
})
app.post('/auth/sessions/revoke-all', requireUser, async (c) => { await revokeUserSessions(c.env.DB, c.get('user').id); await revokeUserRefreshTokens(c.env.DB, c.get('user').id); deleteCookie(c, c.env.SESSION_COOKIE || '__Host-session', { path: '/' }); return c.body(null, 204) })

app.post('/auth/refresh', async (c) => {
  if (!(await rateLimit(c.env, `refresh:${c.req.header('CF-Connecting-IP') || 'unknown'}`, 20))) return jsonError(c, 'Demasiadas solicitudes', 429)
  const data = await body(c), refreshToken = typeof data?.refresh_token === 'string' ? data.refresh_token : ''
  const current = refreshToken ? await findRefreshToken(c.env.DB, await sha256(refreshToken)) : null
  if (!current) {
    const reused = refreshToken ? await findRefreshTokenAny(c.env.DB, await sha256(refreshToken)) : null
    if (reused?.revoked_at) await revokeRefreshFamily(c.env.DB, reused.family_id)
    return jsonError(c, 'Refresh token inválido o expirado', 401)
  }
  const nextAccess = randomToken(32), nextRefresh = randomToken(48)
  if (!await rotateRefreshToken(c.env.DB, await sha256(refreshToken), await sha256(nextRefresh), current.user_id, current.family_id, REFRESH_TTL)) return jsonError(c, 'Refresh token inválido o expirado', 401)
  await createSession(c.env.DB, current.user_id, await sha256(nextAccess), ACCESS_TTL)
  return c.json({ access_token: nextAccess, refresh_token: nextRefresh, token_type: 'Bearer', expires_in: ACCESS_TTL, refresh_token_expires_in: REFRESH_TTL })
})

app.post('/auth/verify-email', async (c) => {
  const data = await body(c), token = typeof data?.token === 'string' ? data.token : ''
  const row = await consumeEmailToken(c.env.DB, token, 'verify_email')
  if (!row) return jsonError(c, 'Token inválido o expirado', 400)
  await c.env.DB.prepare('UPDATE users SET email_verified_at=?, updated_at=? WHERE id=?').bind(now(), now(), row.user_id).run()
  return c.json({ message: 'Email verificado' })
})
app.post('/auth/resend-verification', async (c) => {
  const data = await body(c), email = normalizeEmail(data?.email), user = email ? await findUserByEmail(c.env.DB, email) : null
  if (user && !user.email_verified_at) { const token = randomToken(); await createEmailToken(c.env.DB, user.id, 'verify_email', token, EMAIL_TTL); queueEmail(c, email!, 'verify_email', token) }
  return c.json({ message: genericAuthMessage }, 202)
})

app.post('/auth/password/request-reset', async (c) => {
  const data = await body(c), email = normalizeEmail(data?.email), user = email ? await findUserByEmail(c.env.DB, email) : null
  if (user) { const token = randomToken(); await createEmailToken(c.env.DB, user.id, 'reset_password', token, RESET_TTL); queueEmail(c, email!, 'reset_password', token) }
  return c.json({ message: genericAuthMessage }, 202)
})
app.post('/auth/password/reset', async (c) => {
  const data = await body(c), token = typeof data?.token === 'string' ? data.token : ''
  if (!validPassword(data?.password)) return jsonError(c, 'Contraseña inválida')
  const row = await consumeEmailToken(c.env.DB, token, 'reset_password')
  if (!row) return jsonError(c, 'Token inválido o expirado', 400)
  await c.env.DB.prepare('UPDATE users SET password_hash=?, updated_at=? WHERE id=?').bind(await hashPassword(data!.password as string), now(), row.user_id).run()
  await revokeUserSessions(c.env.DB, row.user_id)
  await revokeUserRefreshTokens(c.env.DB, row.user_id)
  return c.json({ message: 'Contraseña actualizada' })
})
app.post('/auth/password/change', requireUser, async (c) => {
  const data = await body(c), user = c.get('user')
  if (!validPassword(data?.password) || !(await verifyPassword(typeof data?.currentPassword === 'string' ? data.currentPassword : '', user.password_hash))) return jsonError(c, 'Datos inválidos', 400)
  await c.env.DB.prepare('UPDATE users SET password_hash=?, updated_at=? WHERE id=?').bind(await hashPassword(data!.password as string), now(), user.id).run()
  await revokeUserSessions(c.env.DB, user.id)
  await revokeUserRefreshTokens(c.env.DB, user.id)
  return c.json({ message: 'Contraseña actualizada' })
})

app.get('/auth/me', requireUser, (c) => { const user = c.get('user'); return c.json({ id: user.id, email: user.email, emailVerified: Boolean(user.email_verified_at) }) })

app.get('/auth/github/start', async (c) => {
  const sessionToken = getCookie(c, c.env.SESSION_COOKIE || '__Host-session')
  const user = sessionToken ? await sessionUser(c.env.DB, await sha256(sessionToken)) : null
  const state = randomToken(), verifier = randomToken(48)
  await c.env.DB.prepare('INSERT INTO oauth_states (state_hash,user_id,code_verifier,expires_at,created_at) VALUES (?,?,?,?,?)').bind(await sha256(state), user?.id || null, verifier, now() + 600, now()).run()
  const challenge = base64url(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier)))
  const url = new URL('https://github.com/login/oauth/authorize')
  url.search = new URLSearchParams({ client_id: c.env.GITHUB_CLIENT_ID, redirect_uri: c.env.GITHUB_REDIRECT_URI, scope: 'read:user user:email', state, code_challenge: challenge, code_challenge_method: 'S256' }).toString()
  return c.json({ url: url.toString() })
})
app.get('/auth/github/callback', async (c) => {
  const state = c.req.query('state') || '', code = c.req.query('code') || ''
  const stateRow = await c.env.DB.prepare('SELECT * FROM oauth_states WHERE state_hash=? AND expires_at>?').bind(await sha256(state), now()).first<{ user_id: string | null; code_verifier: string; state_hash: string }>()
  if (!stateRow || !code) return jsonError(c, 'Callback OAuth inválido', 400)
  await c.env.DB.prepare('DELETE FROM oauth_states WHERE state_hash=?').bind(stateRow.state_hash).run()
  const exchange = await fetch('https://github.com/login/oauth/access_token', { method: 'POST', headers: { accept: 'application/json', 'content-type': 'application/json' }, body: JSON.stringify({ client_id: c.env.GITHUB_CLIENT_ID, client_secret: c.env.GITHUB_CLIENT_SECRET, code, redirect_uri: c.env.GITHUB_REDIRECT_URI, code_verifier: stateRow.code_verifier }) })
  const access = await exchange.json() as { access_token?: string }
  if (!access.access_token) return jsonError(c, 'OAuth rechazado', 401)
  const profile = await fetch('https://api.github.com/user', { headers: { authorization: `Bearer ${access.access_token}`, 'user-agent': 'jadev-auth' } }).then((response) => response.json()) as { id: number; email?: string }
  const email = profile.email ? normalizeEmail(profile.email) : null
  if (!email) return jsonError(c, 'GitHub no proporcionó email', 400)
  let user = stateRow.user_id ? await findUser(c.env.DB, stateRow.user_id) : await findUserByEmail(c.env.DB, email)
  if (stateRow.user_id && user && await c.env.DB.prepare('SELECT 1 FROM oauth_accounts WHERE provider=? AND provider_account_id=?').bind('github', String(profile.id)).first()) return c.redirect(`${c.env.APP_ORIGIN}/account`)
  if (!user) user = await createUser(c.env.DB, email, null)
  await c.env.DB.prepare('INSERT OR IGNORE INTO oauth_accounts (provider,provider_account_id,user_id,created_at) VALUES (?,?,?,?)').bind('github', String(profile.id), user.id, now()).run()
  const token = randomToken(); await createSession(c.env.DB, user.id, await sha256(token), SESSION_TTL); setSession(c, token)
  return c.redirect(`${c.env.APP_ORIGIN}/account`)
})

app.post('/auth/token', requireUser, async (c) => {
  const data = await body(c), clientId = typeof data?.clientId === 'string' ? data.clientId : '', secret = typeof data?.clientSecret === 'string' ? data.clientSecret : ''
  const client = await c.env.DB.prepare('SELECT * FROM clients WHERE client_id=? AND revoked_at IS NULL').bind(clientId).first<{ client_id: string; client_secret_hash: string; scopes: string }>()
  if (!client || !(await verifyPassword(secret, client?.client_secret_hash || null))) return jsonError(c, 'Cliente inválido', 401)
  const requested = Array.isArray(data?.scopes) ? data!.scopes.filter((scope): scope is string => typeof scope === 'string') : client.scopes.split(' ')
  const allowed = requested.filter((scope) => client.scopes.split(' ').includes(scope))
  const token = randomToken(48); await createAccessToken(c.env, c.get('user').id, clientId, allowed, token, ACCESS_TTL)
  return c.json({ access_token: token, token_type: 'Bearer', expires_in: ACCESS_TTL, scope: allowed.join(' ') })
})
app.post('/auth/token/clients', requireUser, async (c) => {
  const data = await body(c), name = typeof data?.name === 'string' ? data.name.trim() : '', requested = Array.isArray(data?.scopes) ? data.scopes.filter((scope): scope is string => typeof scope === 'string' && /^[a-z0-9:_-]{1,64}$/.test(scope)) : []
  if (!name || name.length > 120 || requested.length === 0) return jsonError(c, 'Configuración de cliente inválida')
  const clientId = `jadev_${randomToken(18)}`, clientSecret = randomToken(32)
  await c.env.DB.prepare('INSERT INTO clients (client_id,owner_user_id,client_secret_hash,name,scopes,created_at) VALUES (?,?,?,?,?,?)').bind(clientId, c.get('user').id, await hashPassword(clientSecret), name, [...new Set(requested)].join(' '), now()).run()
  return c.json({ client_id: clientId, client_secret: clientSecret, name, scopes: [...new Set(requested)] }, 201)
})
app.post('/auth/token/introspect', async (c) => {
  const data = await body(c), token = typeof data?.token === 'string' ? data.token : ''
  const row = await c.env.DB.prepare('SELECT user_id,client_id,scopes,expires_at FROM access_tokens WHERE token_hash=? AND revoked_at IS NULL AND expires_at>?').bind(await sha256(`${c.env.TOKEN_PEPPER}:${token}`), now()).first<{ user_id: string; client_id: string; scopes: string; expires_at: number }>()
  return c.json(row ? { active: true, sub: row.user_id, client_id: row.client_id, scope: row.scopes, exp: row.expires_at } : { active: false })
})
app.post('/auth/token/revoke', async (c) => { const data = await body(c); if (typeof data?.token === 'string') await c.env.DB.prepare('UPDATE access_tokens SET revoked_at=? WHERE token_hash=?').bind(now(), await sha256(`${c.env.TOKEN_PEPPER}:${data.token}`)).run(); return c.body(null, 204) })

app.post('/auth/passkey/register/options', requireUser, async (c) => {
  const user = c.get('user'), options = await generateRegistrationOptions({ rpName: c.env.WEBAUTHN_RP_NAME, rpID: c.env.WEBAUTHN_RP_ID, userName: user.email, userID: fromBase64url(base64url(new TextEncoder().encode(user.id))), attestationType: 'none', excludeCredentials: (await c.env.DB.prepare('SELECT id FROM passkeys WHERE user_id=?').bind(user.id).all<{ id: string }>()).results.map((key) => ({ id: key.id })) })
  await c.env.RATE_LIMIT.put(`challenge:${user.id}`, JSON.stringify(options), { expirationTtl: 300 })
  return c.json(options)
})
app.post('/auth/passkey/register/verify', requireUser, async (c) => {
  const user = c.get('user'), data = await body(c), expected = await c.env.RATE_LIMIT.get(`challenge:${user.id}`, 'json') as { challenge: string } | null
  if (!expected || !data) return jsonError(c, 'Challenge inválido', 400)
  const verification = await verifyRegistrationResponse({ response: data as any, expectedChallenge: expected.challenge, expectedOrigin: c.env.WEBAUTHN_ORIGIN, expectedRPID: c.env.WEBAUTHN_RP_ID })
  if (!verification.verified || !verification.registrationInfo) return jsonError(c, 'Passkey inválida', 400)
  const info = verification.registrationInfo
  await c.env.DB.prepare('INSERT INTO passkeys (id,user_id,public_key,counter,transports,created_at) VALUES (?,?,?,?,?,?)').bind(info.credential.id, user.id, info.credential.publicKey, info.credential.counter, JSON.stringify(info.credential.transports || []), now()).run()
  await c.env.RATE_LIMIT.delete(`challenge:${user.id}`)
  return c.json({ verified: true })
})
app.post('/auth/passkey/login/options', async (c) => {
  const data = await body(c), email = normalizeEmail(data?.email), user = email ? await findUserByEmail(c.env.DB, email) : null
  const options = await generateAuthenticationOptions({ rpID: c.env.WEBAUTHN_RP_ID, userVerification: 'preferred', allowCredentials: user ? (await c.env.DB.prepare('SELECT id,transports FROM passkeys WHERE user_id=?').bind(user.id).all<{ id: string; transports: string | null }>()).results.map((key) => ({ id: key.id, transports: key.transports ? JSON.parse(key.transports) : undefined })) : [] })
  await c.env.RATE_LIMIT.put(`login-challenge:${options.challenge}`, JSON.stringify({ userId: user?.id || null, challenge: options.challenge }), { expirationTtl: 300 })
  return c.json(options)
})
app.post('/auth/passkey/login/verify', async (c) => {
  const data = await body(c), response = data?.response as Record<string, unknown> | undefined, challenge = typeof response?.response === 'object' && response.response ? (response.response as Record<string, unknown>).clientDataJSON : null
  if (!response || typeof challenge !== 'string') return jsonError(c, 'Passkey inválida', 400)
  const challengeBytes = fromBase64url(challenge)
  const clientData = JSON.parse(new TextDecoder().decode(challengeBytes)) as { challenge?: string }
  const expected = clientData.challenge ? await c.env.RATE_LIMIT.get(`login-challenge:${clientData.challenge}`, 'json') as { userId: string | null; challenge: string } | null : null
  if (!expected?.userId) return jsonError(c, 'Challenge inválido', 400)
  const credentialId = typeof response.id === 'string' ? response.id : ''
  const credential = await c.env.DB.prepare('SELECT * FROM passkeys WHERE id=? AND user_id=?').bind(credentialId, expected.userId).first<{ id: string; public_key: ArrayBuffer; counter: number; transports: string | null }>()
  if (!credential) return jsonError(c, 'Passkey inválida', 401)
  const verification = await verifyAuthenticationResponse({ response: response as any, expectedChallenge: expected.challenge, expectedOrigin: c.env.WEBAUTHN_ORIGIN, expectedRPID: c.env.WEBAUTHN_RP_ID, credential: { id: credential.id, publicKey: new Uint8Array(credential.public_key), counter: credential.counter, transports: credential.transports ? JSON.parse(credential.transports) : undefined } })
  if (!verification.verified) return jsonError(c, 'Passkey inválida', 401)
  await c.env.DB.prepare('UPDATE passkeys SET counter=?, last_used_at=? WHERE id=?').bind(verification.authenticationInfo.newCounter, now(), credential.id).run()
  await c.env.RATE_LIMIT.delete(`login-challenge:${expected.challenge}`)
  return c.json({ authenticated: true, ...(await issueApiTokens(c, expected.userId, true)) })
})
app.delete('/auth/passkey/:id', requireUser, async (c) => {
  const result = await c.env.DB.prepare('DELETE FROM passkeys WHERE id=? AND user_id=?').bind(c.req.param('id'), c.get('user').id).run()
  return result.meta.changes ? c.body(null, 204) : jsonError(c, 'Passkey no encontrada', 404)
})

app.notFound((c) => c.json({ error: 'No encontrado' }, 404))
app.onError((error, c) => {
  console.error(JSON.stringify({ event: 'request_failed', name: error.name, message: error.message }))
  return c.json({ error: 'Error interno' }, 500)
})
export default app
