import type { Env, User, TokenPurpose } from './types'
import { now, sha256 } from './security'

export async function findUserByEmail(db: D1Database, email: string) {
  return db.prepare('SELECT * FROM users WHERE email = ?').bind(email).first<User>()
}
export async function findUser(db: D1Database, id: string) {
  return db.prepare('SELECT * FROM users WHERE id = ?').bind(id).first<User>()
}
export async function createUser(db: D1Database, email: string, passwordHash: string | null) {
  const id = crypto.randomUUID(), timestamp = now()
  await db.prepare('INSERT INTO users (id,email,password_hash,created_at,updated_at) VALUES (?,?,?,?,?)').bind(id, email, passwordHash, timestamp, timestamp).run()
  return { id, email, password_hash: passwordHash, email_verified_at: null, created_at: timestamp, updated_at: timestamp } satisfies User
}
export async function createEmailToken(db: D1Database, userId: string, purpose: TokenPurpose, token: string, ttl: number) {
  await db.prepare('DELETE FROM email_tokens WHERE user_id = ? AND purpose = ?').bind(userId, purpose).run()
  await db.prepare('INSERT INTO email_tokens (token_hash,user_id,purpose,expires_at,created_at) VALUES (?,?,?,?,?)').bind(await sha256(token), userId, purpose, now() + ttl, now()).run()
}
export async function consumeEmailToken(db: D1Database, token: string, purpose: TokenPurpose) {
  const row = await db.prepare('SELECT * FROM email_tokens WHERE token_hash = ? AND purpose = ? AND consumed_at IS NULL AND expires_at > ?').bind(await sha256(token), purpose, now()).first<{ user_id: string; token_hash: string }>()
  if (row) await db.prepare('UPDATE email_tokens SET consumed_at = ? WHERE token_hash = ?').bind(now(), row.token_hash).run()
  return row
}
export async function createSession(db: D1Database, userId: string, tokenHash: string, ttl: number) {
  await db.prepare('INSERT INTO sessions (id_hash,user_id,expires_at,created_at,last_seen_at) VALUES (?,?,?,?,?)').bind(tokenHash, userId, now() + ttl, now(), now()).run()
}
export async function sessionUser(db: D1Database, tokenHash: string) {
  return db.prepare('SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.id_hash=? AND s.revoked_at IS NULL AND s.expires_at>?').bind(tokenHash, now()).first<User>()
}
export async function revokeSession(db: D1Database, tokenHash: string) { await db.prepare('UPDATE sessions SET revoked_at = ? WHERE id_hash = ?').bind(now(), tokenHash).run() }
export async function revokeUserSessions(db: D1Database, userId: string) { await db.prepare('UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL').bind(now(), userId).run() }
export async function createRefreshToken(db: D1Database, userId: string, familyId: string, tokenHash: string, ttl: number) {
  await db.prepare('INSERT INTO refresh_tokens (token_hash,user_id,family_id,expires_at,created_at) VALUES (?,?,?,?,?)').bind(tokenHash, userId, familyId, now() + ttl, now()).run()
}
export async function findRefreshToken(db: D1Database, tokenHash: string) {
  return db.prepare('SELECT r.*, u.email, u.password_hash, u.email_verified_at, u.created_at AS user_created_at, u.updated_at AS user_updated_at FROM refresh_tokens r JOIN users u ON u.id=r.user_id WHERE r.token_hash=? AND r.revoked_at IS NULL AND r.expires_at>?').bind(tokenHash, now()).first<{ token_hash: string; user_id: string; family_id: string; expires_at: number }>()
}
export async function findRefreshTokenAny(db: D1Database, tokenHash: string) {
  return db.prepare('SELECT token_hash,user_id,family_id,revoked_at,expires_at FROM refresh_tokens WHERE token_hash=?').bind(tokenHash).first<{ token_hash: string; user_id: string; family_id: string; revoked_at: number | null; expires_at: number }>()
}
export async function rotateRefreshToken(db: D1Database, oldHash: string, newHash: string, userId: string, familyId: string, ttl: number) {
  const revoked = await db.prepare('UPDATE refresh_tokens SET revoked_at=?, replaced_by_hash=?, last_used_at=? WHERE token_hash=? AND user_id=? AND revoked_at IS NULL AND expires_at>?').bind(now(), newHash, now(), oldHash, userId, now()).run()
  if (!revoked.meta.changes) return false
  await createRefreshToken(db, userId, familyId, newHash, ttl)
  return true
}
export async function revokeRefreshToken(db: D1Database, tokenHash: string) { await db.prepare('UPDATE refresh_tokens SET revoked_at=?, last_used_at=? WHERE token_hash=? AND revoked_at IS NULL').bind(now(), now(), tokenHash).run() }
export async function revokeRefreshFamily(db: D1Database, familyId: string) { await db.prepare('UPDATE refresh_tokens SET revoked_at=? WHERE family_id=? AND revoked_at IS NULL').bind(now(), familyId).run() }
export async function revokeUserRefreshTokens(db: D1Database, userId: string) { await db.prepare('UPDATE refresh_tokens SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL').bind(now(), userId).run() }
export async function createAccessToken(env: Env, userId: string, clientId: string, scopes: string[], token: string, ttl: number) {
  await env.DB.prepare('INSERT INTO access_tokens (token_hash,user_id,client_id,scopes,expires_at,created_at) VALUES (?,?,?,?,?,?)').bind(await sha256(`${env.TOKEN_PEPPER}:${token}`), userId, clientId, scopes.join(' '), now() + ttl, now()).run()
}
