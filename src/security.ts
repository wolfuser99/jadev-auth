const encoder = new TextEncoder()
const decoder = new TextDecoder()

export const now = () => Math.floor(Date.now() / 1000)
export const randomToken = (bytes = 32) => {
  const data = new Uint8Array(bytes)
  crypto.getRandomValues(data)
  return base64url(data)
}
export const base64url = (data: ArrayBuffer | Uint8Array) => {
  const bytes = data instanceof Uint8Array ? data : new Uint8Array(data)
  let binary = ''
  for (const byte of bytes) binary += String.fromCharCode(byte)
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '')
}
export const fromBase64url = (value: string) => {
  const normalized = value.replaceAll('-', '+').replaceAll('_', '/')
  const binary = atob(normalized + '='.repeat((4 - normalized.length % 4) % 4))
  return Uint8Array.from(binary, (char) => char.charCodeAt(0))
}

export async function sha256(value: string): Promise<string> {
  return base64url(await crypto.subtle.digest('SHA-256', encoder.encode(value)))
}

export async function hashPassword(password: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(16))
  const key = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveBits'])
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 210_000, hash: 'SHA-256' }, key, 256)
  return `pbkdf2_sha256$210000$${base64url(salt)}$${base64url(bits)}`
}

export async function verifyPassword(password: string, encoded: string | null): Promise<boolean> {
  if (!encoded) { await hashPassword(password); return false }
  const [scheme, iterations, salt, expected] = encoded.split('$')
  if (scheme !== 'pbkdf2_sha256' || !iterations || !salt || !expected) return false
  const key = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveBits'])
  const actual = new Uint8Array(await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: fromBase64url(salt), iterations: Number(iterations), hash: 'SHA-256' }, key, 256))
  const wanted = fromBase64url(expected)
  let difference = actual.length ^ wanted.length
  const length = Math.max(actual.length, wanted.length)
  for (let index = 0; index < length; index++) difference |= (actual[index] || 0) ^ (wanted[index] || 0)
  return difference === 0
}

export const json = (value: unknown) => JSON.stringify(value)
export const utf8 = (value: string) => encoder.encode(value)
export const text = (value: ArrayBuffer) => decoder.decode(value)
