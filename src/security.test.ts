import { describe, expect, it } from 'vitest'
import { hashPassword, verifyPassword, randomToken, sha256 } from './security'

describe('security primitives', () => {
  it('hashes and verifies passwords without storing plaintext', async () => {
    const password = 'correct horse battery staple'
    const encoded = await hashPassword(password)
    expect(encoded).toMatch(/^pbkdf2_sha256\$210000\$/)
    expect(encoded).not.toContain(password)
    expect(await verifyPassword(password, encoded)).toBe(true)
    expect(await verifyPassword('wrong password', encoded)).toBe(false)
  })

  it('creates unique tokens and deterministic token digests', async () => {
    const first = randomToken()
    const second = randomToken()
    expect(first).not.toBe(second)
    expect(await sha256(first)).toBe(await sha256(first))
  })
})
