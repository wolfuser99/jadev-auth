export interface Env {
  DB: D1Database
  RATE_LIMIT: KVNamespace
  APP_ORIGIN: string
  SESSION_COOKIE?: string
  GITHUB_CLIENT_ID: string
  GITHUB_CLIENT_SECRET: string
  GITHUB_REDIRECT_URI: string
  WEBAUTHN_RP_ID: string
  WEBAUTHN_RP_NAME: string
  WEBAUTHN_ORIGIN: string
  TOKEN_PEPPER: string
  SMTP_HOST: string
  SMTP_PORT: string
  SMTP_USER: string
  SMTP_PASSWORD: string
  SMTP_CRYPTO?: 'tls' | 'ssl'
  SMTP_FROM: string
  SMTP_FROM_NAME?: string
}

export type AppEnv = { Bindings: Env; Variables: { user: User } }

export interface User {
  id: string
  email: string
  password_hash: string | null
  email_verified_at: number | null
  created_at: number
  updated_at: number
}

export type TokenPurpose = 'verify_email' | 'reset_password'
