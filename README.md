# Jadev Auth

API de autenticación para Cloudflare Workers con Hono, D1, KV y Web Crypto.

## Arquitectura

- `src/app.ts`: rutas HTTP, controles de origen, cookies y rate limiting.
- `src/security.ts`: PBKDF2-SHA-256, tokens aleatorios y hashes SHA-256.
- `src/db.ts`: acceso D1 acotado a operaciones de autenticación.
- `migrations/0001_auth.sql`: usuarios, sesiones, tokens, OAuth, passkeys y clientes.
- D1 es la fuente de verdad. KV se usa para buckets de rate limit y challenges WebAuthn.
- Los secretos viven en Cloudflare Secrets; nunca se guardan en el repositorio.

## Configuración local

Requisitos: Node.js 20+, pnpm y Wrangler.

```sh
pnpm install
cp .dev.vars.example .dev.vars
pnpm exec wrangler d1 create jadev-auth
pnpm exec wrangler kv namespace create RATE_LIMIT
```

Sustituye los identificadores en `wrangler.jsonc`. Para una base local:

```sh
pnpm exec wrangler d1 migrations apply DB --local
pnpm dev
```

Configura `TOKEN_PEPPER`, credenciales GitHub y las variables SMTP de
`.dev.vars.example`. El Worker usa `cloudflare:sockets` con TLS directo, por
lo que el proveedor debe ofrecer SMTP sobre SSL, normalmente en el puerto
`465`; los puertos `587` y `2525` usan `STARTTLS` (`SMTP_CRYPTO=tls`). El token nunca se devuelve
por las rutas HTTP. El envío se ejecuta con `waitUntil` para que un fallo
temporal del proveedor no revele detalles SMTP ni convierta el registro en un
error de autenticación.

## Secrets y despliegue

```sh
pnpm exec wrangler secret put GITHUB_CLIENT_ID
pnpm exec wrangler secret put GITHUB_CLIENT_SECRET
pnpm exec wrangler secret put TOKEN_PEPPER
pnpm exec wrangler secret put SMTP_HOST
pnpm exec wrangler secret put SMTP_PORT
pnpm exec wrangler secret put SMTP_USER
pnpm exec wrangler secret put SMTP_PASSWORD
pnpm exec wrangler secret put SMTP_FROM
pnpm exec wrangler secret put SMTP_FROM_NAME
pnpm exec wrangler d1 migrations apply DB --remote
pnpm deploy
```

En producción cambia `APP_ORIGIN`, `GITHUB_REDIRECT_URI` y `WEBAUTHN_ORIGIN`
por HTTPS. `WEBAUTHN_RP_ID` debe ser el dominio efectivo, sin protocolo.

## API

Todas las respuestas de error son JSON. Las sesiones usan cookie `HttpOnly`,
`Secure`, `SameSite=Lax` y expiración de 30 días. Las mutaciones rechazan un
`Origin` distinto de `APP_ORIGIN`.

```sh
# Registro: responde igual aunque el email ya exista
curl -i -X POST "$API/auth/register" -H 'content-type: application/json' \
	-d '{"email":"ana@example.com","password":"una contraseña de 12+ caracteres"}'

# Login y cookie de sesión
curl -i -c cookies.txt -X POST "$API/auth/login" -H 'content-type: application/json' \
	-d '{"email":"ana@example.com","password":"una contraseña de 12+ caracteres"}'

curl -b cookies.txt "$API/auth/me"
curl -b cookies.txt -X POST "$API/auth/logout"
```

### React Native / REST

El login también devuelve credenciales para clientes móviles. Guarda el
`refresh_token` en almacenamiento seguro del dispositivo (Keychain/Keystore),
no en AsyncStorage. Envía el access token como Bearer y rótalo al recibir un
`401` o cuando expire:

```sh
curl -s -X POST "$API/auth/login" -H 'content-type: application/json' \
	-d '{"email":"ana@example.com","password":"una contraseña de 12+ caracteres"}'

curl -H "Authorization: Bearer $ACCESS_TOKEN" "$API/auth/me"

curl -s -X POST "$API/auth/refresh" -H 'content-type: application/json' \
	-d "{\"refresh_token\":\"$REFRESH_TOKEN\"}"

curl -X POST "$API/auth/logout" -H 'content-type: application/json' \
	-d "{\"refresh_token\":\"$REFRESH_TOKEN\"}"
```

Los access tokens duran 15 minutos. Los refresh tokens duran 30 días, se
almacenan únicamente como hash en D1 y son rotatorios: después de un refresh,
el token anterior deja de ser válido. Si se detecta reutilización de un refresh
revocado, el cliente debe iniciar sesión de nuevo.

Rutas disponibles:

| Ruta | Propósito |
| --- | --- |
| `POST /auth/register` | Crear usuario y enviar verificación |
| `POST /auth/login` / `POST /auth/logout` | Sesión web |
| `POST /auth/refresh` | Rotar refresh token y obtener access token |
| `POST /auth/verify-email` | Consumir token de verificación |
| `POST /auth/resend-verification` | Reenviar sin enumerar usuarios |
| `POST /auth/password/request-reset` | Solicitar recuperación |
| `POST /auth/password/reset` | Cambiar con token de recuperación |
| `POST /auth/password/change` | Cambiar autenticado |
| `POST /auth/sessions/revoke-all` | Rotar/revocar sesiones |
| `GET /auth/github/start` / `GET /auth/github/callback` | OAuth GitHub + vinculación |
| `POST /auth/passkey/register/options` | Opciones de alta WebAuthn |
| `POST /auth/passkey/register/verify` | Verificar y guardar passkey |
| `POST /auth/passkey/login/options` | Challenge de login WebAuthn |
| `POST /auth/passkey/login/verify` | Verificar passkey y crear sesión |
| `DELETE /auth/passkey/:id` | Revocar una passkey propia |
| `POST /auth/token/clients` | Registrar servicio externo |
| `POST /auth/token` | Emitir token con scopes |
| `POST /auth/token/introspect` | Validar sin exponer datos sensibles |
| `POST /auth/token/revoke` | Revocar token |

El secreto de un cliente se muestra solo al crearlo. Los tokens externos se
almacenan como `SHA-256(pepper + token)`, expiran en una hora y la introspección
solo devuelve `active`, sujeto, cliente, scopes y expiración.

## Tests

```sh
pnpm test
pnpm exec tsc --noEmit
```

La suite unitaria cubre hash PBKDF2, verificación positiva/negativa y tokens.
Los flujos D1/WebAuthn deben probarse además con `wrangler dev` y una base local
antes de desplegar; el proveedor de email debe probarse con un endpoint de
staging.
```txt
npm install
npm run dev
```

```txt
npm run deploy
```

[For generating/synchronizing types based on your Worker configuration run](https://developers.cloudflare.com/workers/wrangler/commands/#types):

```txt
npm run cf-typegen
```

Pass the `CloudflareBindings` as generics when instantiating `Hono`:

```ts
// src/index.ts
const app = new Hono<{ Bindings: CloudflareBindings }>()
```
