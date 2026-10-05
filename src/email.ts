import { connect } from 'cloudflare:sockets'
import type { Env } from './types'

const encoder = new TextEncoder()
const decoder = new TextDecoder()

class SmtpConnection {
  private writer: WritableStreamDefaultWriter<Uint8Array>
  private reader: ReadableStreamDefaultReader<Uint8Array>
  private buffer = ''

  constructor(private socket: Socket) {
    this.writer = socket.writable.getWriter()
    this.reader = socket.readable.getReader()
  }

  async write(command: string) {
    await this.writer.write(encoder.encode(`${command}\r\n`))
  }

  upgradeToTls() {
    this.reader.releaseLock()
    this.writer.releaseLock()
    const socket = this.socket.startTls()
    this.socket = socket
    this.reader = socket.readable.getReader()
    this.writer = socket.writable.getWriter()
    this.buffer = ''
  }

  async response() {
    while (true) {
      const lineEnd = this.buffer.indexOf('\r\n')
      if (lineEnd >= 0) {
        const line = this.buffer.slice(0, lineEnd)
        this.buffer = this.buffer.slice(lineEnd + 2)
        if (/^\d{3} /.test(line)) {
          if (!/^[23]\d{2} /.test(line)) throw new Error(`SMTP rejected command: ${line.slice(0, 3)}`)
          return line
        }
        continue
      }
      const result = await this.reader.read()
      if (result.done) throw new Error('SMTP connection closed unexpectedly')
      this.buffer += decoder.decode(result.value, { stream: true })
    }
  }

  async close() {
    try { await this.write('QUIT'); await this.response() } catch { /* close below */ }
    this.reader.releaseLock()
    this.writer.releaseLock()
    await this.socket.close()
  }
}

const encodeBase64 = (value: string) => btoa(value)
const escapeHeader = (value: string) => value.replace(/[\r\n]/g, '')
const messageFor = (purpose: string, token: string, origin: string) => {
  const action = purpose === 'verify_email' ? 'verificar tu email' : 'restablecer tu contraseña'
  const url = `${origin}/auth/${purpose === 'verify_email' ? 'verify-email' : 'password/reset'}?token=${encodeURIComponent(token)}`
  return { subject: purpose === 'verify_email' ? 'Verifica tu email' : 'Restablece tu contraseña', text: `Usa este enlace para ${action}: ${url}\n\nSi no lo solicitaste, ignora este mensaje.` }
}

export async function sendAuthEmail(env: Env, to: string, purpose: string, token: string) {
  const port = Number(env.SMTP_PORT) || 465
  const directTls = env.SMTP_CRYPTO === 'ssl' || (env.SMTP_CRYPTO !== 'tls' && port === 465)
  const connection = new SmtpConnection(connect({ hostname: env.SMTP_HOST, port }, { secureTransport: directTls ? 'on' : 'starttls', allowHalfOpen: false }))
  const message = messageFor(purpose, token, env.APP_ORIGIN)
  try {
    await connection.response()
    await connection.write(`EHLO ${new URL(env.APP_ORIGIN).hostname}`)
    await connection.response()
    if (!directTls) {
      await connection.write('STARTTLS')
      await connection.response()
      connection.upgradeToTls()
      await connection.write(`EHLO ${new URL(env.APP_ORIGIN).hostname}`)
      await connection.response()
    }
    await connection.write('AUTH LOGIN')
    await connection.response()
    await connection.write(encodeBase64(env.SMTP_USER))
    await connection.response()
    await connection.write(encodeBase64(env.SMTP_PASSWORD))
    await connection.response()
    await connection.write(`MAIL FROM:<${escapeHeader(env.SMTP_FROM)}>`) 
    await connection.response()
    await connection.write(`RCPT TO:<${escapeHeader(to)}>`)
    await connection.response()
    await connection.write('DATA')
    await connection.response()
    const fromName = env.SMTP_FROM_NAME ? `${escapeHeader(env.SMTP_FROM_NAME)} ` : ''
    const data = `From: ${fromName}<${escapeHeader(env.SMTP_FROM)}>\r\nTo: <${escapeHeader(to)}>\r\nSubject: ${message.subject}\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n${message.text.replace(/^\./gm, '..')}\r\n.`
    await connection.write(data)
    await connection.response()
  } finally {
    await connection.close()
  }
}