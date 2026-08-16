import * as http from 'node:http'

const tokenExchangeGrant = 'urn:ietf:params:oauth:grant-type:token-exchange'
const accessTokenType = 'urn:ietf:params:oauth:token-type:access_token'
const deviceSecretType = 'urn:openid:params:token-type:device-secret'
const maximumBodySize = 16 * 1024

export type NativeSsoSession = {
  accessToken: string
  deviceSecret: string
  userName: string
  displayName: string
  avatar: string
}

export type NativeSsoAuthorizeRequest = {
  serverUrl?: string
  clientId?: string
  applicationName?: string
  organization?: string
  responseType?: string
  redirectUri?: string
  scope?: string
  state?: string
  nonce?: string
  codeChallenge?: string
  challengeMethod?: string
  resource?: string
}

type NativeSsoServiceOptions = {
  endpoint: string
  session: NativeSsoSession
  preferredPort: number
  approve: (input: {
    applicationName: string
    userName: string
    displayName: string
  }) => Promise<boolean>
}

function normalizeEndpoint(endpoint: string): string {
  return endpoint.trim().replace(/\/+$/, '')
}

function addCorsHeaders(response: http.ServerResponse, origin: string): void {
  response.setHeader('Access-Control-Allow-Origin', origin)
  response.setHeader('Vary', 'Origin')
  response.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
  response.setHeader('Access-Control-Allow-Headers', 'Content-Type')
  response.setHeader('Access-Control-Max-Age', '600')
}

function writeJson(response: http.ServerResponse, statusCode: number, body: unknown): void {
  response.statusCode = statusCode
  response.setHeader('Content-Type', 'application/json; charset=utf-8')
  response.end(JSON.stringify(body))
}

function readJson(request: http.IncomingMessage): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    let body = ''
    request.on('data', (chunk: Buffer) => {
      body += chunk.toString('utf8')
      if (Buffer.byteLength(body, 'utf8') > maximumBodySize) {
        request.destroy()
        reject(new Error('请求体过大'))
      }
    })
    request.on('end', () => {
      if (body === '') {
        resolve({})
        return
      }
      try {
        const parsed = JSON.parse(body) as unknown
        if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
          throw new Error('请求内容格式无效')
        }
        resolve(parsed as Record<string, unknown>)
      } catch (error) {
        reject(error instanceof Error ? error : new Error('请求内容格式无效'))
      }
    })
    request.on('error', reject)
  })
}

function normalizedScope(value: string | undefined): string {
  const scopes = new Set((value || 'openid profile email').split(/\s+/).filter(Boolean))
  scopes.add('device_sso')
  return [...scopes].join(' ')
}

function requestString(value: unknown): string {
  return typeof value === 'string' ? value : ''
}

export class NativeSsoService {
  private server: http.Server | null = null
  private port: number | null = null
  private inFlightRequests = new Set<string>()

  constructor(private readonly options: NativeSsoServiceOptions) {}

  public async start(): Promise<number> {
    if (this.server && this.port !== null) {
      return this.port
    }

    this.server = http.createServer((request, response) => {
      void this.handleRequest(request, response)
    })

    this.port = await this.listen(this.options.preferredPort)
    return this.port
  }

  public async stop(): Promise<void> {
    this.inFlightRequests.clear()
    if (!this.server) {
      this.port = null
      return
    }

    const server = this.server
    this.server = null
    this.port = null
    await new Promise<void>((resolve, reject) => {
      server.close((error) => (error ? reject(error) : resolve()))
    })
  }

  private async listen(preferredPort: number): Promise<number> {
    let lastError: unknown
    for (const port of [preferredPort, preferredPort + 1, preferredPort + 2, preferredPort + 3, preferredPort + 4]) {
      try {
        return await this.listenOn(port)
      } catch (error: any) {
        if (error?.code !== 'EADDRINUSE') {
          throw error
        }
        lastError = error
      }
    }
    throw lastError || new Error('Native SSO 端口不可用')
  }

  private listenOn(port: number): Promise<number> {
    if (!this.server) {
      throw new Error('Native SSO 服务尚未初始化')
    }

    return new Promise((resolve, reject) => {
      const server = this.server as http.Server
      const onError = (error: Error) => {
        server.off('listening', onListening)
        reject(error)
      }
      const onListening = () => {
        server.off('error', onError)
        const address = server.address()
        if (!address || typeof address === 'string') {
          reject(new Error('无法获取 Native SSO 本地端口'))
          return
        }
        resolve(address.port)
      }

      server.once('error', onError)
      server.once('listening', onListening)
      server.listen(port, '127.0.0.1')
    })
  }

  private async handleRequest(request: http.IncomingMessage, response: http.ServerResponse): Promise<void> {
    const allowedOrigin = new URL(normalizeEndpoint(this.options.endpoint)).origin
    const origin = typeof request.headers.origin === 'string' ? request.headers.origin : ''
    if (origin !== allowedOrigin) {
      writeJson(response, 403, { available: false, message: '该网页未获准使用此设备服务。' })
      return
    }

    addCorsHeaders(response, allowedOrigin)
    if (request.method === 'OPTIONS') {
      response.statusCode = 204
      response.end()
      return
    }

    const url = new URL(request.url || '/', 'http://127.0.0.1')
    if (request.method === 'GET' && url.pathname === '/native-sso/status') {
      this.handleStatus(url, response)
      return
    }

    if (request.method === 'POST' && url.pathname === '/native-sso/authorize') {
      await this.handleAuthorize(request, response)
      return
    }

    writeJson(response, 404, { available: false, message: '请求地址无效。' })
  }

  private handleStatus(url: URL, response: http.ServerResponse): void {
    const serverUrl = normalizeEndpoint(url.searchParams.get('serverUrl') || '')
    if (serverUrl !== normalizeEndpoint(this.options.endpoint)) {
      writeJson(response, 200, { available: false, message: '网页服务地址与当前租户不一致。' })
      return
    }
    if (!url.searchParams.get('clientId')) {
      writeJson(response, 200, { available: false, message: '网页应用信息无效。' })
      return
    }

    writeJson(response, 200, {
      available: true,
      serverUrl: normalizeEndpoint(this.options.endpoint),
      userName: this.options.session.userName,
      displayName: this.options.session.displayName,
      avatar: this.options.session.avatar,
    })
  }

  private async handleAuthorize(request: http.IncomingMessage, response: http.ServerResponse): Promise<void> {
    try {
      const raw = await readJson(request)
      const input: NativeSsoAuthorizeRequest = {
        serverUrl: requestString(raw.serverUrl),
        clientId: requestString(raw.clientId),
        applicationName: requestString(raw.applicationName),
        organization: requestString(raw.organization),
        responseType: requestString(raw.responseType),
        redirectUri: requestString(raw.redirectUri),
        scope: requestString(raw.scope),
        state: requestString(raw.state),
        nonce: requestString(raw.nonce),
        codeChallenge: requestString(raw.codeChallenge),
        challengeMethod: requestString(raw.challengeMethod),
        resource: requestString(raw.resource),
      }

      if (normalizeEndpoint(input.serverUrl || '') !== normalizeEndpoint(this.options.endpoint)) {
        writeJson(response, 400, { status: 'denied', message: '网页服务地址与当前租户不一致。' })
        return
      }
      if (!input.clientId) {
        writeJson(response, 400, { status: 'denied', message: '网页应用信息无效。' })
        return
      }

      // 部分默认网页应用不会发送 state 和 redirectUri；这类请求不能使用固定字段去重，
      // 否则第二次登录会被误判为旧请求。只有带有至少一个有效标识时才进行并发保护。
      const hasRequestIdentity = Boolean(input.state || input.redirectUri)
      const requestKey = hasRequestIdentity ? JSON.stringify({
        clientId: input.clientId,
        redirectUri: input.redirectUri,
        state: input.state,
        codeChallenge: input.codeChallenge,
      }) : null
      if (requestKey && this.inFlightRequests.has(requestKey)) {
        writeJson(response, 409, { status: 'denied', message: '相同的登录请求正在处理中，请稍候。' })
        return
      }
      if (requestKey) this.inFlightRequests.add(requestKey)

      try {
        const approved = await this.options.approve({
          applicationName: input.applicationName || input.clientId,
          userName: this.options.session.userName,
          displayName: this.options.session.displayName,
        })
        if (!approved) {
          writeJson(response, 200, { status: 'denied', message: '用户拒绝了 Native SSO 登录请求' })
          return
        }

        const exchanged = await this.exchangeToken(input)
        writeJson(response, 200, {
          status: 'approved',
          accessToken: exchanged.access_token,
          token: exchanged,
        })
      } finally {
        // 只防止同一请求的并发重复处理；一次授权完成后，下一次网页登录必须能够再次请求。
        if (requestKey) this.inFlightRequests.delete(requestKey)
      }
    } catch (error) {
      writeJson(response, 500, {
        status: 'denied',
        message: error instanceof Error ? error.message : 'Native SSO 授权失败',
      })
    }
  }

  private async exchangeToken(input: NativeSsoAuthorizeRequest): Promise<{ access_token: string }> {
    // 服务端通过查询参数读取这些令牌交换字段。
    // Keeping the full Native SSO token-exchange context in the query string
    // ensures the minted token belongs to the web page's target application,
    // rather than the desktop companion application.
    const tokenUrl = new URL('/api/login/oauth/access_token', normalizeEndpoint(this.options.endpoint))
    tokenUrl.search = new URLSearchParams({
      client_id: input.clientId || '',
      grant_type: tokenExchangeGrant,
      subject_token: this.options.session.accessToken,
      subject_token_type: accessTokenType,
      actor_token: this.options.session.deviceSecret,
      actor_token_type: deviceSecretType,
      scope: normalizedScope(input.scope),
      ...(input.resource ? { resource: input.resource } : {}),
    }).toString()

    const response = await fetch(tokenUrl, {
      method: 'POST',
    })
    const payload = (await response.json()) as { access_token?: string; error?: string; error_description?: string; msg?: string }
    if (!response.ok || !payload.access_token) {
      const message = payload.error_description || payload.msg || payload.error || '身份服务拒绝本次设备登录请求。'
      if (message.includes('grant_type: urn:ietf:params:oauth:grant-type:token-exchange is not supported')) {
        throw new Error('您尝试登录的网页应用尚未启用设备登录授权，请联系该应用管理员。')
      }
      if (/client_secret.*cross organizations|across organizations/i.test(message)) {
        throw new Error('您尝试登录的应用不属于当前组织，请使用其它账号。')
      }
      throw new Error('身份服务暂时无法完成本次登录，请稍后重试。')
    }
    return { access_token: payload.access_token }
  }
}
