import * as crypto from 'node:crypto'

export type IdentityClientOptions = {
  endpoint: string
  clientId: string
  certificate: string
}

export type AuthTokens = {
  access_token: string
  refresh_token?: string
  device_secret?: string
}

export type IdentityUser = {
  name?: string
  displayName?: string
  preferred_username?: string
  email?: string
  avatar?: string
}

function decodeBase64Url(value: string): Buffer { return Buffer.from(value, 'base64url') }

export class IdentityClient {
  constructor(private readonly options: IdentityClientOptions) {}

  /**
   * 公共原生客户端授权码换取。单次 PKCE verifier 证明最初授权请求的持有权，
   * 不依赖随桌面应用分发的共享 secret。
   */
  public async getAuthToken(code: string, codeVerifier: string): Promise<AuthTokens> {
    if (!codeVerifier) throw new Error('登录验证信息已失效，请返回应用后重新登录。')
    const response = await fetch(new URL('/api/login/oauth/access_token', this.options.endpoint), {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ client_id: this.options.clientId, grant_type: 'authorization_code', code, code_verifier: codeVerifier }),
    })
    const payload = await response.json() as AuthTokens & { error?: string; error_description?: string; msg?: string }
    if (!response.ok || !payload.access_token) throw new Error(payload.error_description || payload.msg || payload.error || '身份服务未能完成登录。')
    return payload
  }

  public parseAndVerifyAccessToken(token: string): IdentityUser {
    const parts = token.split('.')
    if (parts.length !== 3) throw new Error('身份服务返回的登录凭据无效。')
    const [headerPart, payloadPart, signaturePart] = parts
    const header = JSON.parse(decodeBase64Url(headerPart).toString('utf8')) as { alg?: string }
    if (header.alg !== 'RS256') throw new Error('身份服务返回的登录凭据算法不受支持。')
    const verifier = crypto.createVerify('RSA-SHA256')
    verifier.update(`${headerPart}.${payloadPart}`)
    verifier.end()
    if (!verifier.verify(this.options.certificate, decodeBase64Url(signaturePart))) throw new Error('身份服务返回的登录凭据未通过验证。')
    return JSON.parse(decodeBase64Url(payloadPart).toString('utf8')) as IdentityUser
  }

  /** 使用经验证的访问令牌读取 OIDC 用户资料；仅用于补齐 token 未承载的展示性邮箱字段。 */
  public async getUserInfo(accessToken: string): Promise<IdentityUser> {
    const response = await fetch(new URL('/api/userinfo', this.options.endpoint), { headers: { Authorization: `Bearer ${accessToken}` } })
    if (!response.ok) throw new Error('身份服务未返回账户资料。')
    const payload = await response.json() as IdentityUser & { data?: IdentityUser }
    return payload.data ?? payload
  }
}
