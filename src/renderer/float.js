(() => {
  const personalDomains = new Set([
    '163.com', '126.com', 'qq.com', 'yeah.net', 'gmail.com', 'googlemail.com', 'outlook.com',
    'hotmail.com', 'live.com', 'icloud.com', 'foxmail.com', 'sina.com', 'sohu.com', 'aliyun.com', '189.cn', '139.com',
  ])
  const byId = (id) => document.getElementById(id)
  const elements = {
    risk: byId('float-risk'), user: byId('float-user'), tenant: byId('float-tenant'), domain: byId('float-domain'),
    ip: byId('float-ip'), security: byId('float-security'), login: byId('float-login'), refresh: byId('float-refresh'),
  }
  let latestStatus = null

  function domainLabel(userName) {
    const domain = String(userName || '').split('@')[1]?.trim().toLowerCase() || ''
    if (!domain) return '未获取'
    if (personalDomains.has(domain)) return '个人用户'
    if (domain.includes('devhjz')) return 'DevHjz'
    return domain
  }

  function riskCopy(report) {
    if (!report) return { text: '检查中', className: 'risk-neutral', detail: '正在读取本机安全状态。' }
    if (!report.platformSupported) return { text: '暂不支持', className: 'risk-neutral', detail: '设备安全态势仅在 Windows 设备上提供。' }
    if (report.risk === 'pass') return { text: '通过检测', className: 'risk-pass', detail: '设备登录凭据、杀毒软件、病毒库和防火墙均通过检测。' }
    if (report.risk === 'danger') return { text: '高危风险', className: 'risk-danger', detail: `发现 ${report.issueCount} 项明确的安全问题。` }
    if (report.issueCount > 0) return { text: '存在隐患', className: 'risk-warning', detail: `发现 ${report.issueCount} 项安全问题；${report.unknownCount || 0} 项状态需要重新检测。` }
    return { text: '检测异常', className: 'risk-warning', detail: `${report.unknownCount || 0} 项系统状态暂未读取成功，请刷新检测重试。` }
  }

  function render(status) {
    latestStatus = status
    const report = status.securityReport
    const risk = riskCopy(report)
    const userName = status.userName || ''
    elements.user.textContent = status.signedIn ? (status.displayName || userName || '已登录') : '未登录'
    elements.user.title = userName || '未登录'
    elements.tenant.textContent = status.activeTenantName || '—'
    elements.tenant.title = status.activeTenantOrgName || '未获取租户组织'
    const domain = domainLabel(userName)
    elements.domain.textContent = domain
    elements.domain.title = domain
    elements.ip.textContent = report ? `${report.localIp}${report.publicAccess ? '（公网接入）' : ''}` : '正在检测'
    elements.ip.title = report?.publicAccess ? '已检测到公网连通性。' : '未检测到公网连通性或仍在检测。'
    elements.risk.textContent = risk.text
    elements.risk.className = `risk ${risk.className}`
    elements.risk.title = report ? report.checks.map((check) => `${check.title}：${check.detail}`).join('\n') : risk.detail
    elements.security.textContent = risk.text
    elements.security.title = elements.risk.title
    elements.security.style.color = report?.risk === 'pass' ? '#176b3e' : report?.risk === 'danger' ? '#a22f42' : report ? '#8a6116' : '#526f88'
    elements.login.textContent = status.signedIn ? '退出' : '登录'
    elements.login.disabled = !status.signedIn && !status.configured
  }

  async function refresh() {
    elements.refresh.disabled = true
    try {
      await window.cloudVerifyDevice.refreshSecurity()
      render(await window.cloudVerifyDevice.getStatus())
    } finally { elements.refresh.disabled = false }
  }

  elements.login.addEventListener('click', async () => {
    elements.login.disabled = true
    try {
      if (latestStatus?.signedIn) await window.cloudVerifyDevice.logout()
      else await window.cloudVerifyDevice.login()
      render(await window.cloudVerifyDevice.getStatus())
    } finally { elements.login.disabled = false }
  })
  elements.refresh.addEventListener('click', () => void refresh())
  window.cloudVerifyDevice.onStatusChanged(render)
  window.cloudVerifyDevice.getStatus().then(render).catch(() => undefined)
})()
