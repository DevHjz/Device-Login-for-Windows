(() => {
  const personalDomains = new Set(['163.com', '126.com', 'qq.com', 'yeah.net', 'gmail.com', 'googlemail.com', 'outlook.com', 'hotmail.com', 'live.com', 'icloud.com', 'foxmail.com', 'sina.com', 'sohu.com'])
  const byId = (id) => document.getElementById(id)
  const elements = {
    risk: byId('float-risk'), user: byId('float-user'), tenant: byId('float-tenant'), domain: byId('float-domain'), ip: byId('float-ip'), security: byId('float-security'), login: byId('float-login'), refresh: byId('float-refresh'),
  }
  let latestStatus = null

  function domainLabel(userName) {
    const domain = String(userName || '').split('@')[1]?.toLowerCase() || ''
    if (!domain) return '未获取'
    if (personalDomains.has(domain)) return '个人用户'
    if (domain.includes('devhjz')) return 'DevHjz'
    return domain
  }

  function riskCopy(report) {
    if (!report) return { text: '检查中', className: 'risk-neutral', detail: '正在读取本机安全状态。' }
    if (report.risk === 'pass') return { text: '通过检测', className: 'risk-pass', detail: '所有设备安全检查均已通过。' }
    if (report.risk === 'danger') return { text: '高危风险', className: 'risk-danger', detail: `发现 ${report.issueCount} 项需要处理的安全问题。` }
    return { text: '存在隐患', className: 'risk-warning', detail: `发现 ${report.issueCount} 项需要处理或确认的安全问题。` }
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
    elements.domain.textContent = domainLabel(userName)
    elements.domain.title = elements.domain.textContent
    elements.ip.textContent = report ? `${report.localIp}${report.publicAccess ? '（公网接入）' : ''}` : '正在检测'
    elements.ip.title = report?.publicAccess ? '已检测到公网连通性。' : '未检测到公网连通性或仍在检测。'
    elements.risk.textContent = risk.text
    elements.risk.className = `risk ${risk.className}`
    elements.security.textContent = risk.text
    elements.security.style.color = report?.risk === 'pass' ? '#16693b' : report?.risk === 'danger' ? '#a33242' : report ? '#8e6215' : '#52677c'
    elements.security.title = report ? report.checks.map((check) => `${check.title}：${check.detail}`).join('\n') : risk.detail
    elements.login.textContent = status.signedIn ? '退出' : '登录'
    elements.login.disabled = !status.signedIn && !status.configured
  }

  async function refresh() {
    elements.refresh.disabled = true
    try { await window.cloudVerifyDevice.refreshSecurity(); render(await window.cloudVerifyDevice.getStatus()) } finally { elements.refresh.disabled = false }
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
