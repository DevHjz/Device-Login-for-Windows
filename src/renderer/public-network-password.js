(() => {
  const form = document.getElementById('password-form')
  const password = document.getElementById('password')
  const message = document.getElementById('password-message')
  const closeButton = document.getElementById('close-password-dialog')
  if (!(form instanceof HTMLFormElement) || !(password instanceof HTMLInputElement) || !(message instanceof HTMLElement) || !(closeButton instanceof HTMLButtonElement)) return
  const cancel = async () => { await window.cloudVerifyDevice.cancelPublicNetworkUnlock() }
  closeButton.addEventListener('click', () => { void cancel() })
  document.addEventListener('keydown', (event) => { if (event.key === 'Escape') { event.preventDefault(); void cancel() } })
  form.addEventListener('submit', async (event) => {
    event.preventDefault()
    message.textContent = ''
    const value = password.value
    if (!value) return
    // 无论验证结果如何，密码都不保留在弹窗控件中。
    password.value = ''
    try {
      const result = await window.cloudVerifyDevice.unlockPublicNetwork(value)
      if (!result.accepted) {
        password.focus()
        message.textContent = result.message || '管理员密码不正确。'
      }
    } catch {
      password.focus()
      message.textContent = '密码验证未完成，请稍后重试。'
    }
  })
  password.focus()
})()
