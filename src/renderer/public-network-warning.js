(() => {
  const image = document.getElementById('warning-image')
  const overlay = document.getElementById('password-overlay')
  const form = document.getElementById('password-form')
  const password = document.getElementById('password')
  const message = document.getElementById('password-message')
  const closeButton = document.getElementById('close-password-dialog')
  if (!(image instanceof HTMLImageElement) || !(overlay instanceof HTMLElement) || !(form instanceof HTMLFormElement) || !(password instanceof HTMLInputElement) || !(message instanceof HTMLElement) || !(closeButton instanceof HTMLButtonElement) || !window.cloudVerifyDevice) return

  const source = new URLSearchParams(window.location.search).get('image')
  if (source) image.src = source

  const clearAndHide = () => {
    password.value = ''
    message.textContent = ''
    overlay.hidden = true
  }
  const show = () => {
    password.value = ''
    message.textContent = ''
    overlay.hidden = false
    password.focus()
  }
  const cancel = async () => {
    clearAndHide()
    await window.cloudVerifyDevice.cancelPublicNetworkUnlock()
  }

  closeButton.addEventListener('click', () => { void cancel() })
  form.addEventListener('submit', async (event) => {
    event.preventDefault()
    message.textContent = ''
    const value = password.value
    if (!value) return
    // 密码不在渲染层保留；主进程验证成功后会隐藏整个 kiosk 警示页。
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
  window.cloudVerifyDevice.onPublicNetworkPasswordPromptChange((visible) => { if (visible) show(); else clearAndHide() })
})()
