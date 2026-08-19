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
    const result = await window.cloudVerifyDevice.unlockPublicNetwork(value)
    if (!result.accepted) {
      password.value = ''
      password.focus()
      message.textContent = result.message || '管理员密码不正确。'
    }
  })
  password.focus()
})()
