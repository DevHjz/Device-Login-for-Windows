(() => {
  const form = document.getElementById('password-form')
  const password = document.getElementById('password')
  const message = document.getElementById('password-message')
  if (!(form instanceof HTMLFormElement) || !(password instanceof HTMLInputElement) || !(message instanceof HTMLElement)) return
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
