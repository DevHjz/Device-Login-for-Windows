(() => {
  const image = document.getElementById('warning-image')
  if (!(image instanceof HTMLImageElement)) return
  const source = new URLSearchParams(window.location.search).get('image')
  if (source) image.src = source
})()
