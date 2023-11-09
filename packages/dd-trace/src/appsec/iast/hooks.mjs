let i = 0
const loadMap = new Map()
const MAX_REWRITE_TIME_MS = 100
let communicationPort

export async function initialize({ port }) {
  communicationPort = port
  communicationPort.on('message', (msg) => {
    if (msg.id !== undefined) {
      const cb = loadMap.get(msg.id)
      if (cb) {
        cb({ id: msg.id, source: msg.source })
      }
    }
  })
}

export async function load(url, context, nextLoad) {
  const nextLoadResult = await nextLoad(url, context)
  if (nextLoadResult.source) {
    const id = i++
    return new Promise((resolve) => {
      let resolved = false
      const timeout = setTimeout(() => {
        if (!resolved) {
          resolved = true
          loadMap.delete(id)
          resolve(nextLoadResult)
        }
      }, MAX_REWRITE_TIME_MS)
      timeout.unref && timeout.unref()

      loadMap.set(id, ({ source }) => {
        if (!resolved) {
          resolved = true
          nextLoadResult.source = Buffer.from(source)
          clearTimeout(timeout)
          resolve(nextLoadResult)
        }
      })
      communicationPort.postMessage({
        id,
        url,
        source: nextLoadResult.source
      })
    })

  }
  return nextLoadResult
}
