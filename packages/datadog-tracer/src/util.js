'use strict'

function addTags (obj, keyValuePairs, prefix) {
  if (!keyValuePairs) return

  for (const key in keyValuePairs) {
    setTag(obj, prefix ? `${prefix}${key}` : key, keyValuePairs[key])
  }
}

function now () {
  const hr = process.hrtime()
  return hr[0] * 1e9 + hr[1]
}

function parseTags (obj, str) {
  const tags = str ? str.split(',') : []

  for (const tag of tags) {
    const [key, value] = tag.split(':')

    if (key && value) {
      setTag(obj, key.trim(), value.trim())
    }
  }
}

function setTag (obj, key, value) {
  if (typeof value === 'number') {
    obj.metrics[key] = value
  } else if (typeof value === 'boolean') {
    obj.metrics[key] = value ? 1 : 0
  } else if (value) {
    obj.meta[key] = String(value)
  }
}

module.exports = { addTags, now, parseTags, setTag }
