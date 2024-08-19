'use strict'

const Chunk = require('./msgpack/chunk')

class Dictionary {
  constructor () {
    this.length = 0

    this._bytes = new Chunk()

    this.reset()
  }

  get byteLength () {
    return this._bytes.length
  }

  get data () {
    return this._bytes.buffer.subarray(0, this._bytes.length)
  }

  get (value = '') {
    if (!(value in this._map)) {
      this._map[value] = this.length++
      this._bytes.write(value)
    }

    return this._map[value]
  }

  reset () {
    this._bytes.length = 0
    this._map = {}

    this.length = 0

    this.get('')
  }
}

module.exports = { Dictionary }