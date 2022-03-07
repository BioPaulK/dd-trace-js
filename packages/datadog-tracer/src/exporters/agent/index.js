'use strict'

const { Client } = require('./client')

const noop = () => {}

class AgentExporter {
  constructor (config, sampler) {
    this._config = config
    this._sampler = sampler
    this._protocolVersion = config.protocolVersion
    this._client = new Client(config)
    this._encoders = {}
    this._timer = undefined

    process.once('beforeExit', () => this.flush())
  }

  add (spans) {
    const flushInterval = this._config.flushInterval

    this._getEncoder().encode(spans)

    if (flushInterval === 0) {
      this.flush()
    } else if (flushInterval > 0 && !this._timer) {
      this._timer = setTimeout(() => this.flush(), flushInterval).unref()
    }
  }

  flush (done = noop) {
    const encoder = this._getEncoder()
    const count = encoder.count()

    if (count === 0) return

    const data = encoder.makePayload()
    const path = `/v${this._protocolVersion}/traces`

    this._client.request({ data, path, count }, (err, res) => {
      if (!err && res.rate_by_service) {
        this._sampler.update(res.rate_by_service)
      }

      done(err)
    })

    this._protocolVersion = this._config.protocolVersion
  }

  _getEncoder () {
    const config = this._config
    const protocolVersion = this._protocolVersion

    if (!this._encoders[protocolVersion]) {
      switch (protocolVersion) {
        case '0.5': {
          const { Encoder } = require('./encoder/0.5')
          this._encoders[protocolVersion] = new Encoder(this, config)
          break
        }
        default: {
          const { Encoder } = require('./encoder/0.4')
          this._encoders[protocolVersion] = new Encoder(this, config)
        }
      }
    }

    return this._encoders[protocolVersion]
  }
}

module.exports = { AgentExporter }
