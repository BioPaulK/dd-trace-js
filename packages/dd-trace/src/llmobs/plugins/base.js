'use strict'

const log = require('../../log')
const { storage } = require('../storage')

const TracingPlugin = require('../../plugins/tracing')
const LLMObsTagger = require('../tagger')

// we make this a `Plugin` so we don't have to worry about `finish` being called
class LLMObsPlugin extends TracingPlugin {
  constructor (...args) {
    super(...args)

    this._tagger = new LLMObsTagger(this._tracerConfig, true)
  }

  setLLMObsTags (ctx) {
    throw new Error('setLLMObsTags must be implemented by the subclass')
  }

  getLLMObsSpanRegisterOptions (ctx) {
    throw new Error('getLLMObsSPanRegisterOptions must be implemented by the subclass')
  }

  start (ctx) {
    const parent = this.getLLMObsParent(ctx)
    const span = ctx.currentStore?.span

    const registerOptions = this.getLLMObsSpanRegisterOptions(ctx)

    if (registerOptions) {
      this._tagger.registerLLMObsSpan(span, { parent, ...registerOptions })
    }
  }

  asyncEnd (ctx) {
    // even though llmobs span events won't be enqueued if llmobs is disabled
    // we should avoid doing any computations here (these listeners aren't disabled)
    const enabled = this._tracerConfig.llmobs.enabled
    if (!enabled) return

    const span = ctx.currentStore?.span
    if (!span) {
      log.debug(
        `Tried to start an LLMObs span for ${this.constructor.name} without an active APM span.
        Not starting LLMObs span.`
      )
      return
    }

    this.setLLMObsTags(ctx)
  }

  configure (config) {
    // we do not want to enable any LLMObs plugins if it is disabled on the tracer
    const llmobsEnabled = this._tracerConfig.llmobs.enabled
    if (llmobsEnabled === false) {
      config = typeof config === 'boolean' ? false : { ...config, enabled: false } // override to false
    }
    super.configure(config)
  }

  getLLMObsParent (ctx) {
    const parentApmSpan = ctx.currentStore?.span
    const parentLLMObsSpan = storage.getStore()?.span

    let parent
    if (
      parentApmSpan === parentLLMObsSpan || // they are the same
      LLMObsTagger.tagMap.has(parentApmSpan) // they are not the same, but the APM span is a parent
    ) {
      parent = parentApmSpan
    } else {
      parent = parentLLMObsSpan
    }

    return parent
  }
}

module.exports = LLMObsPlugin
