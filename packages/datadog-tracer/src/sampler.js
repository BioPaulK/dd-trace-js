'use strict'

const { RateLimiter } = require('./limiter')

const DEFAULT_KEY = 'service:,env:'
const {
  AUTO_KEEP,
  AUTO_REJECT,
  SAMPLING_MECHANISM_AGENT,
  SAMPLING_MECHANISM_DEFAULT,
  SAMPLING_MECHANISM_RULE,
  SAMPLING_AGENT_DECISION,
  SAMPLING_RULE_DECISION,
  SAMPLING_LIMIT_DECISION,
  USER_KEEP,
  USER_REJECT,
  UPSTREAM_SERVICES_KEY
} = require('./constants')

const serviceNames = new Map()

class Sampler {
  constructor ({ sampleRate, rateLimit = 100, rules = [] } = {}) {
    this._rates = {}
    this._rules = this._normalizeRules(rules, sampleRate)
    this._limiter = this._rules.length > 0 && new RateLimiter(rateLimit)
  }

  sample (span) {
    const trace = span.trace
    const root = trace.spans[0]

    if (!root || trace.samplingPriority !== undefined) return

    const rule = this._findRule(root)

    if (rule) {
      this._setPriorityByRule(root, rule)
    } else {
      this._setPriorityByAgent(root)
    }
  }

  update (rates) {
    this._rates = rates
  }

  _isSampled (rate) {
    return rate === 1 || Math.random() < rate
  }

  _setPriorityByRule (span, rule) {
    const trace = span.trace
    const sampled = this._isSampled(rule.sampleRate)
    const allowed = sampled && this._limiter.isAllowed()

    trace.samplingPriority = sampled && allowed ? USER_KEEP : USER_REJECT
    trace.samplingMechanism = SAMPLING_MECHANISM_RULE
    trace.metrics[SAMPLING_RULE_DECISION] = rule.sampleRate

    if (!allowed) {
      trace.metrics[SAMPLING_LIMIT_DECISION] = this._limiter.effectiveRate()
    }
  }

  _setPriorityByAgent (span) {
    const trace = span.trace
    const key = `service:${span.service},env:${this._env}`
    const rate = this._rates[key] || this._rates[DEFAULT_KEY]

    if (rate === undefined) {
      trace.samplingPriority = AUTO_KEEP
      trace.samplingMechanism = SAMPLING_MECHANISM_DEFAULT
    } else {
      trace.samplingPriority = this._isSampled(rate) ? AUTO_KEEP : AUTO_REJECT
      trace.samplingMechanism = SAMPLING_MECHANISM_AGENT
      trace.metrics[SAMPLING_AGENT_DECISION] = rate
    }
  }

  _normalizeRules (rules, sampleRate) {
    return rules
      .concat({ sampleRate })
      .map(rule => ({ ...rule, sampleRate: parseFloat(rule.sampleRate) }))
      .filter(rule => !isNaN(rule.sampleRate))
  }

  _findRule (context) {
    for (let i = 0, l = this._rules.length; i < l; i++) {
      if (this._matchRule(context, this._rules[i])) return this._rules[i]
    }
  }

  _matchRule (span, rule) {
    const name = span.name
    const service = span.service

    if (rule.name instanceof RegExp && !rule.name.test(name)) return false
    if (typeof rule.name === 'string' && rule.name !== name) return false
    if (rule.service instanceof RegExp && !rule.service.test(service)) return false
    if (typeof rule.service === 'string' && rule.service !== service) return false

    return true
  }

  _addUpstreamService (span) {
    const context = span.context()
    const trace = context._trace
    const service = this._toBase64(context._tags['service.name'])
    const priority = context._sampling.priority
    const mechanism = context._sampling.mechanism
    const rate = this._getRate(span)
    const group = `${service}|${priority}|${mechanism}|${rate}`
    const groups = trace.meta[UPSTREAM_SERVICES_KEY]
      ? `${trace.meta[UPSTREAM_SERVICES_KEY]};${group}`
      : group

    trace.meta[UPSTREAM_SERVICES_KEY] = groups
  }

  _toBase64 (serviceName) {
    let encoded = serviceNames.get(serviceName)

    if (!encoded) {
      encoded = Buffer.from(serviceName).toString('base64')
      serviceNames.set(serviceName, encoded)
    }

    return encoded
  }

  _getRate (span) {
    const trace = span.trace

    switch (trace.samplingMechanism) {
      case SAMPLING_MECHANISM_RULE:
        return Math.ceil(trace.metrics[SAMPLING_RULE_DECISION] * 10000) / 10000
      case SAMPLING_MECHANISM_AGENT:
        return Math.ceil(trace.metrics[SAMPLING_AGENT_DECISION] * 10000) / 10000
      default:
        return ''
    }
  }
}

module.exports = { Sampler }
