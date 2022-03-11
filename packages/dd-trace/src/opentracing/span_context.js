'use strict'

const SpanContext = require('opentracing').SpanContext

class DatadogSpanContext extends SpanContext {
  constructor (span) {
    super()

    this._span = span
  }

  get _traceId () {
    return this._span.trace.traceId
  }

  get _spanId () {
    return this._span.spanId
  }

  get _parentId () {
    return this._span.parentId
  }

  get _name () {
    return this._span.name
  }

  set _name (value) {
    this._span.name = value
  }

  get _tags () {
    const span = this._span
    const spanTags = Object.assign({}, span.meta, span.metrics)
    const errorTags = {}

    if (span.error) {
      if (typeof span.error === 'object') {
        errorTags['error'] = 1
        errorTags['error.type'] = span.error.name
        errorTags['error.msg'] = span.error.message
        errorTags['error.stack'] = span.error.stack
      } else {
        errorTags['error'] = span.error
      }
    }

    return {
      'resource.name': span.resource,
      'service.name': span.service || span.tracer.config.service,
      'span.kind': span.kind,
      'span.type': span.type,
      ...errorTags,
      ...spanTags
    }
  }

  get _baggageItems () {
    return this._span.baggage
  }

  get _sampling () {
    const span = this._span

    return {
      get priority () {
        return span.trace.samplingPriority
      },

      set priority (value) {
        span.trace.samplingPriority = value
      }
    }
  }

  get _trace () {
    const trace = this._span.trace

    return {
      get started () {
        return trace.spans
      },

      get finished () {
        return trace.spans.filter(span => span.duration > 0)
      },

      get tags () {
        return Object.assign({}, trace.meta, trace.metrics)
      },

      get origin () {
        return trace.origin
      },

      set origin (value) {
        trace.origin = value
      }
    }
  }

  toTraceId () {
    return this._traceId.toString(10)
  }

  toSpanId () {
    return this._spanId.toString(10)
  }
}

module.exports = DatadogSpanContext
