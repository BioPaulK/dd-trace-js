'use strict'

const InjectionAnalyzer = require('./injection-analyzer')
const { CODE_INJECTION } = require('../vulnerabilities')
const { isTainted, getRanges } = require('../taint-tracking/operations')

class CodeInjectionAnalyzer extends InjectionAnalyzer {
  constructor () {
    super(CODE_INJECTION)
  }

  onConfigure () {
    this.addSub('datadog:eval:call', ({ script }) => {
      this.analyze(script)
      console.log('here?', script)
    })
  }

  _isVulnerable (value, iastContext) {
    console.log('istainted', value, getRanges(iastContext, value))
    const result = super._isVulnerable(value, iastContext)
    console.log('CodeInjection is vulnerable', result)
    return result
  }
}

module.exports = new CodeInjectionAnalyzer()
