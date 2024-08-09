'use strict'

if (process.env.DD_BENCH_TRACE_ENABLE) {
  require('../..').init({})
} else if (process.env.DD_BENCH_ASYNC_HOOKS) {
  const asyncHooks = require('node:async_hooks')
  const hook = asyncHooks.createHook({
    init () {},
    before () {},
    after () {},
    destroy () {}
  })
  hook.enable()
}
const { Server } = require('node:http')
const origEmit = Server.prototype.emit
Server.prototype.emit = function (name) {
  if (name === 'listening') { process.send && process.send({ ready: true }) }
  return origEmit.apply(this, arguments)
}
