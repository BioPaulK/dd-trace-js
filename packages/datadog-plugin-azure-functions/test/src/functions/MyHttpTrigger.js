const tracer = require('dd-trace').init({
  service: 'test',
  env: 'tester',
  flushInterval: 0,
  plugins: false
})
tracer.use('azure-functions')
const { app } = require('@azure/functions')

app.http('MyHttpTrigger', {
  methods: ['GET', 'POST'],
  authLevel: 'anonymous',
  handler: async (request, context) => {
    context.log(`Http function processed request for url "${request.url}"`)
	    const response1 = await fetch('https://example.com')
    const name = request.query.get('name') || await request.text() || 'world'

    return { body: `Hello, ${name}!` }
  }
})
