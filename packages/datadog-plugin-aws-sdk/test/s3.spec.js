'use strict'

const agent = require('../../dd-trace/test/plugins/agent')
const { setup } = require('./spec_helpers')
const axios = require('axios')
const { rawExpectedSchema } = require('./s3-naming')
const { SPAN_LINK_KIND, S3_PTR_KIND, SPAN_POINTER_DIRECTION } = require('../../dd-trace/src/span_pointers')

const bucketName = 's3-bucket-name-test'

/* eslint-disable no-console */
async function resetLocalStackS3 () {
  try {
    await axios.post('http://localhost:4566/reset')
    console.log('LocalStack S3 reset successful')
  } catch (error) {
    console.error('Error resetting LocalStack S3:', error.message)
  }
}

describe('Plugin', () => {
  describe('aws-sdk (s3)', function () {
    setup()

    withVersions('aws-sdk', ['aws-sdk', '@aws-sdk/smithy-client'], (version, moduleName) => {
      let AWS
      let s3
      let tracer

      const s3ClientName = moduleName === '@aws-sdk/smithy-client' ? '@aws-sdk/client-s3' : 'aws-sdk'
      describe('with configuration', () => {
        before(() => {
          tracer = require('../../dd-trace')
          tracer.init()
          return agent.load('aws-sdk')
        })

        before(done => {
          AWS = require(`../../../versions/${s3ClientName}@${version}`).get()
          s3 = new AWS.S3({ endpoint: 'http://127.0.0.1:4566', s3ForcePathStyle: true, region: 'us-east-1' })

          // Fix for LocationConstraint issue - only for SDK v2
          if (s3ClientName === 'aws-sdk') {
            s3.api.globalEndpoint = '127.0.0.1'
          }

          s3.createBucket({ Bucket: bucketName }, (err) => {
            if (err) return done(err)
            done()
          })
        })

        after(async () => {
          await resetLocalStackS3()
          return agent.close({ ritmReset: false })
        })

        withPeerService(
          () => tracer,
          'aws-sdk',
          (done) => s3.putObject({
            Bucket: bucketName,
            Key: 'test-key',
            Body: 'test body'
          }, (err) => err && done(err)),
          bucketName, 'bucketname')

        withNamingSchema(
          (done) => s3.putObject({
            Bucket: bucketName,
            Key: 'test-key',
            Body: 'test body'
          }, (err) => err && done(err)),
          rawExpectedSchema.outbound
        )

        describe('span pointers', () => {
          it('should add span pointer for putObject operation', (done) => {
            agent.use(traces => {
              try {
                const span = traces[0][0]
                const links = JSON.parse(span.meta?.['_dd.span_links'] || '[]')

                expect(links).to.have.lengthOf(1)
                expect(links[0].attributes).to.deep.equal({
                  'ptr.kind': S3_PTR_KIND,
                  'ptr.dir': SPAN_POINTER_DIRECTION.DOWNSTREAM,
                  'link.kind': SPAN_LINK_KIND,
                  'ptr.hash': '6d1a2fe194c6579187408f827f942be3'
                })
                done()
              } catch (error) {
                done(error)
              }
            }).catch(done)

            s3.putObject({
              Bucket: bucketName,
              Key: 'test-key',
              Body: 'test body'
            }, (err) => {
              if (err) {
                done(err)
              }
            })
          })

          it('should add span pointer for copyObject operation', (done) => {
            agent.use(traces => {
              try {
                const span = traces[0][0]
                const links = JSON.parse(span.meta?.['_dd.span_links'] || '[]')

                expect(links).to.have.lengthOf(1)
                expect(links[0].attributes).to.deep.equal({
                  'ptr.kind': S3_PTR_KIND,
                  'ptr.dir': SPAN_POINTER_DIRECTION.DOWNSTREAM,
                  'link.kind': SPAN_LINK_KIND,
                  'ptr.hash': '1542053ce6d393c424b1374bac1fc0c5'
                })
                done()
              } catch (error) {
                done(error)
              }
            }).catch(done)

            s3.copyObject({
              Bucket: bucketName,
              Key: 'new-key',
              CopySource: `${bucketName}/test-key`
            }, (err) => {
              if (err) {
                done(err)
              }
            })
          })
        })

        it('should allow disabling a specific span kind of a service', (done) => {
          let total = 0

          agent.use(traces => {
            const span = traces[0][0]
            expect(span).to.include({
              name: 'aws.request',
              resource: `putObject ${bucketName}`
            })

            expect(span.meta).to.include({
              bucketname: bucketName,
              aws_service: 'S3',
              region: 'us-east-1'
            })

            total++
          }).catch(() => {}, { timeoutMs: 100 })

          s3.putObject({
            Bucket: bucketName,
            Key: 'test-key',
            Body: 'test body'
          }, (err) => {
            if (err) return done(err)

            setTimeout(() => {
              try {
                expect(total).to.equal(1)
                done()
              } catch (e) {
                done(e)
              }
            }, 250)
          })
        })
      })
    })
  })
})
