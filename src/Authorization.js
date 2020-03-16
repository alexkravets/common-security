'use strict'

const config             = require('config')
const cookie             = require('cookie')
const includes           = require('lodash.includes')
const { Security }       = require('@slatestudio/common-service')
const AccessDeniedError  = require('./errors/AccessDeniedError')
const UnauthorizedError  = require('./errors/UnauthorizedError')
const { verify, decode } = require('jsonwebtoken')

class Authorization extends Security {
  authorize(options, payload) {
    const { group } = payload
    return includes(options, group)
  }

  getIdentity(payload) {
    const { sub: did, group, accountId } = payload
    return { did, group, accountId }
  }

  async isAuthorized(options) {
    let token

    const hasCookie = this._req.headers['set-cookie']

    if (hasCookie) {
      const cookies = cookie.parse(this._req.headers['set-cookie'])
      token = cookies.authorization
    }

    if (!token) {
      token = this._req.headers.authorization
    }

    if (!token) {
      const error = new UnauthorizedError('Authorization header is missing')
      return { isAuthorized: false, error }
    }

    const object = decode(token, { complete: true })
    if (!object) {
      const error = new UnauthorizedError('Invalid authorization token')
      return { isAuthorized: false, error }
    }

    try {
      const publicKey = config.get('authorization.publicKey')
      verify(token, publicKey, { algorithms: ['RS256'] })

    } catch (originalError) {
      const error = new UnauthorizedError()
      return { isAuthorized: false, error }

    }

    const { payload }  = object
    const isAuthorized = this.authorize(options, payload)

    if (!isAuthorized) {
      const error = new AccessDeniedError()
      return { isAuthorized: false, error }
    }

    const identity = this.getIdentity(payload)
    const context  = { identity }

    return { isAuthorized: true, context }
  }
}

module.exports = Authorization
