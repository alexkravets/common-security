'use strict'

const cookie             = require('cookie')
const includes           = require('lodash.includes')
const authorize          = require('./authorize')
const AccessDeniedError  = require('./errors/AccessDeniedError')
const UnauthorizedError  = require('./errors/UnauthorizedError')
const { verify, decode } = require('jsonwebtoken')

const errors = {
  UnauthorizedError: { status: 'Unauthorized' },
  AccessDeniedError: { status: 'Forbidden' }
}

class Authorization {
  static get errors() {
    return errors
  }

  static get in() {
    return 'header'
  }

  static get type() {
    return 'apiKey'
  }

  static get definition() {
    return {
      [this.name]: {
        in:   this.in,
        type: this.type,
        name: this.name
      }
    }
  }

  static get algorithm() {
    return 'RS256'
  }

  static createRequirement(options = []) {
    return {
      [this.name]: {
        klass: this,
        options
      }
    }
  }

  static authorize(headers, requirements) {
    return authorize(headers, requirements)
  }

  constructor(headers) {
    this._headers = headers
  }

  /* istanbul ignore next */
  get publicKey() {
    throw new Error(`Public key is undefined for "${this.constructor.name}"`)
  }

  authorize(options, payload) {
    const { group } = payload
    return includes(options, group)
  }

  async isAuthorized(options) {
    let token

    const hasCookie = this._headers['set-cookie']

    if (hasCookie) {
      const cookies = cookie.parse(this._headers['set-cookie'])
      token = cookies.authorization
    }

    if (!token) {
      token = this._headers.authorization
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

    const { publicKey } = this

    try {
      verify(token, publicKey, { algorithms: [ this.constructor.algorithm ] })

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

    return { isAuthorized: true, identity: payload }
  }
}

module.exports = Authorization
