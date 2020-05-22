'use strict'

const authorize         = require('./authorize')
const Authorization     = require('./Authorization')
const UnauthorizedError = require('./errors/UnauthorizedError')
const AccessDeniedError = require('./errors/AccessDeniedError')

module.exports = {
  authorize,
  Authorization,
  UnauthorizedError,
  AccessDeniedError
}
