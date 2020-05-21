'use strict'

const authorize         = require('./authorize')
const Authorization     = require('./Authorization')
const UnauthorizedError = require('./errors/UnauthorizedError')
const AccessDeniedError = require('./errors/AccessDeniedError')

const errors = {
  UnauthorizedError: { status: 'Unauthorized' },
  AccessDeniedError: { status: 'Forbidden' }
}

module.exports = {
  errors,
  authorize,
  Authorization,
  UnauthorizedError,
  AccessDeniedError
}
