'use strict'

const Authorization = require('./src/Authorization')

const errors = {
  UnauthorizedError: { status: 'Unauthorized' },
  AccessDeniedError: { status: 'Forbidden' }
}

module.exports = {
  Authorization,
  errors
}
