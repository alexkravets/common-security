'use strict'

class UnauthorizedError extends Error {
  constructor(message = 'Unauthorized') {
    super(message)
  }

  get code() {
    return 'UnauthorizedError'
  }
}

module.exports = UnauthorizedError
