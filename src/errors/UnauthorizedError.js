'use strict'

class UnauthorizedError extends Error {
  constructor(message = 'Unauthorized') {
    super(message)
  }

  get code() {
    return this.constructor.name
  }
}

module.exports = UnauthorizedError
