'use strict'

class AccessDeniedError extends Error {
  constructor(message = 'Operation access denied') {
    super(message)
  }

  get code() {
    return this.constructor.name
  }
}

module.exports = AccessDeniedError
