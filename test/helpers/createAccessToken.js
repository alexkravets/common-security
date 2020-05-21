'use strict'

const JWT           = require('jsonwebtoken')
const privateKey    = require('./privateKey')
const { algorithm } = require('src/Authorization')

const createAccessToken = (options, attributes) => {
  const payload = {
    sub:    'SESSION_ID',
    userId: 'USER_ID',
    ...attributes
  }

  const token = JWT.sign(payload, privateKey, { algorithm, ...options })

  return token
}

module.exports = createAccessToken
