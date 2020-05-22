'use strict'

const wait              = require('./helpers/wait')
const publicKey         = require('./helpers/publicKey')
const { expect }        = require('chai')
const _Authorization    = require('src/Authorization')
const createAccessToken = require('./helpers/createAccessToken')

class Authorization extends _Authorization {
  get publicKey() {
    return publicKey
  }
}

const requirements = [
  Authorization.createRequirement([ 'Administrators' ])
]

describe('Authorization', () => {
  describe('Authorization.authorize(headers, requirements)', () => {
    it('throws "UnauthorizedError" if no authorization headers', async() => {
      try {
        await Authorization.authorize({}, requirements)

      } catch (error) {
        expect(error.message).to.eql('Authorization header is missing')
        expect(error.code).to.eql('UnauthorizedError')
        return
      }

      throw new Error('"UnauthorizedError" error has not been thrown')
    })

    it('throws "UnauthorizedError" if invalid authorization header', async() => {
      const cookie = 'authorization=INVALID_TOKEN; path=/; HttpOnly'

      try {
        await Authorization.authorize({ 'set-cookie': cookie }, requirements)

      } catch (error) {
        expect(error.message).to.eql('Invalid authorization token')
        expect(error.code).to.eql('UnauthorizedError')
        return
      }

      throw new Error('"UnauthorizedError" error has not been thrown')
    })

    it('throws "UnauthorizedError" if token expired', async() => {
      const authorization = createAccessToken({ expiresIn: '1 second' })
      await wait(1200)

      try {
        await Authorization.authorize({ authorization }, requirements)

      } catch (error) {
        expect(error.message).to.eql('Unauthorized')
        expect(error.code).to.eql('UnauthorizedError')
        return
      }

      throw new Error('"UnauthorizedError" error has not been thrown')
    })

    it('throws "AccessDeniedError" if token missing an option', async() => {
      const authorization = createAccessToken()

      try {
        await Authorization.authorize({ authorization }, requirements)

      } catch (error) {
        expect(error.message).to.eql('Operation access denied')
        expect(error.code).to.eql('AccessDeniedError')
        return
      }

      throw new Error('"UnauthorizedError" error has not been thrown')
    })

    it('returns isAuthorized: true and identity if success', async() => {
      const authorization = createAccessToken({}, { group: 'Administrators' })

      const { identity } = await Authorization.authorize({ authorization }, requirements)

      expect(identity.sub).to.eql('SESSION_ID')
      expect(identity.group).to.eql('Administrators')
      expect(identity.userId).to.eql('USER_ID')
    })

    it('does nothing if no requirements specified', async() => {
      await Authorization.authorize()
    })
  })

  describe('Authorization.errors', () => {
    it('returns errors map', () => {
      expect(Authorization.errors).to.exist
    })
  })

  describe('Authorization.in', () => {
    it('returns authorization location', () => {
      expect(Authorization.in).to.eql('header')
    })
  })

  describe('Authorization.apiKey', () => {
    it('returns authorization type', () => {
      expect(Authorization.type).to.eql('apiKey')
    })
  })

  describe('Authorization.definition', () => {
    it('returns OAS security definition', () => {
      const { definition } = Authorization

      expect(definition.Authorization.in).to.eql('header')
      expect(definition.Authorization.type).to.eql('apiKey')
      expect(definition.Authorization.name).to.eql('Authorization')

      expect(Authorization.definition).to.exist
    })
  })

  describe('Authorization.createRequirement(options = [])', () => {
    it('returns requirement with empty options', () => {
      const requirement = Authorization.createRequirement()

      expect(requirement.Authorization.options).to.be.empty
    })
  })
})
