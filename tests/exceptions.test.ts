import { describe, it, expect } from 'vitest'
import { UnauthorizedException, UnauthenticatedException } from '../src/exceptions'

describe('UnauthorizedException', () => {
  it('should create exception with default message', () => {
    const error = new UnauthorizedException()

    expect(error).toBeInstanceOf(Error)
    expect(error).toBeInstanceOf(UnauthorizedException)
    expect(error.message).toBe('You do not have permission to perform this action')
    expect(error.name).toBe('UnauthorizedException')
    expect(error.code).toBe('UNAUTHORIZED')
    expect(error.statusCode).toBe(403)
  })

  it('should create exception with custom message', () => {
    const customMessage = 'Custom unauthorized message'
    const error = new UnauthorizedException(customMessage)

    expect(error.message).toBe(customMessage)
    expect(error.name).toBe('UnauthorizedException')
    expect(error.code).toBe('UNAUTHORIZED')
    expect(error.statusCode).toBe(403)
  })

  it('should have proper stack trace', () => {
    const error = new UnauthorizedException()

    expect(error.stack).toBeDefined()
    expect(error.stack).toContain('UnauthorizedException')
  })

  it('should be catchable as Error', () => {
    expect(() => {
      throw new UnauthorizedException()
    }).toThrow(Error)
  })

  it('should be catchable by name', () => {
    try {
      throw new UnauthorizedException()
    } catch (error) {
      expect((error as Error).name).toBe('UnauthorizedException')
    }
  })
})

describe('UnauthenticatedException', () => {
  it('should create exception with default message', () => {
    const error = new UnauthenticatedException()

    expect(error).toBeInstanceOf(Error)
    expect(error).toBeInstanceOf(UnauthenticatedException)
    expect(error.message).toBe('Authentication required')
    expect(error.name).toBe('UnauthenticatedException')
    expect(error.code).toBe('UNAUTHENTICATED')
    expect(error.statusCode).toBe(401)
  })

  it('should create exception with custom message', () => {
    const customMessage = 'Please log in to continue'
    const error = new UnauthenticatedException(customMessage)

    expect(error.message).toBe(customMessage)
    expect(error.name).toBe('UnauthenticatedException')
    expect(error.code).toBe('UNAUTHENTICATED')
    expect(error.statusCode).toBe(401)
  })

  it('should have proper stack trace', () => {
    const error = new UnauthenticatedException()

    expect(error.stack).toBeDefined()
    expect(error.stack).toContain('UnauthenticatedException')
  })

  it('should be distinguishable from UnauthorizedException', () => {
    const unauthenticated = new UnauthenticatedException()
    const unauthorized = new UnauthorizedException()

    expect(unauthenticated.statusCode).not.toBe(unauthorized.statusCode)
    expect(unauthenticated.code).not.toBe(unauthorized.code)
    expect(unauthenticated.name).not.toBe(unauthorized.name)
  })
})
