import { describe, it, expect } from 'vitest'
import {
  UnauthorizedException,
  UnauthenticatedException,
  PolicyConfigurationException,
  AuthErrorCode,
  createErrorMessage,
} from '../src/exceptions'

describe('UnauthorizedException', () => {
  it('should create exception with default message', () => {
    const error = new UnauthorizedException()

    expect(error).toBeInstanceOf(Error)
    expect(error).toBeInstanceOf(UnauthorizedException)
    expect(error.message).toBe('You do not have permission to perform this action')
    expect(error.name).toBe('UnauthorizedException')
    expect(error.code).toBe(AuthErrorCode.UNAUTHORIZED)
    expect(error.statusCode).toBe(403)
    expect(error.context).toBeUndefined()
  })

  it('should create exception with custom message', () => {
    const customMessage = 'Custom unauthorized message'
    const error = new UnauthorizedException(customMessage)

    expect(error.message).toBe(customMessage)
    expect(error.name).toBe('UnauthorizedException')
    expect(error.code).toBe(AuthErrorCode.UNAUTHORIZED)
    expect(error.statusCode).toBe(403)
  })

  it('should create exception with custom code and context', () => {
    const error = new UnauthorizedException(
      'Cannot delete user',
      AuthErrorCode.POLICY_DENIED,
      {
        action: 'delete',
        resourceType: 'User',
        role: 'EDITOR',
        userId: '123',
      }
    )

    expect(error.message).toBe('Cannot delete user')
    expect(error.code).toBe(AuthErrorCode.POLICY_DENIED)
    expect(error.context).toEqual({
      action: 'delete',
      resourceType: 'User',
      role: 'EDITOR',
      userId: '123',
    })
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

  describe('toDetailedMessage', () => {
    it('should return just message when no context', () => {
      const error = new UnauthorizedException('Access denied')
      expect(error.toDetailedMessage()).toBe('Access denied')
    })

    it('should include action and resource type', () => {
      const error = new UnauthorizedException('Access denied', AuthErrorCode.POLICY_DENIED, {
        action: 'delete',
        resourceType: 'User',
      })
      expect(error.toDetailedMessage()).toBe('Access denied | Action: delete on User')
    })

    it('should include role and user ID', () => {
      const error = new UnauthorizedException('Access denied', AuthErrorCode.POLICY_DENIED, {
        action: 'delete',
        resourceType: 'User',
        role: 'EDITOR',
        userId: '123',
      })
      expect(error.toDetailedMessage()).toBe(
        'Access denied | Action: delete on User | Role: EDITOR | User ID: 123'
      )
    })
  })

  describe('toJSON', () => {
    it('should return JSON-serializable object without context', () => {
      const error = new UnauthorizedException()
      const json = error.toJSON()

      expect(json).toEqual({
        error: 'UnauthorizedException',
        message: 'You do not have permission to perform this action',
        code: AuthErrorCode.UNAUTHORIZED,
        statusCode: 403,
      })
    })

    it('should include context in JSON when present', () => {
      const error = new UnauthorizedException('Denied', AuthErrorCode.POLICY_DENIED, {
        action: 'update',
        resourceType: 'Post',
      })
      const json = error.toJSON()

      expect(json).toEqual({
        error: 'UnauthorizedException',
        message: 'Denied',
        code: AuthErrorCode.POLICY_DENIED,
        statusCode: 403,
        context: {
          action: 'update',
          resourceType: 'Post',
        },
      })
    })
  })
})

describe('UnauthenticatedException', () => {
  it('should create exception with default message', () => {
    const error = new UnauthenticatedException()

    expect(error).toBeInstanceOf(Error)
    expect(error).toBeInstanceOf(UnauthenticatedException)
    expect(error.message).toBe('Authentication required')
    expect(error.name).toBe('UnauthenticatedException')
    expect(error.code).toBe(AuthErrorCode.UNAUTHENTICATED)
    expect(error.statusCode).toBe(401)
  })

  it('should create exception with custom message', () => {
    const customMessage = 'Please log in to continue'
    const error = new UnauthenticatedException(customMessage)

    expect(error.message).toBe(customMessage)
    expect(error.name).toBe('UnauthenticatedException')
    expect(error.code).toBe(AuthErrorCode.UNAUTHENTICATED)
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

  describe('toJSON', () => {
    it('should return JSON-serializable object', () => {
      const error = new UnauthenticatedException()
      const json = error.toJSON()

      expect(json).toEqual({
        error: 'UnauthenticatedException',
        message: 'Authentication required',
        code: AuthErrorCode.UNAUTHENTICATED,
        statusCode: 401,
      })
    })
  })
})

describe('PolicyConfigurationException', () => {
  it('should create exception with message and default code', () => {
    const error = new PolicyConfigurationException('Policy not found')

    expect(error).toBeInstanceOf(Error)
    expect(error.message).toBe('Policy not found')
    expect(error.name).toBe('PolicyConfigurationException')
    expect(error.code).toBe(AuthErrorCode.POLICY_NOT_FOUND)
    expect(error.statusCode).toBe(500)
  })

  it('should create exception with custom code and context', () => {
    const error = new PolicyConfigurationException(
      'Action not found',
      AuthErrorCode.ACTION_NOT_FOUND,
      {
        action: 'archive',
        resourceType: 'Post',
        details: { availableActions: ['view', 'update', 'delete'] },
      }
    )

    expect(error.message).toBe('Action not found')
    expect(error.code).toBe(AuthErrorCode.ACTION_NOT_FOUND)
    expect(error.context?.details).toEqual({ availableActions: ['view', 'update', 'delete'] })
  })

  describe('toJSON', () => {
    it('should return JSON-serializable object with context', () => {
      const error = new PolicyConfigurationException(
        'Policy error',
        AuthErrorCode.POLICY_NOT_FOUND,
        { resourceType: 'Unknown' }
      )
      const json = error.toJSON()

      expect(json).toEqual({
        error: 'PolicyConfigurationException',
        message: 'Policy error',
        code: AuthErrorCode.POLICY_NOT_FOUND,
        statusCode: 500,
        context: { resourceType: 'Unknown' },
      })
    })
  })
})

describe('AuthErrorCode', () => {
  it('should have all expected error codes', () => {
    expect(AuthErrorCode.UNAUTHORIZED).toBe('UNAUTHORIZED')
    expect(AuthErrorCode.UNAUTHENTICATED).toBe('UNAUTHENTICATED')
    expect(AuthErrorCode.POLICY_NOT_FOUND).toBe('POLICY_NOT_FOUND')
    expect(AuthErrorCode.ACTION_NOT_FOUND).toBe('ACTION_NOT_FOUND')
    expect(AuthErrorCode.POLICY_DENIED).toBe('POLICY_DENIED')
  })
})

describe('createErrorMessage', () => {
  it('should create message without role', () => {
    const message = createErrorMessage('delete', 'User')
    expect(message).toBe('You do not have permission to delete User')
  })

  it('should create message with role', () => {
    const message = createErrorMessage('update', 'Post', 'EDITOR')
    expect(message).toBe('You do not have permission to update Post as EDITOR')
  })
})
