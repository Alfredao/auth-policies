/**
 * Context information for authorization errors
 */
export interface AuthErrorContext {
  /** The action that was attempted (e.g., 'update', 'delete') */
  action?: string
  /** The resource type (e.g., 'User', 'Post') */
  resourceType?: string
  /** The user's role */
  role?: string
  /** The user's ID */
  userId?: string
  /** Additional details */
  details?: Record<string, unknown>
}

/**
 * Error codes for programmatic handling
 */
export const AuthErrorCode = {
  UNAUTHORIZED: 'UNAUTHORIZED',
  UNAUTHENTICATED: 'UNAUTHENTICATED',
  POLICY_NOT_FOUND: 'POLICY_NOT_FOUND',
  ACTION_NOT_FOUND: 'ACTION_NOT_FOUND',
  POLICY_DENIED: 'POLICY_DENIED',
} as const

export type AuthErrorCodeType = (typeof AuthErrorCode)[keyof typeof AuthErrorCode]

/**
 * Exception thrown when a user is not authorized to perform an action
 * Typically caught in API error handlers and converted to a 403 response
 */
export class UnauthorizedException extends Error {
  public readonly code: AuthErrorCodeType
  public readonly statusCode = 403
  public readonly context?: AuthErrorContext

  constructor(
    message = 'You do not have permission to perform this action',
    code: AuthErrorCodeType = AuthErrorCode.UNAUTHORIZED,
    context?: AuthErrorContext
  ) {
    super(message)
    this.name = 'UnauthorizedException'
    this.code = code
    this.context = context

    // Maintains proper stack trace for where error was thrown (V8 engines)
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, UnauthorizedException)
    }
  }

  /**
   * Get a detailed error message including context
   */
  toDetailedMessage(): string {
    const parts = [this.message]

    if (this.context) {
      const { action, resourceType, role, userId } = this.context
      if (action && resourceType) {
        parts.push(`Action: ${action} on ${resourceType}`)
      }
      if (role) {
        parts.push(`Role: ${role}`)
      }
      if (userId) {
        parts.push(`User ID: ${userId}`)
      }
    }

    return parts.join(' | ')
  }

  /**
   * Convert to a JSON-serializable object for API responses
   */
  toJSON(): Record<string, unknown> {
    return {
      error: this.name,
      message: this.message,
      code: this.code,
      statusCode: this.statusCode,
      ...(this.context && { context: this.context }),
    }
  }
}

/**
 * Exception thrown when no user is authenticated
 * Typically caught in API error handlers and converted to a 401 response
 */
export class UnauthenticatedException extends Error {
  public readonly code = AuthErrorCode.UNAUTHENTICATED
  public readonly statusCode = 401

  constructor(message = 'Authentication required') {
    super(message)
    this.name = 'UnauthenticatedException'

    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, UnauthenticatedException)
    }
  }

  /**
   * Convert to a JSON-serializable object for API responses
   */
  toJSON(): Record<string, unknown> {
    return {
      error: this.name,
      message: this.message,
      code: this.code,
      statusCode: this.statusCode,
    }
  }
}

/**
 * Exception thrown when a policy configuration error occurs
 */
export class PolicyConfigurationException extends Error {
  public readonly code: AuthErrorCodeType
  public readonly statusCode = 500
  public readonly context?: AuthErrorContext

  constructor(
    message: string,
    code: AuthErrorCodeType = AuthErrorCode.POLICY_NOT_FOUND,
    context?: AuthErrorContext
  ) {
    super(message)
    this.name = 'PolicyConfigurationException'
    this.code = code
    this.context = context

    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, PolicyConfigurationException)
    }
  }

  /**
   * Convert to a JSON-serializable object for API responses
   */
  toJSON(): Record<string, unknown> {
    return {
      error: this.name,
      message: this.message,
      code: this.code,
      statusCode: this.statusCode,
      ...(this.context && { context: this.context }),
    }
  }
}

/**
 * Helper to create user-friendly error messages
 */
export function createErrorMessage(
  action: string,
  resourceType: string,
  role?: string
): string {
  const roleInfo = role ? ` as ${role}` : ''
  return `You do not have permission to ${action} ${resourceType}${roleInfo}`
}
