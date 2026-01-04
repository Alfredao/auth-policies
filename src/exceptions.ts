/**
 * Exception thrown when a user is not authorized to perform an action
 * Typically caught in API error handlers and converted to a 403 response
 */
export class UnauthorizedException extends Error {
  public readonly code = 'UNAUTHORIZED'
  public readonly statusCode = 403

  constructor(message = 'You do not have permission to perform this action') {
    super(message)
    this.name = 'UnauthorizedException'

    // Maintains proper stack trace for where error was thrown (V8 engines)
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, UnauthorizedException)
    }
  }
}

/**
 * Exception thrown when no user is authenticated
 * Typically caught in API error handlers and converted to a 401 response
 */
export class UnauthenticatedException extends Error {
  public readonly code = 'UNAUTHENTICATED'
  public readonly statusCode = 401

  constructor(message = 'Authentication required') {
    super(message)
    this.name = 'UnauthenticatedException'

    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, UnauthenticatedException)
    }
  }
}
