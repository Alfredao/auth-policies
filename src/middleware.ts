import type { AuthConfig, AuthorizeOptions, BaseUser, RolePermissions } from './types'
import {
  UnauthorizedException,
  UnauthenticatedException,
  AuthErrorCode,
  createErrorMessage,
} from './exceptions'
import { createAuth } from './create-auth'
import { resolvePermissions } from './permissions'

/**
 * Get all permissions for a user from their roles
 * Supports both single role and multiple roles
 */
function getUserPermissions<TRole extends string>(
  user: BaseUser<TRole>,
  rolePermissions: RolePermissions<TRole>
): string[] {
  const resolvedPerms = resolvePermissions(rolePermissions)
  const userRoles: TRole[] = []

  // Add single role if present
  if (user.role) {
    userRoles.push(user.role as TRole)
  }

  // Add multiple roles if present
  if (user.roles && Array.isArray(user.roles)) {
    for (const role of user.roles) {
      if (!userRoles.includes(role as TRole)) {
        userRoles.push(role as TRole)
      }
    }
  }

  // Merge permissions from all roles
  const permissions = new Set<string>()
  for (const role of userRoles) {
    const rolePerms = resolvedPerms[role]
    if (rolePerms) {
      for (const perm of rolePerms) {
        permissions.add(perm)
      }
    }
  }

  return [...permissions]
}

/**
 * Options for the withAuth wrapper
 */
export interface WithAuthOptions<TResourceType extends string = string> {
  /**
   * Required action to perform
   */
  action: string
  /**
   * Resource type to check
   */
  type: TResourceType
  /**
   * Function to extract resource from request for context-aware checks
   */
  getResource?: (req: Request) => Promise<unknown> | unknown
  /**
   * Custom error message
   */
  message?: string
}

/**
 * JSON error response structure
 */
export interface AuthErrorResponse {
  error: string
  message: string
  code: string
  statusCode: number
}

/**
 * Create a Next.js App Router API route wrapper that enforces authorization
 *
 * @example
 * ```typescript
 * // lib/authorization/index.ts
 * import { createAuthMiddleware } from '@alfredaoo/auth-policies/middleware'
 *
 * export const withAuth = createAuthMiddleware({
 *   rolePermissions,
 *   policies,
 *   getUser: async () => {
 *     const session = await getSession()
 *     return session?.user ?? null
 *   },
 * })
 *
 * // app/api/posts/[id]/route.ts
 * import { withAuth } from '@/lib/authorization'
 *
 * export const DELETE = withAuth(
 *   async (request, context) => {
 *     // User is authorized, handle the request
 *     await deletePost(context.params.id)
 *     return Response.json({ success: true })
 *   },
 *   { action: 'delete', type: 'Post' }
 * )
 * ```
 */
export function createAuthMiddleware<
  TUser extends BaseUser<TRole>,
  TRole extends string = string,
  TResourceType extends string = string
>(config: AuthConfig<TUser, TRole, TResourceType>) {
  const auth = createAuth(config)

  return function withAuth<TContext = unknown>(
    handler: (request: Request, context: TContext) => Promise<Response> | Response,
    options: WithAuthOptions<TResourceType>
  ): (request: Request, context: TContext) => Promise<Response> {
    return async (request: Request, context: TContext): Promise<Response> => {
      try {
        // Get resource if extractor provided
        const resource = options.getResource
          ? await options.getResource(request)
          : undefined

        // Check authorization
        await auth.canApi(options.action, options.type, {
          resource,
          message: options.message,
        })

        // User is authorized, call the handler
        return await handler(request, context)
      } catch (error) {
        if (error instanceof UnauthenticatedException) {
          return Response.json(
            {
              error: 'UnauthenticatedException',
              message: error.message,
              code: error.code,
              statusCode: 401,
            } satisfies AuthErrorResponse,
            { status: 401 }
          )
        }

        if (error instanceof UnauthorizedException) {
          return Response.json(
            {
              error: 'UnauthorizedException',
              message: error.message,
              code: error.code,
              statusCode: 403,
              ...(error.context && { context: error.context }),
            },
            { status: 403 }
          )
        }

        // Re-throw unknown errors
        throw error
      }
    }
  }
}

/**
 * Options for requiring specific permissions
 */
export interface RequirePermissionOptions {
  /**
   * Permission string to check (e.g., 'delete.post')
   */
  permission: string
  /**
   * Custom error message
   */
  message?: string
}

/**
 * Create a permission-based middleware (simpler than policy-based)
 *
 * @example
 * ```typescript
 * const requirePermission = createPermissionMiddleware({
 *   rolePermissions,
 *   getUser: async () => {
 *     const session = await getSession()
 *     return session?.user ?? null
 *   },
 * })
 *
 * export const DELETE = requirePermission(
 *   async (request) => {
 *     return Response.json({ success: true })
 *   },
 *   { permission: 'delete.post' }
 * )
 * ```
 */
export function createPermissionMiddleware<
  TUser extends BaseUser<TRole>,
  TRole extends string = string
>(config: {
  rolePermissions: Record<TRole, string[]>
  getUser: () => Promise<TUser | null>
}) {
  const { rolePermissions, getUser } = config

  return function requirePermission<TContext = unknown>(
    handler: (request: Request, context: TContext) => Promise<Response> | Response,
    options: RequirePermissionOptions
  ): (request: Request, context: TContext) => Promise<Response> {
    return async (request: Request, context: TContext): Promise<Response> => {
      const user = await getUser()

      if (!user) {
        return Response.json(
          {
            error: 'UnauthenticatedException',
            message: 'Authentication required',
            code: AuthErrorCode.UNAUTHENTICATED,
            statusCode: 401,
          } satisfies AuthErrorResponse,
          { status: 401 }
        )
      }

      const userPermissions = getUserPermissions(user, rolePermissions)
      const hasPermission = userPermissions.includes(options.permission)

      if (!hasPermission) {
        return Response.json(
          {
            error: 'UnauthorizedException',
            message: options.message ?? `Permission '${options.permission}' required`,
            code: AuthErrorCode.UNAUTHORIZED,
            statusCode: 403,
          } satisfies AuthErrorResponse,
          { status: 403 }
        )
      }

      return await handler(request, context)
    }
  }
}

/**
 * Express/Hono compatible middleware request type
 */
export interface MiddlewareRequest {
  user?: unknown
  [key: string]: unknown
}

/**
 * Express/Hono compatible middleware response type
 */
export interface MiddlewareResponse {
  status: (code: number) => MiddlewareResponse
  json: (body: unknown) => void
}

/**
 * Express/Hono compatible next function
 */
export type NextFunction = (error?: unknown) => void

/**
 * Express/Hono middleware handler
 */
export type ExpressMiddleware<TReq = MiddlewareRequest, TRes = MiddlewareResponse> = (
  req: TReq,
  res: TRes,
  next: NextFunction
) => void | Promise<void>

/**
 * Options for Express middleware
 */
export interface ExpressAuthMiddlewareOptions<TResourceType extends string = string> {
  /**
   * Action to check
   */
  action: string
  /**
   * Resource type to check
   */
  type: TResourceType
  /**
   * Function to extract resource from request
   */
  getResource?: (req: MiddlewareRequest) => Promise<unknown> | unknown
  /**
   * Custom error message
   */
  message?: string
}

/**
 * Create Express/Hono compatible middleware factory
 *
 * @example
 * ```typescript
 * // Express
 * import express from 'express'
 * import { createExpressAuth } from '@alfredaoo/auth-policies/middleware'
 *
 * const { protect, requireAuth } = createExpressAuth({
 *   rolePermissions,
 *   policies,
 *   getUser: async (req) => req.user,
 * })
 *
 * // Protect a route
 * app.delete('/posts/:id', protect({ action: 'delete', type: 'Post' }), (req, res) => {
 *   res.json({ success: true })
 * })
 *
 * // Just require authentication
 * app.get('/profile', requireAuth, (req, res) => {
 *   res.json(req.user)
 * })
 * ```
 */
export function createExpressAuth<
  TUser extends BaseUser<TRole>,
  TRole extends string = string,
  TResourceType extends string = string,
  TReq extends MiddlewareRequest = MiddlewareRequest,
  TRes extends MiddlewareResponse = MiddlewareResponse
>(config: {
  rolePermissions: Record<TRole, string[]>
  policies: AuthConfig<TUser, TRole, TResourceType>['policies']
  getUser: (req: TReq) => Promise<TUser | null> | TUser | null
}) {
  const { rolePermissions, policies, getUser } = config

  /**
   * Middleware that requires authentication only
   */
  const requireAuth: ExpressMiddleware<TReq, TRes> = async (req, res, next) => {
    try {
      const user = await getUser(req)

      if (!user) {
        res.status(401).json({
          error: 'UnauthenticatedException',
          message: 'Authentication required',
          code: AuthErrorCode.UNAUTHENTICATED,
          statusCode: 401,
        })
        return
      }

      // Attach user to request
      req.user = user
      next()
    } catch (error) {
      next(error)
    }
  }

  /**
   * Middleware factory that checks policy authorization
   */
  function protect(
    options: ExpressAuthMiddlewareOptions<TResourceType>
  ): ExpressMiddleware<TReq, TRes> {
    return async (req, res, next) => {
      try {
        const user = await getUser(req)

        if (!user) {
          res.status(401).json({
            error: 'UnauthenticatedException',
            message: 'Authentication required',
            code: AuthErrorCode.UNAUTHENTICATED,
            statusCode: 401,
          })
          return
        }

        // Attach user to request
        req.user = user

        const policy = policies[options.type]
        if (!policy) {
          res.status(500).json({
            error: 'PolicyConfigurationException',
            message: `Policy not found for resource type '${options.type}'`,
            code: AuthErrorCode.POLICY_NOT_FOUND,
            statusCode: 500,
          })
          return
        }

        const policyMethod = policy[options.action]
        if (!policyMethod) {
          res.status(500).json({
            error: 'PolicyConfigurationException',
            message: `Action '${options.action}' not found on ${options.type}`,
            code: AuthErrorCode.ACTION_NOT_FOUND,
            statusCode: 500,
          })
          return
        }

        const resource = options.getResource ? await options.getResource(req) : undefined
        const allowed = await policyMethod(user, resource)

        if (!allowed) {
          res.status(403).json({
            error: 'UnauthorizedException',
            message: options.message ?? createErrorMessage(options.action, options.type, user.role),
            code: AuthErrorCode.POLICY_DENIED,
            statusCode: 403,
          })
          return
        }

        next()
      } catch (error) {
        next(error)
      }
    }
  }

  /**
   * Middleware factory that checks a specific permission
   */
  function requirePermission(permission: string, message?: string): ExpressMiddleware<TReq, TRes> {
    return async (req, res, next) => {
      try {
        const user = await getUser(req)

        if (!user) {
          res.status(401).json({
            error: 'UnauthenticatedException',
            message: 'Authentication required',
            code: AuthErrorCode.UNAUTHENTICATED,
            statusCode: 401,
          })
          return
        }

        req.user = user

        const userPermissions = getUserPermissions(user, rolePermissions)
        const hasPermission = userPermissions.includes(permission)

        if (!hasPermission) {
          res.status(403).json({
            error: 'UnauthorizedException',
            message: message ?? `Permission '${permission}' required`,
            code: AuthErrorCode.UNAUTHORIZED,
            statusCode: 403,
          })
          return
        }

        next()
      } catch (error) {
        next(error)
      }
    }
  }

  return {
    requireAuth,
    protect,
    requirePermission,
  }
}
