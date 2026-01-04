import type { AuthConfig, AuthorizeOptions, BaseUser, AuditLogEntry } from './types'
import {
  UnauthorizedException,
  UnauthenticatedException,
  PolicyConfigurationException,
  AuthErrorCode,
  createErrorMessage,
} from './exceptions'
import { createPermissionChecker } from './permissions'
import { PolicyCache } from './cache'

/**
 * Create an authorization instance with the provided configuration
 *
 * @example
 * ```typescript
 * const auth = createAuth({
 *   rolePermissions: {
 *     ADMIN: ['view.user', 'create.user', 'update.user', 'delete.user'],
 *     OPERATOR: ['view.user'],
 *   },
 *   policies: {
 *     User: UserPolicy,
 *     Instance: InstancePolicy,
 *   },
 *   getUser: async () => {
 *     const session = await getSession()
 *     return session?.user ?? null
 *   },
 *   debug: process.env.NODE_ENV === 'development',
 * })
 *
 * // In API routes:
 * await auth.canApi('update', 'User', { resource: user })
 *
 * // In server components:
 * await auth.can('viewAll', 'User')
 * ```
 */
export function createAuth<
  TUser extends BaseUser<TRole>,
  TRole extends string = string,
  TResourceType extends string = string
>(config: AuthConfig<TUser, TRole, TResourceType>) {
  const { rolePermissions, policies, getUser, handlers, debug = false, onAudit, cache: cacheConfig } = config

  // Create permission utilities
  const permissionChecker = createPermissionChecker<TUser, TRole>(rolePermissions)

  // Create cache if enabled
  const cache = cacheConfig?.enabled ? new PolicyCache(cacheConfig) : null

  /**
   * Debug logger - only logs when debug mode is enabled
   */
  function debugLog(message: string, data?: Record<string, unknown>): void {
    if (debug) {
      console.log(`[auth-policies] ${message}`, data ?? '')
    }
  }

  /**
   * Audit logger - calls the onAudit callback if provided
   */
  async function audit(
    entry: Omit<AuditLogEntry<TUser, TResourceType>, 'timestamp'>
  ): Promise<void> {
    if (onAudit) {
      try {
        await onAudit({
          ...entry,
          timestamp: new Date(),
        })
      } catch (error) {
        // Don't let audit errors break the authorization flow
        console.error('[auth-policies] Audit logger error:', error)
      }
    }
  }

  /**
   * Get the current user, throwing if not authenticated
   */
  async function requireUser(): Promise<TUser> {
    const user = await getUser()
    if (!user) {
      debugLog('requireUser failed: No authenticated user')
      throw new UnauthenticatedException()
    }
    debugLog('requireUser success', { userId: user.id, role: user.role })
    return user
  }

  /**
   * Check if the current user can perform an action on a resource type
   * Returns true/false without throwing
   */
  async function checkPermission(
    action: string,
    type: TResourceType,
    options?: AuthorizeOptions & { metadata?: Record<string, unknown> }
  ): Promise<boolean> {
    const startTime = Date.now()
    const user = await getUser()

    if (!user) {
      debugLog('checkPermission denied: No authenticated user', { action, type })
      await audit({
        user: null,
        action,
        resourceType: type,
        allowed: false,
        reason: 'unauthenticated',
        resource: options?.resource,
        duration: Date.now() - startTime,
        metadata: options?.metadata,
      })
      return false
    }

    const policy = policies[type]
    if (!policy) {
      debugLog('checkPermission failed: Policy not found', { action, type })
      console.warn(
        `[auth-policies] No policy found for resource type: ${type}. ` +
          `Available types: ${Object.keys(policies).join(', ') || 'none'}`
      )
      await audit({
        user,
        action,
        resourceType: type,
        allowed: false,
        reason: 'policy_not_found',
        resource: options?.resource,
        duration: Date.now() - startTime,
        metadata: options?.metadata,
      })
      return false
    }

    const policyMethod = policy[action]
    if (!policyMethod) {
      debugLog('checkPermission failed: Action not found', { action, type })
      console.warn(
        `[auth-policies] No policy method '${action}' on ${type}. ` +
          `Available actions: ${Object.keys(policy).join(', ') || 'none'}`
      )
      await audit({
        user,
        action,
        resourceType: type,
        allowed: false,
        reason: 'action_not_found',
        resource: options?.resource,
        duration: Date.now() - startTime,
        metadata: options?.metadata,
      })
      return false
    }

    try {
      // Check cache first
      const cacheKey = cache?.generateKey(action, type, user.id, options?.resource)
      if (cache && cacheKey) {
        const cachedResult = cache.get(cacheKey)
        if (cachedResult !== undefined) {
          debugLog('checkPermission cache hit', {
            action,
            type,
            userId: user.id,
            allowed: cachedResult,
          })
          await audit({
            user,
            action,
            resourceType: type,
            allowed: cachedResult,
            reason: cachedResult ? undefined : 'policy_denied',
            resource: options?.resource,
            duration: Date.now() - startTime,
            metadata: { ...options?.metadata, cached: true },
          })
          return cachedResult
        }
      }

      const result = await policyMethod(user, options?.resource)

      // Cache the result
      if (cache && cacheKey) {
        cache.set(cacheKey, result)
        debugLog('checkPermission cache set', { cacheKey, result })
      }

      debugLog('checkPermission result', {
        action,
        type,
        userId: user.id,
        role: user.role,
        allowed: result,
      })
      await audit({
        user,
        action,
        resourceType: type,
        allowed: result,
        reason: result ? undefined : 'policy_denied',
        resource: options?.resource,
        duration: Date.now() - startTime,
        metadata: options?.metadata,
      })
      return result
    } catch (error) {
      console.error(
        `[auth-policies] Policy check error for ${action} on ${type}:`,
        error instanceof Error ? error.message : error
      )
      debugLog('checkPermission error', {
        action,
        type,
        error: error instanceof Error ? error.message : String(error),
      })
      await audit({
        user,
        action,
        resourceType: type,
        allowed: false,
        reason: 'policy_denied',
        resource: options?.resource,
        duration: Date.now() - startTime,
        metadata: {
          ...options?.metadata,
          error: error instanceof Error ? error.message : String(error),
        },
      })
      return false
    }
  }

  /**
   * Core authorization function
   */
  async function authorize(
    action: string,
    type: TResourceType,
    options: (AuthorizeOptions & { metadata?: Record<string, unknown> }) | undefined,
    onUnauthorized: (error: UnauthorizedException) => never
  ): Promise<true> {
    const startTime = Date.now()
    const user = await getUser()

    if (!user) {
      debugLog('authorize failed: No authenticated user', { action, type })
      await audit({
        user: null,
        action,
        resourceType: type,
        allowed: false,
        reason: 'unauthenticated',
        resource: options?.resource,
        duration: Date.now() - startTime,
        metadata: options?.metadata,
      })
      throw new UnauthenticatedException(
        'You must be logged in to perform this action'
      )
    }

    const policy = policies[type]
    if (!policy) {
      const availableTypes = Object.keys(policies).join(', ') || 'none'
      const message = `Policy not found for resource type '${type}'. Available types: ${availableTypes}`
      debugLog('authorize failed: Policy not found', { action, type, availableTypes })
      await audit({
        user,
        action,
        resourceType: type,
        allowed: false,
        reason: 'policy_not_found',
        resource: options?.resource,
        duration: Date.now() - startTime,
        metadata: options?.metadata,
      })
      throw new PolicyConfigurationException(message, AuthErrorCode.POLICY_NOT_FOUND, {
        action,
        resourceType: type,
        details: { availableTypes: Object.keys(policies) },
      })
    }

    const policyMethod = policy[action]
    if (!policyMethod) {
      const availableActions = Object.keys(policy).join(', ') || 'none'
      const message = `Action '${action}' not found on ${type}. Available actions: ${availableActions}`
      debugLog('authorize failed: Action not found', { action, type, availableActions })
      await audit({
        user,
        action,
        resourceType: type,
        allowed: false,
        reason: 'action_not_found',
        resource: options?.resource,
        duration: Date.now() - startTime,
        metadata: options?.metadata,
      })
      throw new PolicyConfigurationException(message, AuthErrorCode.ACTION_NOT_FOUND, {
        action,
        resourceType: type,
        details: { availableActions: Object.keys(policy) },
      })
    }

    // Check cache first
    const cacheKey = cache?.generateKey(action, type, user.id, options?.resource)
    let allowed: boolean
    let fromCache = false

    if (cache && cacheKey) {
      const cachedResult = cache.get(cacheKey)
      if (cachedResult !== undefined) {
        debugLog('authorize cache hit', {
          action,
          type,
          userId: user.id,
          allowed: cachedResult,
        })
        allowed = cachedResult
        fromCache = true
      } else {
        allowed = await policyMethod(user, options?.resource)
        cache.set(cacheKey, allowed)
        debugLog('authorize cache set', { cacheKey, allowed })
      }
    } else {
      allowed = await policyMethod(user, options?.resource)
    }

    if (!allowed) {
      const message = options?.message || createErrorMessage(action, type, user.role)
      debugLog('authorize denied', {
        action,
        type,
        userId: user.id,
        role: user.role,
      })

      await audit({
        user,
        action,
        resourceType: type,
        allowed: false,
        reason: 'policy_denied',
        resource: options?.resource,
        duration: Date.now() - startTime,
        metadata: { ...options?.metadata, cached: fromCache },
      })

      const error = new UnauthorizedException(message, AuthErrorCode.POLICY_DENIED, {
        action,
        resourceType: type,
        role: user.role,
        userId: user.id,
      })

      onUnauthorized(error)
    }

    debugLog('authorize success', {
      action,
      type,
      userId: user.id,
      role: user.role,
    })

    await audit({
      user,
      action,
      resourceType: type,
      allowed: true,
      resource: options?.resource,
      duration: Date.now() - startTime,
      metadata: { ...options?.metadata, cached: fromCache },
    })

    return true
  }

  /**
   * Authorization check for Server Components and Pages
   * Redirects to /unauthorized (or custom handler) if the policy check fails
   *
   * @example
   * ```typescript
   * // In a server component
   * await auth.can('viewAll', 'User')
   *
   * // With metadata for audit logging
   * await auth.can('delete', 'Post', {
   *   resource: post,
   *   metadata: { ip: request.ip, userAgent: request.headers['user-agent'] }
   * })
   * ```
   */
  async function can(
    action: string,
    type: TResourceType,
    options?: AuthorizeOptions & { metadata?: Record<string, unknown> }
  ): Promise<true> {
    return authorize(action, type, options, (error) => {
      if (handlers?.onUnauthorizedRedirect) {
        handlers.onUnauthorizedRedirect(error.message)
      }
      // Fallback: throw if no redirect handler
      throw error
    })
  }

  /**
   * Authorization check for API Routes
   * Throws UnauthorizedException if the policy check fails
   *
   * @example
   * ```typescript
   * // In an API route
   * await auth.canApi('update', 'User', { resource: existingUser })
   *
   * // With metadata for audit logging
   * await auth.canApi('delete', 'Post', {
   *   resource: post,
   *   metadata: { ip: request.ip }
   * })
   * ```
   */
  async function canApi(
    action: string,
    type: TResourceType,
    options?: AuthorizeOptions & { metadata?: Record<string, unknown> }
  ): Promise<true> {
    return authorize(action, type, options, (error) => {
      if (handlers?.onUnauthorizedThrow) {
        handlers.onUnauthorizedThrow(error.message)
      }
      throw error
    })
  }

  return {
    // Core authorization
    can,
    canApi,
    checkPermission,

    // User utilities
    getUser,
    requireUser,

    // Permission utilities (bound to config)
    hasPermission: (user: TUser, permission: string) =>
      permissionChecker.hasPermission(user, permission),
    hasAnyPermission: (user: TUser, permissions: string[]) =>
      permissionChecker.hasAnyPermission(user, permissions),
    hasAllPermissions: (user: TUser, permissions: string[]) =>
      permissionChecker.hasAllPermissions(user, permissions),
    getPermissions: (user: TUser) => permissionChecker.getPermissions(user),

    // Access to the permission checker for advanced use cases
    permissionChecker,

    // Cache utilities (only available when caching is enabled)
    cache: cache
      ? {
          /**
           * Invalidate all cached entries for a specific user
           */
          invalidateUser: (userId: string) => cache.invalidateUser(userId),

          /**
           * Invalidate all cached entries for a specific resource type
           */
          invalidateResourceType: (resourceType: string) =>
            cache.invalidateResourceType(resourceType),

          /**
           * Invalidate all cached entries for a specific resource
           */
          invalidateResource: (resourceType: string, resourceId: string) =>
            cache.invalidateResource(resourceType, resourceId),

          /**
           * Clear all cached entries
           */
          clear: () => cache.clear(),

          /**
           * Get cache statistics
           */
          stats: () => cache.stats(),

          /**
           * Clean up expired entries (call periodically in long-running processes)
           */
          cleanup: () => cache.cleanup(),
        }
      : null,

    // Access to config for debugging/testing
    config: {
      rolePermissions,
      policies,
      debug,
      cacheEnabled: !!cache,
    },
  }
}

/**
 * Type helper to infer the return type of createAuth
 */
export type AuthInstance<
  TUser extends BaseUser<TRole>,
  TRole extends string = string,
  TResourceType extends string = string
> = ReturnType<typeof createAuth<TUser, TRole, TResourceType>>
