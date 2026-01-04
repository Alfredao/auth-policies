import type { AuthConfig, AuthorizeOptions, BaseUser, AuditLogEntry, TenantUser } from './types'
import {
  UnauthorizedException,
  UnauthenticatedException,
  PolicyConfigurationException,
  AuthErrorCode,
  createErrorMessage,
} from './exceptions'
import { createPermissionChecker, createTenantPermissionChecker, getTenantRoles } from './permissions'
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
  const {
    rolePermissions,
    policies,
    getUser,
    handlers,
    debug = false,
    onAudit,
    cache: cacheConfig,
    tenant: tenantConfig,
  } = config

  // Create permission utilities
  const permissionChecker = createPermissionChecker<TUser, TRole>(rolePermissions)

  // Create tenant permission checker if tenant config is provided
  // Note: Tenant role permissions use the same TRole type constraint for simplicity
  const tenantPermissionChecker = tenantConfig
    ? createTenantPermissionChecker<TRole, TRole>({
        systemRolePermissions: rolePermissions,
        tenantRolePermissions: tenantConfig.rolePermissions,
      })
    : null

  // Create cache if enabled
  const cache = cacheConfig?.enabled ? new PolicyCache(cacheConfig) : null

  /**
   * Get the current tenant ID from config or options
   */
  async function resolveTenantId(optionsTenantId?: string): Promise<string | null> {
    if (optionsTenantId !== undefined) {
      return optionsTenantId
    }
    if (tenantConfig?.getTenantId) {
      return await tenantConfig.getTenantId()
    }
    return null
  }

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
    const tenantId = await resolveTenantId(options?.tenantId)

    if (!user) {
      debugLog('checkPermission denied: No authenticated user', { action, type, tenantId })
      await audit({
        user: null,
        action,
        resourceType: type,
        allowed: false,
        reason: 'unauthenticated',
        resource: options?.resource,
        tenantId,
        duration: Date.now() - startTime,
        metadata: options?.metadata,
      })
      return false
    }

    const policy = policies[type]
    if (!policy) {
      debugLog('checkPermission failed: Policy not found', { action, type, tenantId })
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
        tenantId,
        duration: Date.now() - startTime,
        metadata: options?.metadata,
      })
      return false
    }

    const policyMethod = policy[action]
    if (!policyMethod) {
      debugLog('checkPermission failed: Action not found', { action, type, tenantId })
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
        tenantId,
        duration: Date.now() - startTime,
        metadata: options?.metadata,
      })
      return false
    }

    try {
      // Check cache first (include tenantId in cache key)
      const cacheKey = cache?.generateKey(action, type, user.id, options?.resource, tenantId)
      if (cache && cacheKey) {
        const cachedResult = cache.get(cacheKey)
        if (cachedResult !== undefined) {
          debugLog('checkPermission cache hit', {
            action,
            type,
            userId: user.id,
            tenantId,
            allowed: cachedResult,
          })
          await audit({
            user,
            action,
            resourceType: type,
            allowed: cachedResult,
            reason: cachedResult ? undefined : 'policy_denied',
            resource: options?.resource,
            tenantId,
            duration: Date.now() - startTime,
            metadata: { ...options?.metadata, cached: true },
          })
          return cachedResult
        }
      }

      // Pass tenantId to policy method for tenant-aware checks
      const result = await policyMethod(user, options?.resource, tenantId)

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
        tenantId,
        allowed: result,
      })
      await audit({
        user,
        action,
        resourceType: type,
        allowed: result,
        reason: result ? undefined : 'policy_denied',
        resource: options?.resource,
        tenantId,
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
        tenantId,
        error: error instanceof Error ? error.message : String(error),
      })
      await audit({
        user,
        action,
        resourceType: type,
        allowed: false,
        reason: 'policy_denied',
        resource: options?.resource,
        tenantId,
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
    const tenantId = await resolveTenantId(options?.tenantId)

    if (!user) {
      debugLog('authorize failed: No authenticated user', { action, type, tenantId })
      await audit({
        user: null,
        action,
        resourceType: type,
        allowed: false,
        reason: 'unauthenticated',
        resource: options?.resource,
        tenantId,
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
      debugLog('authorize failed: Policy not found', { action, type, tenantId, availableTypes })
      await audit({
        user,
        action,
        resourceType: type,
        allowed: false,
        reason: 'policy_not_found',
        resource: options?.resource,
        tenantId,
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
      debugLog('authorize failed: Action not found', { action, type, tenantId, availableActions })
      await audit({
        user,
        action,
        resourceType: type,
        allowed: false,
        reason: 'action_not_found',
        resource: options?.resource,
        tenantId,
        duration: Date.now() - startTime,
        metadata: options?.metadata,
      })
      throw new PolicyConfigurationException(message, AuthErrorCode.ACTION_NOT_FOUND, {
        action,
        resourceType: type,
        details: { availableActions: Object.keys(policy) },
      })
    }

    // Check cache first (include tenantId in cache key)
    const cacheKey = cache?.generateKey(action, type, user.id, options?.resource, tenantId)
    let allowed: boolean
    let fromCache = false

    if (cache && cacheKey) {
      const cachedResult = cache.get(cacheKey)
      if (cachedResult !== undefined) {
        debugLog('authorize cache hit', {
          action,
          type,
          userId: user.id,
          tenantId,
          allowed: cachedResult,
        })
        allowed = cachedResult
        fromCache = true
      } else {
        // Pass tenantId to policy method for tenant-aware checks
        allowed = await policyMethod(user, options?.resource, tenantId)
        cache.set(cacheKey, allowed)
        debugLog('authorize cache set', { cacheKey, allowed })
      }
    } else {
      // Pass tenantId to policy method for tenant-aware checks
      allowed = await policyMethod(user, options?.resource, tenantId)
    }

    if (!allowed) {
      const message = options?.message || createErrorMessage(action, type, user.role)
      debugLog('authorize denied', {
        action,
        type,
        userId: user.id,
        role: user.role,
        tenantId,
      })

      await audit({
        user,
        action,
        resourceType: type,
        allowed: false,
        reason: 'policy_denied',
        resource: options?.resource,
        tenantId,
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
      tenantId,
    })

    await audit({
      user,
      action,
      resourceType: type,
      allowed: true,
      resource: options?.resource,
      tenantId,
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
    getRoles: (user: TUser) => permissionChecker.getRoles(user),

    // Access to the permission checker for advanced use cases
    permissionChecker,

    // Tenant utilities (only available when tenant config is provided)
    tenant: tenantPermissionChecker
      ? {
          /**
           * Get tenant ID from config or resolve it
           */
          getTenantId: resolveTenantId,

          /**
           * Get tenant roles for a user in a specific tenant
           */
          getTenantRoles: (user: TUser, tenantId: string) =>
            getTenantRoles(user as TenantUser<TRole, TRole>, tenantId),

          /**
           * Get all permissions for a user (system + tenant)
           */
          getPermissions: (user: TUser, tenantId: string | null) =>
            tenantPermissionChecker.getPermissions(user as TenantUser<TRole, TRole>, tenantId),

          /**
           * Check if user has a permission (system or tenant level)
           */
          hasPermission: (user: TUser, permission: string, tenantId: string | null) =>
            tenantPermissionChecker.hasPermission(user as TenantUser<TRole, TRole>, permission, tenantId),

          /**
           * Get roles for a user (system + tenant)
           */
          getRoles: (user: TUser, tenantId: string | null) =>
            tenantPermissionChecker.getRoles(user as TenantUser<TRole, TRole>, tenantId),

          /**
           * Access to the full tenant permission checker
           */
          permissionChecker: tenantPermissionChecker,
        }
      : null,

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
           * Invalidate all cached entries for a specific tenant
           */
          invalidateTenant: (tenantId: string) => cache.invalidateTenant(tenantId),

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
      tenantEnabled: !!tenantConfig,
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
