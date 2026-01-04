import type { AuthConfig, AuthorizeOptions, BaseUser } from './types'
import { UnauthorizedException, UnauthenticatedException } from './exceptions'
import { createPermissionChecker } from './permissions'

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
  const { rolePermissions, policies, getUser, handlers } = config

  // Create permission utilities
  const permissionChecker = createPermissionChecker<TUser, TRole>(rolePermissions)

  /**
   * Get the current user, throwing if not authenticated
   */
  async function requireUser(): Promise<TUser> {
    const user = await getUser()
    if (!user) {
      throw new UnauthenticatedException()
    }
    return user
  }

  /**
   * Check if the current user can perform an action on a resource type
   * Returns true/false without throwing
   */
  async function checkPermission(
    action: string,
    type: TResourceType,
    options?: AuthorizeOptions
  ): Promise<boolean> {
    const user = await getUser()
    if (!user) return false

    const policy = policies[type]
    if (!policy) {
      console.warn(`No policy found for resource type: ${type}`)
      return false
    }

    const policyMethod = policy[action]
    if (!policyMethod) {
      console.warn(`No policy method found for action: ${action} on ${type}`)
      return false
    }

    try {
      return await policyMethod(user, options?.resource)
    } catch (error) {
      console.error(`Policy check error for ${action} on ${type}:`, error)
      return false
    }
  }

  /**
   * Core authorization function
   */
  async function authorize(
    action: string,
    type: TResourceType,
    options: AuthorizeOptions | undefined,
    onUnauthorized: (message: string) => never
  ): Promise<true> {
    const user = await getUser()
    if (!user) {
      throw new UnauthenticatedException()
    }

    const policy = policies[type]
    if (!policy) {
      throw new Error(`No policy found for resource type: ${type}`)
    }

    const policyMethod = policy[action]
    if (!policyMethod) {
      throw new Error(`No policy method found for action: ${action} on ${type}`)
    }

    const allowed = await policyMethod(user, options?.resource)
    if (!allowed) {
      const message = options?.message || 'You do not have permission to perform this action'
      onUnauthorized(message)
    }

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
   * ```
   */
  async function can(
    action: string,
    type: TResourceType,
    options?: AuthorizeOptions
  ): Promise<true> {
    return authorize(action, type, options, (message) => {
      if (handlers?.onUnauthorizedRedirect) {
        handlers.onUnauthorizedRedirect(message)
      }
      // Fallback: throw if no redirect handler
      throw new UnauthorizedException(message)
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
   * ```
   */
  async function canApi(
    action: string,
    type: TResourceType,
    options?: AuthorizeOptions
  ): Promise<true> {
    return authorize(action, type, options, (message) => {
      if (handlers?.onUnauthorizedThrow) {
        handlers.onUnauthorizedThrow(message)
      }
      throw new UnauthorizedException(message)
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

    // Access to config for debugging/testing
    config: {
      rolePermissions,
      policies,
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
