/**
 * Base user type that applications must extend
 */
export interface BaseUser<TRole extends string = string> {
  id: string
  role: TRole
}

/**
 * Policy method signature - takes the user and optionally a resource
 */
export type PolicyMethod<TUser extends BaseUser = BaseUser> = (
  user: TUser,
  resource?: unknown
) => Promise<boolean> | boolean

/**
 * A policy is a collection of authorization methods for a resource type
 */
export type Policy<TUser extends BaseUser = BaseUser> = {
  [action: string]: PolicyMethod<TUser>
}

/**
 * Policy map - registry of all policies for each resource type
 */
export type PolicyMap<
  TUser extends BaseUser = BaseUser,
  TResourceType extends string = string
> = {
  [K in TResourceType]?: Policy<TUser>
}

/**
 * Configuration for creating an authorization instance
 */
export interface AuthConfig<
  TUser extends BaseUser = BaseUser,
  TRole extends string = string,
  TResourceType extends string = string
> {
  /**
   * Map of roles to their permissions
   * Example: { ADMIN: ['view.user', 'create.user'], OPERATOR: ['view.user'] }
   */
  rolePermissions: Record<TRole, string[]>

  /**
   * Map of resource types to their policies
   */
  policies: PolicyMap<TUser, TResourceType>

  /**
   * Function to get the current authenticated user
   * This is called on every authorization check
   */
  getUser: () => Promise<TUser | null>

  /**
   * Optional handlers for unauthorized access
   */
  handlers?: {
    /**
     * Handler for server components - should redirect
     */
    onUnauthorizedRedirect?: (message: string) => never

    /**
     * Handler for API routes - should throw
     * If not provided, UnauthorizedException is thrown
     */
    onUnauthorizedThrow?: (message: string) => never
  }
}

/**
 * Options for authorization checks
 */
export interface AuthorizeOptions {
  /**
   * The resource being accessed (for context-aware checks)
   */
  resource?: unknown

  /**
   * Custom error message
   */
  message?: string
}

/**
 * Result of a permission check
 */
export interface PermissionCheckResult {
  allowed: boolean
  reason?: string
}
