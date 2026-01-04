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

  /**
   * Enable debug mode for verbose logging
   * When true, logs detailed authorization checks to console
   * @default false
   */
  debug?: boolean

  /**
   * Audit logger callback - called on every authorization check
   * Use this to log authorization decisions to your logging system
   *
   * @example
   * ```typescript
   * const auth = createAuth({
   *   // ...
   *   onAudit: async (entry) => {
   *     await logger.info('Authorization check', entry)
   *   },
   * })
   * ```
   */
  onAudit?: AuditLogger<TUser, TResourceType>
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

/**
 * Audit log entry for authorization checks
 */
export interface AuditLogEntry<
  TUser extends BaseUser = BaseUser,
  TResourceType extends string = string
> {
  /**
   * Timestamp of the authorization check
   */
  timestamp: Date

  /**
   * The user who made the request (null if unauthenticated)
   */
  user: TUser | null

  /**
   * The action being performed
   */
  action: string

  /**
   * The resource type being accessed
   */
  resourceType: TResourceType

  /**
   * Whether the action was allowed
   */
  allowed: boolean

  /**
   * The reason for denial (if applicable)
   */
  reason?: 'unauthenticated' | 'policy_denied' | 'policy_not_found' | 'action_not_found'

  /**
   * The resource being accessed (if provided)
   */
  resource?: unknown

  /**
   * Duration of the policy check in milliseconds
   */
  duration: number

  /**
   * Additional metadata
   */
  metadata?: Record<string, unknown>
}

/**
 * Callback function for audit logging
 */
export type AuditLogger<
  TUser extends BaseUser = BaseUser,
  TResourceType extends string = string
> = (entry: AuditLogEntry<TUser, TResourceType>) => void | Promise<void>
