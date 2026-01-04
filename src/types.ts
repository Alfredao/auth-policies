/**
 * Base user type that applications must extend
 *
 * Supports both single role and multiple roles:
 *
 * @example
 * ```typescript
 * // Single role (simple)
 * interface User extends BaseUser<'ADMIN' | 'USER'> {
 *   id: string
 *   role: 'ADMIN' | 'USER'
 * }
 *
 * // Multiple roles
 * interface User extends BaseUser<'VIEWER' | 'EDITOR' | 'BILLING'> {
 *   id: string
 *   roles: ('VIEWER' | 'EDITOR' | 'BILLING')[]
 * }
 *
 * // Both (role as primary, roles as additional)
 * interface User extends BaseUser<Role> {
 *   id: string
 *   role: Role
 *   roles?: Role[]
 * }
 * ```
 */
export interface BaseUser<TRole extends string = string> {
  id: string
  /**
   * Single role (for simple use cases)
   * If both role and roles are provided, they are combined
   */
  role?: TRole
  /**
   * Multiple roles (for complex use cases)
   * Permissions from all roles are merged
   */
  roles?: TRole[]
}

/**
 * Multi-tenant user type that extends BaseUser with tenant-specific roles
 *
 * @example
 * ```typescript
 * // User with system role and per-tenant roles
 * interface User extends TenantUser<
 *   'SUPER_ADMIN' | 'USER',           // System roles
 *   'OWNER' | 'ADMIN' | 'MEMBER',     // Tenant roles
 *   string                             // Tenant ID type
 * > {
 *   id: string
 *   role: 'SUPER_ADMIN' | 'USER'
 *   tenantRoles: {
 *     [businessId: string]: 'OWNER' | 'ADMIN' | 'MEMBER'
 *   }
 * }
 *
 * // Example user
 * const user: User = {
 *   id: '1',
 *   role: 'USER',
 *   tenantRoles: {
 *     'business-1': 'OWNER',
 *     'business-2': 'MEMBER',
 *   },
 * }
 * ```
 */
export interface TenantUser<
  TSystemRole extends string = string,
  TTenantRole extends string = string,
  TTenantId extends string | number = string
> extends BaseUser<TSystemRole> {
  /**
   * Tenant-specific roles - maps tenant IDs to roles within that tenant
   * A user can have different roles in different tenants
   */
  tenantRoles?: Record<TTenantId & string, TTenantRole | TTenantRole[]>
}

/**
 * Role definition with inheritance support
 *
 * @example
 * ```typescript
 * // Simple array of permissions
 * const simpleRole: RoleDefinition = ['view.user', 'create.user']
 *
 * // With inheritance from a single role
 * const adminRole: RoleDefinition<'OPERATOR'> = {
 *   inherits: 'OPERATOR',
 *   permissions: ['delete.user'],
 * }
 *
 * // With inheritance from multiple roles
 * const superAdmin: RoleDefinition<'ADMIN' | 'BILLING'> = {
 *   inherits: ['ADMIN', 'BILLING'],
 *   permissions: ['manage.system'],
 * }
 * ```
 */
export type RoleDefinition<TRole extends string = string> =
  | string[]
  | {
      /**
       * Role(s) to inherit permissions from
       */
      inherits: TRole | TRole[]
      /**
       * Additional permissions for this role
       */
      permissions: string[]
    }

/**
 * Role permissions configuration supporting both flat and hierarchical definitions
 *
 * @example
 * ```typescript
 * const rolePermissions: RolePermissions<'VIEWER' | 'ADMIN'> = {
 *   VIEWER: ['view.user', 'view.post'],
 *   ADMIN: {
 *     inherits: 'VIEWER',
 *     permissions: ['create.user', 'delete.user'],
 *   },
 * }
 * ```
 */
export type RolePermissions<TRole extends string = string> = Record<
  TRole,
  RoleDefinition<TRole>
>

/**
 * Cache configuration options for memoizing policy results
 */
export interface CacheConfig {
  /**
   * Enable or disable caching
   * @default false
   */
  enabled?: boolean

  /**
   * Time-to-live in milliseconds
   * Set to 0 for no expiration (not recommended for long-running processes)
   * @default 60000 (1 minute)
   */
  ttl?: number

  /**
   * Maximum number of entries in the cache
   * Uses LRU eviction when exceeded
   * @default 1000
   */
  maxSize?: number

  /**
   * Custom function to generate a cache key for a resource
   * By default, uses resource.id if available
   */
  getResourceKey?: (resource: unknown) => string | undefined
}

/**
 * Policy method signature - takes the user, optionally a resource, and optionally a tenant ID
 *
 * @example
 * ```typescript
 * // Simple policy
 * const view: PolicyMethod<User> = (user) => user.role === 'ADMIN'
 *
 * // Resource-aware policy
 * const update: PolicyMethod<User> = (user, resource) =>
 *   user.role === 'ADMIN' || resource?.ownerId === user.id
 *
 * // Tenant-aware policy
 * const manage: PolicyMethod<User> = (user, resource, tenantId) =>
 *   getTenantRoles(user, tenantId).includes('OWNER')
 * ```
 */
export type PolicyMethod<TUser extends BaseUser = BaseUser> = (
  user: TUser,
  resource?: unknown,
  tenantId?: string | null
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
   * Map of roles to their permissions (supports inheritance)
   *
   * @example
   * ```typescript
   * // Flat permissions
   * rolePermissions: {
   *   ADMIN: ['view.user', 'create.user'],
   *   OPERATOR: ['view.user'],
   * }
   *
   * // With inheritance
   * rolePermissions: {
   *   VIEWER: ['view.user'],
   *   ADMIN: { inherits: 'VIEWER', permissions: ['create.user', 'delete.user'] },
   * }
   * ```
   */
  rolePermissions: RolePermissions<TRole>

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

  /**
   * Cache configuration for memoizing policy results
   * When enabled, policy check results are cached to improve performance
   *
   * @example
   * ```typescript
   * const auth = createAuth({
   *   // ...
   *   cache: {
   *     enabled: true,
   *     ttl: 30000, // 30 seconds
   *     maxSize: 500,
   *   },
   * })
   * ```
   */
  cache?: CacheConfig

  /**
   * Multi-tenancy configuration
   * When provided, enables tenant-scoped permission checking
   *
   * @example
   * ```typescript
   * const auth = createAuth({
   *   rolePermissions: systemRolePermissions,
   *   policies,
   *   getUser,
   *   tenant: {
   *     rolePermissions: tenantRolePermissions,
   *     getTenantId: async () => {
   *       const session = await getSession()
   *       return session?.activeTenantId ?? null
   *     },
   *   },
   * })
   * ```
   */
  tenant?: TenantConfig<TRole>
}

/**
 * Multi-tenancy configuration
 */
export interface TenantConfig<TTenantRole extends string = string> {
  /**
   * Tenant-level role permissions
   * These apply only within the context of a specific tenant
   */
  rolePermissions: RolePermissions<TTenantRole>

  /**
   * Function to get the current tenant ID from context
   * Returns null if no tenant context is active
   */
  getTenantId: () => Promise<string | null> | string | null
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

  /**
   * Override the tenant ID for this specific check
   * If not provided, uses getTenantId() from tenant config
   */
  tenantId?: string
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
   * The tenant ID context (if multi-tenancy is enabled)
   */
  tenantId?: string | null

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
