// Core
export { createAuth, type AuthInstance } from './create-auth'
export { createNextAuth } from './nextjs'

// Types
export type {
  BaseUser,
  TenantUser,
  RoleDefinition,
  RolePermissions,
  PolicyMethod,
  Policy,
  PolicyMap,
  AuthConfig,
  TenantConfig,
  AuthorizeOptions,
  PermissionCheckResult,
  AuditLogEntry,
  AuditLogger,
  CacheConfig,
} from './types'

// Exceptions
export {
  UnauthorizedException,
  UnauthenticatedException,
  PolicyConfigurationException,
  AuthErrorCode,
  createErrorMessage,
  type AuthErrorContext,
  type AuthErrorCodeType,
} from './exceptions'

// Utilities
export {
  createPermissionChecker,
  createTenantPermissionChecker,
  resolvePermissions,
  getTenantRoles,
  CircularInheritanceError,
} from './permissions'
export { createPolicyCache, PolicyCache } from './cache'
