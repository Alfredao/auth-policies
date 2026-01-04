// Core
export { createAuth, type AuthInstance } from './create-auth'
export { createNextAuth } from './nextjs'

// Types
export type {
  BaseUser,
  RoleDefinition,
  RolePermissions,
  PolicyMethod,
  Policy,
  PolicyMap,
  AuthConfig,
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
  resolvePermissions,
  CircularInheritanceError,
} from './permissions'
export { createPolicyCache, PolicyCache } from './cache'
