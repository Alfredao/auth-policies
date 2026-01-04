// Core
export { createAuth, type AuthInstance } from './create-auth'
export { createNextAuth } from './nextjs'

// Types
export type {
  BaseUser,
  PolicyMethod,
  Policy,
  PolicyMap,
  AuthConfig,
  AuthorizeOptions,
  PermissionCheckResult,
} from './types'

// Exceptions
export { UnauthorizedException, UnauthenticatedException } from './exceptions'

// Utilities
export { createPermissionChecker } from './permissions'
