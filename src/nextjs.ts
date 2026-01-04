/**
 * Next.js specific utilities for auth-policies
 *
 * These helpers make it easy to integrate with Next.js applications
 */

import type { AuthConfig, BaseUser } from './types'
import { createAuth } from './create-auth'

/**
 * Create an authorization instance configured for Next.js
 * Automatically sets up redirect handling for server components
 *
 * @example
 * ```typescript
 * // lib/authorization/index.ts
 * import { createNextAuth } from '@alfredao/auth-policies/nextjs'
 * import { redirect } from 'next/navigation'
 *
 * export const auth = createNextAuth({
 *   rolePermissions: { ... },
 *   policies: { ... },
 *   getUser: async () => { ... },
 *   redirectTo: '/unauthorized',
 * })
 * ```
 */
export function createNextAuth<
  TUser extends BaseUser<TRole>,
  TRole extends string = string,
  TResourceType extends string = string
>(
  config: Omit<AuthConfig<TUser, TRole, TResourceType>, 'handlers'> & {
    /**
     * Path to redirect to when unauthorized (used in server components)
     * @default '/unauthorized'
     */
    redirectTo?: string

    /**
     * Next.js redirect function (import from 'next/navigation')
     * Required for redirect functionality in server components
     */
    redirect?: (url: string) => never
  }
) {
  const { redirectTo = '/unauthorized', redirect: nextRedirect, ...baseConfig } = config

  return createAuth<TUser, TRole, TResourceType>({
    ...baseConfig,
    handlers: {
      onUnauthorizedRedirect: nextRedirect
        ? (message) => nextRedirect(redirectTo)
        : undefined,
    },
  })
}
