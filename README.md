# @alfredaoo/auth-policies

A flexible, framework-agnostic authorization library with policy-based access control (RBAC).

## Features

- **Policy-based authorization** - Define granular access rules per resource type
- **Role-permission mapping** - Simple role to permissions configuration
- **Context-aware checks** - Pass resources for dynamic authorization decisions
- **Framework-agnostic** - Works with any Node.js application
- **React hooks** - `useAuth`, `usePermission`, `<Can>` components for React apps
- **Next.js integration** - Built-in helpers for Next.js applications
- **TypeScript-first** - Full type safety and IntelliSense support
- **Lightweight** - Zero dependencies, ~5KB minified

## Installation

```bash
npm install @alfredaoo/auth-policies
# or
pnpm add @alfredaoo/auth-policies
# or
yarn add @alfredaoo/auth-policies
```

## Quick Start

### 1. Define your roles and permissions

```typescript
// lib/authorization/role-permissions.ts
export const rolePermissions = {
  SUPER_ADMIN: [
    'view.user', 'viewAll.user', 'create.user', 'update.user', 'delete.user',
    'view.instance', 'viewAll.instance', 'create.instance', 'update.instance', 'delete.instance',
  ],
  ADMIN: [
    'view.instance', 'viewAll.instance', 'create.instance', 'update.instance', 'delete.instance',
  ],
  OPERATOR: [
    'view.instance', 'viewAll.instance',
  ],
} as const

export type Role = keyof typeof rolePermissions
export type Permission = (typeof rolePermissions)[Role][number]
```

### 2. Define your user type

```typescript
// lib/authorization/types.ts
import type { BaseUser } from '@alfredao/auth-policies'
import type { Role } from './role-permissions'

export interface AuthorizedUser extends BaseUser<Role> {
  id: string
  role: Role
  email: string
  name: string
}
```

### 3. Create policies for your resources

```typescript
// lib/policies/user-policy.ts
import type { AuthorizedUser } from '../authorization/types'
import { hasPermission } from '../authorization'

export const UserPolicy = {
  async view(user: AuthorizedUser, resource?: User) {
    // Users can always view themselves
    if (resource && user.id === resource.id) return true
    return hasPermission(user, 'view.user')
  },

  async viewAll(user: AuthorizedUser) {
    return hasPermission(user, 'viewAll.user')
  },

  async update(user: AuthorizedUser, resource?: User) {
    // Users can update themselves
    if (resource && user.id === resource.id) return true
    // Admins cannot modify super admins
    if (user.role === 'ADMIN' && resource?.role === 'SUPER_ADMIN') return false
    return hasPermission(user, 'update.user')
  },

  async delete(user: AuthorizedUser, resource?: User) {
    // Users cannot delete themselves
    if (resource && user.id === resource.id) return false
    return hasPermission(user, 'delete.user')
  },
}
```

### 4. Create the authorization instance

```typescript
// lib/authorization/index.ts
import { createAuth } from '@alfredao/auth-policies'
import { redirect } from 'next/navigation'
import { rolePermissions, type Role } from './role-permissions'
import type { AuthorizedUser } from './types'
import { UserPolicy } from '../policies/user-policy'
import { InstancePolicy } from '../policies/instance-policy'

// Resource types in your application
type ResourceType = 'User' | 'Instance'

export const auth = createAuth<AuthorizedUser, Role, ResourceType>({
  rolePermissions,
  policies: {
    User: UserPolicy,
    Instance: InstancePolicy,
  },
  getUser: async () => {
    // Your auth logic here (e.g., get session from cookies)
    const session = await getSession()
    return session?.user ?? null
  },
  handlers: {
    onUnauthorizedRedirect: () => redirect('/unauthorized'),
  },
})

// Re-export utilities for convenience
export const { can, canApi, hasPermission, requireUser } = auth
```

### 5. Use in your application

```typescript
// API Route
import { canApi } from '@/lib/authorization'

export async function PUT(request: Request, { params }: { params: { id: string } }) {
  const user = await prisma.user.findUnique({ where: { id: params.id } })

  await canApi('update', 'User', { resource: user })

  // ... update logic
}

// Server Component
import { can } from '@/lib/authorization'

export default async function UsersPage() {
  await can('viewAll', 'User')

  const users = await prisma.user.findMany()
  return <UserList users={users} />
}
```

## API Reference

### `createAuth(config)`

Creates an authorization instance with the provided configuration.

```typescript
const auth = createAuth({
  rolePermissions: Record<Role, Permission[]>,
  policies: PolicyMap,
  getUser: () => Promise<User | null>,
  handlers?: {
    onUnauthorizedRedirect?: (message: string) => never,
    onUnauthorizedThrow?: (message: string) => never,
  },
})
```

Returns:
- `can(action, type, options?)` - For server components (redirects on failure)
- `canApi(action, type, options?)` - For API routes (throws on failure)
- `checkPermission(action, type, options?)` - Returns boolean, never throws
- `hasPermission(user, permission)` - Check single permission
- `hasAnyPermission(user, permissions)` - Check if user has any of the permissions
- `hasAllPermissions(user, permissions)` - Check if user has all permissions
- `requireUser()` - Get user or throw UnauthenticatedException
- `getUser()` - Get user or null

### `createNextAuth(config)`

Convenience wrapper for Next.js applications.

```typescript
import { createNextAuth } from '@alfredao/auth-policies'
import { redirect } from 'next/navigation'

const auth = createNextAuth({
  rolePermissions,
  policies,
  getUser,
  redirect,  // Pass Next.js redirect function
  redirectTo: '/unauthorized',  // Optional, defaults to '/unauthorized'
})
```

### Exceptions

```typescript
import { UnauthorizedException, UnauthenticatedException } from '@alfredaoo/auth-policies'

// In your API error handler
function handleApiError(error: unknown) {
  if (error instanceof UnauthorizedException) {
    return new Response(error.message, { status: 403 })
  }
  if (error instanceof UnauthenticatedException) {
    return new Response(error.message, { status: 401 })
  }
  // ... handle other errors
}
```

## React Hooks

The library provides React hooks and components for client-side authorization.

### Setup

Wrap your app with `AuthProvider`:

```tsx
// app/providers.tsx
'use client'

import { AuthProvider } from '@alfredaoo/auth-policies/react'
import { auth } from '@/lib/authorization'

export function Providers({ children, user }: { children: React.ReactNode; user: User | null }) {
  return (
    <AuthProvider auth={auth} initialUser={user}>
      {children}
    </AuthProvider>
  )
}
```

### useAuth

Access the full auth context:

```tsx
import { useAuth } from '@alfredaoo/auth-policies/react'

function UserMenu() {
  const { user, isLoading, isAuthenticated, refresh } = useAuth()

  if (isLoading) return <Spinner />
  if (!isAuthenticated) return <LoginButton />

  return <div>Welcome, {user.name}</div>
}
```

### useUser

Simplified hook for user data:

```tsx
import { useUser } from '@alfredaoo/auth-policies/react'

function Profile() {
  const { user, isAuthenticated } = useUser()

  if (!isAuthenticated) return <LoginPrompt />
  return <div>{user.email}</div>
}
```

### usePermission

Check a single permission reactively:

```tsx
import { usePermission } from '@alfredaoo/auth-policies/react'

function DeleteButton({ postId }: { postId: string }) {
  const { allowed, isLoading } = usePermission('delete', 'Post')

  if (isLoading) return <button disabled>...</button>
  if (!allowed) return null

  return <button onClick={() => deletePost(postId)}>Delete</button>
}
```

### usePermissions

Check multiple permissions at once:

```tsx
import { usePermissions } from '@alfredaoo/auth-policies/react'

function AdminPanel() {
  const { permissions, isLoading } = usePermissions([
    { action: 'create', resourceType: 'User' },
    { action: 'delete', resourceType: 'User' },
  ])

  if (isLoading) return <Spinner />

  return (
    <div>
      {permissions['create:User'] && <CreateUserButton />}
      {permissions['delete:User'] && <DeleteUserButton />}
    </div>
  )
}
```

### Can Component

Declarative conditional rendering:

```tsx
import { Can } from '@alfredaoo/auth-policies/react'

function PostActions({ post }: { post: Post }) {
  return (
    <div>
      {/* Basic usage */}
      <Can action="delete" resourceType="Post">
        <DeleteButton postId={post.id} />
      </Can>

      {/* With fallback */}
      <Can action="update" resourceType="Post" fallback={<span>Read only</span>}>
        <EditButton postId={post.id} />
      </Can>

      {/* With loading state */}
      <Can action="delete" resourceType="Post" loading={<Spinner />}>
        <DeleteButton postId={post.id} />
      </Can>

      {/* Context-aware check */}
      <Can action="update" resourceType="Post" resource={post}>
        <EditButton postId={post.id} />
      </Can>
    </div>
  )
}
```

### Cannot Component

Render content when permission is denied:

```tsx
import { Cannot } from '@alfredaoo/auth-policies/react'

function PostView({ post }: { post: Post }) {
  return (
    <div>
      <h1>{post.title}</h1>
      <Cannot action="update" resourceType="Post">
        <p className="text-gray-500">You don't have permission to edit this post.</p>
      </Cannot>
    </div>
  )
}
```

## Middleware

The library provides middleware helpers for API route protection.

### Next.js App Router

Wrap API route handlers with authorization:

```typescript
// lib/authorization/middleware.ts
import { createAuthMiddleware } from '@alfredaoo/auth-policies/middleware'

export const withAuth = createAuthMiddleware({
  rolePermissions,
  policies,
  getUser: async () => {
    const session = await getSession()
    return session?.user ?? null
  },
})
```

```typescript
// app/api/posts/[id]/route.ts
import { withAuth } from '@/lib/authorization/middleware'

export const DELETE = withAuth(
  async (request, { params }) => {
    await deletePost(params.id)
    return Response.json({ success: true })
  },
  { action: 'delete', type: 'Post' }
)

// With context-aware check
export const PUT = withAuth(
  async (request, { params }) => {
    const data = await request.json()
    const post = await updatePost(params.id, data)
    return Response.json(post)
  },
  {
    action: 'update',
    type: 'Post',
    getResource: async (req) => {
      const url = new URL(req.url)
      const id = url.pathname.split('/').pop()
      return await getPost(id)
    },
  }
)
```

### Permission-Based Middleware

Simpler middleware that checks permissions directly:

```typescript
import { createPermissionMiddleware } from '@alfredaoo/auth-policies/middleware'

const requirePermission = createPermissionMiddleware({
  rolePermissions,
  getUser: async () => getSession()?.user ?? null,
})

export const DELETE = requirePermission(
  async (request) => {
    return Response.json({ success: true })
  },
  { permission: 'delete.post' }
)
```

### Express / Hono

Compatible middleware for Express, Hono, and similar frameworks:

```typescript
import express from 'express'
import { createExpressAuth } from '@alfredaoo/auth-policies/middleware'

const app = express()

const { protect, requireAuth, requirePermission } = createExpressAuth({
  rolePermissions,
  policies,
  getUser: (req) => req.user, // From your auth middleware
})

// Require authentication only
app.get('/profile', requireAuth, (req, res) => {
  res.json(req.user)
})

// Policy-based protection
app.delete('/posts/:id', protect({ action: 'delete', type: 'Post' }), (req, res) => {
  res.json({ success: true })
})

// Permission-based protection
app.post('/posts', requirePermission('create.post'), (req, res) => {
  res.json({ success: true })
})

// With resource for context-aware check
app.put('/posts/:id',
  protect({
    action: 'update',
    type: 'Post',
    getResource: async (req) => await getPost(req.params.id),
  }),
  (req, res) => {
    res.json({ success: true })
  }
)
```

## Audit Logging

Track all authorization decisions for security monitoring and compliance:

```typescript
import { createAuth, type AuditLogEntry } from '@alfredaoo/auth-policies'

const auth = createAuth({
  rolePermissions,
  policies,
  getUser,
  onAudit: async (entry: AuditLogEntry) => {
    // Log to your preferred logging system
    await logger.info('Authorization check', {
      timestamp: entry.timestamp,
      userId: entry.user?.id,
      role: entry.user?.role,
      action: entry.action,
      resourceType: entry.resourceType,
      allowed: entry.allowed,
      reason: entry.reason,
      duration: entry.duration,
      metadata: entry.metadata,
    })
  },
})
```

### Audit Entry Structure

```typescript
interface AuditLogEntry {
  timestamp: Date           // When the check occurred
  user: User | null         // The user (null if unauthenticated)
  action: string            // The action being performed
  resourceType: string      // The resource type
  allowed: boolean          // Whether access was granted
  reason?: string           // Denial reason: 'unauthenticated' | 'policy_denied' | 'policy_not_found' | 'action_not_found'
  resource?: unknown        // The resource being accessed
  duration: number          // Policy check duration in ms
  metadata?: Record<string, unknown>  // Custom metadata
}
```

### Adding Metadata

Pass additional context for audit logs:

```typescript
// Include request metadata
await auth.canApi('delete', 'Post', {
  resource: post,
  metadata: {
    ip: request.ip,
    userAgent: request.headers['user-agent'],
    requestId: request.id,
  },
})
```

### Integration Examples

**Winston:**
```typescript
import winston from 'winston'

const logger = winston.createLogger({ /* ... */ })

const auth = createAuth({
  // ...
  onAudit: (entry) => {
    logger.info('auth', entry)
  },
})
```

**Pino:**
```typescript
import pino from 'pino'

const logger = pino()

const auth = createAuth({
  // ...
  onAudit: (entry) => {
    logger.info(entry, 'authorization check')
  },
})
```

**Database:**
```typescript
const auth = createAuth({
  // ...
  onAudit: async (entry) => {
    await prisma.auditLog.create({
      data: {
        timestamp: entry.timestamp,
        userId: entry.user?.id,
        action: entry.action,
        resourceType: entry.resourceType,
        allowed: entry.allowed,
        reason: entry.reason,
        duration: entry.duration,
        metadata: entry.metadata,
      },
    })
  },
})
```

## Caching

Enable caching to memoize policy check results and improve performance:

```typescript
const auth = createAuth({
  rolePermissions,
  policies,
  getUser,
  cache: {
    enabled: true,
    ttl: 60000, // 1 minute (default)
    maxSize: 1000, // Max entries (default)
  },
})
```

### Cache Configuration

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | `boolean` | `false` | Enable or disable caching |
| `ttl` | `number` | `60000` | Time-to-live in milliseconds. Set to 0 for no expiration |
| `maxSize` | `number` | `1000` | Maximum cache entries. Uses LRU eviction when exceeded |
| `getResourceKey` | `function` | Uses `resource.id` | Custom function to generate cache key for resources |

### Cache Keys

Cache keys are generated from: `action:resourceType:userId:resourceId`

```typescript
// Without resource: "view:Post:user-123:no-resource"
await auth.can('view', 'Post')

// With resource: "update:Post:user-123:post-456"
await auth.can('update', 'Post', { resource: { id: 'post-456' } })
```

### Custom Resource Key

For resources without an `id` property, provide a custom key generator:

```typescript
const auth = createAuth({
  // ...
  cache: {
    enabled: true,
    getResourceKey: (resource) => {
      if (resource && typeof resource === 'object' && 'uuid' in resource) {
        return String(resource.uuid)
      }
      return undefined
    },
  },
})
```

### Cache Invalidation

Invalidate cached entries when permissions or resources change:

```typescript
// Invalidate all entries for a user (e.g., after role change)
auth.cache?.invalidateUser('user-123')

// Invalidate all entries for a resource type
auth.cache?.invalidateResourceType('Post')

// Invalidate entries for a specific resource
auth.cache?.invalidateResource('Post', 'post-456')

// Clear entire cache
auth.cache?.clear()
```

### Cache Maintenance

For long-running processes, periodically clean up expired entries:

```typescript
// Clean up expired entries
const removed = auth.cache?.cleanup()
console.log(`Removed ${removed} expired entries`)

// Get cache statistics
const stats = auth.cache?.stats()
console.log(`Cache size: ${stats?.size}/${stats?.maxSize}`)
```

### Audit Logging with Cache

When caching is enabled, audit entries include a `cached` flag in metadata:

```typescript
const auth = createAuth({
  // ...
  cache: { enabled: true },
  onAudit: (entry) => {
    if (entry.metadata?.cached) {
      console.log('Result from cache')
    }
  },
})
```

### Standalone Cache

Use the cache independently for custom scenarios:

```typescript
import { createPolicyCache } from '@alfredaoo/auth-policies'

const cache = createPolicyCache({
  ttl: 30000,
  maxSize: 500,
})

const key = cache.generateKey('view', 'Post', 'user-123', { id: 'post-1' })
cache.set(key, true)
const result = cache.get(key) // true
```

## Context-Aware Policies

Policies can receive the resource being accessed for dynamic authorization:

```typescript
const InstancePolicy = {
  async delete(user: AuthorizedUser, resource?: Instance) {
    if (!hasPermission(user, 'delete.instance')) return false

    // Can't delete instances that are being provisioned
    if (resource?.status === 'PROVISIONING') return false

    // Can't delete soft-deleted instances
    if (resource?.deleted_at) return false

    return true
  },
}

// Usage
await canApi('delete', 'Instance', { resource: instance })
```

## Standalone Permission Checker

If you only need permission checking without the full policy system:

```typescript
import { createPermissionChecker } from '@alfredaoo/auth-policies'

const { hasPermission, hasAnyPermission } = createPermissionChecker(rolePermissions)

if (hasPermission(user, 'create.user')) {
  // ...
}
```

## TypeScript

The library is written in TypeScript and provides full type safety:

```typescript
import type { BaseUser, Policy, PolicyMap, AuthConfig } from '@alfredaoo/auth-policies'

// Your user type must extend BaseUser
interface MyUser extends BaseUser<'ADMIN' | 'USER'> {
  id: string
  role: 'ADMIN' | 'USER'
  email: string
}

// Policies are type-safe
const MyPolicy: Policy<MyUser> = {
  view: async (user, resource) => true,
  update: async (user, resource) => user.role === 'ADMIN',
}
```

## License

MIT
