# @alfredaoo/auth-policies

A flexible, framework-agnostic authorization library with policy-based access control (RBAC).

## Features

- **Policy-based authorization** - Define granular access rules per resource type
- **Role-permission mapping** - Simple role to permissions configuration
- **Permission inheritance** - Define role hierarchies with automatic permission inheritance
- **Multiple roles** - Users can have multiple roles with merged permissions
- **Multi-tenancy** - Different roles per organization/tenant with tenant-scoped permissions
- **Context-aware checks** - Pass resources for dynamic authorization decisions
- **Framework-agnostic** - Works with any Node.js application
- **React hooks** - `useAuth`, `usePermission`, `<Can>` components for React apps
- **Next.js integration** - Built-in helpers for Next.js applications
- **Caching** - LRU cache with TTL for policy check results
- **Audit logging** - Track all authorization decisions
- **TypeScript-first** - Full type safety and IntelliSense support
- **Lightweight** - Zero dependencies

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

## Permission Inheritance

Define role hierarchies where higher roles automatically inherit permissions from lower roles:

### Basic Inheritance

```typescript
const rolePermissions = {
  VIEWER: ['view.user', 'view.post'],
  EDITOR: {
    inherits: 'VIEWER',
    permissions: ['create.post', 'update.post'],
  },
  ADMIN: {
    inherits: 'EDITOR',
    permissions: ['delete.post', 'delete.user'],
  },
}

// Resolved permissions:
// VIEWER: ['view.user', 'view.post']
// EDITOR: ['view.user', 'view.post', 'create.post', 'update.post']
// ADMIN:  ['view.user', 'view.post', 'create.post', 'update.post', 'delete.post', 'delete.user']
```

### Multiple Inheritance

Inherit from multiple roles at once:

```typescript
const rolePermissions = {
  VIEWER: ['view.dashboard'],
  BILLING: {
    inherits: 'VIEWER',
    permissions: ['view.invoice', 'create.invoice'],
  },
  SUPPORT: {
    inherits: 'VIEWER',
    permissions: ['view.ticket', 'update.ticket'],
  },
  MANAGER: {
    inherits: ['BILLING', 'SUPPORT'],  // Inherits from both
    permissions: ['delete.user'],
  },
}

// MANAGER gets: view.dashboard, view.invoice, create.invoice, view.ticket, update.ticket, delete.user
```

### Mixed Syntax

You can mix flat arrays and inheritance in the same configuration:

```typescript
const rolePermissions = {
  VIEWER: ['view.user'],  // Flat array
  ADMIN: {                // With inheritance
    inherits: 'VIEWER',
    permissions: ['delete.user'],
  },
}
```

### Circular Inheritance Detection

The library automatically detects and throws an error for circular inheritance:

```typescript
import { CircularInheritanceError } from '@alfredaoo/auth-policies'

const rolePermissions = {
  A: { inherits: 'B', permissions: ['a'] },
  B: { inherits: 'A', permissions: ['b'] },  // Circular!
}

try {
  createAuth({ rolePermissions, ... })
} catch (error) {
  if (error instanceof CircularInheritanceError) {
    console.log(error.cycle)  // ['A', 'B', 'A']
  }
}
```

### Resolving Permissions Manually

For debugging or advanced use cases, resolve permissions manually:

```typescript
import { resolvePermissions } from '@alfredaoo/auth-policies'

const resolved = resolvePermissions(rolePermissions)
console.log(resolved.ADMIN)  // All permissions including inherited
```

## Multiple Roles

Users can have multiple roles, and permissions are merged from all roles:

### Single Role (Simple)

```typescript
interface User extends BaseUser<'ADMIN' | 'USER'> {
  id: string
  role: 'ADMIN' | 'USER'  // Single role
}

const user: User = { id: '1', role: 'ADMIN' }
```

### Multiple Roles

```typescript
interface User extends BaseUser<'VIEWER' | 'EDITOR' | 'BILLING'> {
  id: string
  roles: ('VIEWER' | 'EDITOR' | 'BILLING')[]  // Multiple roles
}

const user: User = {
  id: '1',
  roles: ['VIEWER', 'BILLING'],  // Has permissions from both roles
}

// Permissions are merged from all roles
auth.hasPermission(user, 'view.dashboard')  // true (from VIEWER)
auth.hasPermission(user, 'view.invoice')    // true (from BILLING)
auth.hasPermission(user, 'create.post')     // false (EDITOR only)
```

### Combined (role + roles)

You can use both `role` and `roles` together:

```typescript
const user = {
  id: '1',
  role: 'VIEWER',           // Primary role
  roles: ['BILLING'],       // Additional roles
}

// Gets permissions from VIEWER + BILLING
auth.getPermissions(user)   // ['view.dashboard', 'view.invoice', ...]
auth.getRoles(user)         // ['VIEWER', 'BILLING']
```

### Utility Functions

```typescript
// Get all roles for a user
const roles = auth.getRoles(user)  // ['VIEWER', 'BILLING']

// Get all permissions (merged from all roles)
const permissions = auth.getPermissions(user)

// Check permissions across all roles
auth.hasPermission(user, 'view.invoice')
auth.hasAnyPermission(user, ['view.invoice', 'create.post'])
auth.hasAllPermissions(user, ['view.dashboard', 'view.invoice'])
```

## Multi-Tenancy

Support for SaaS applications where users have different roles in different organizations/tenants.

### User Type with Tenant Roles

```typescript
import type { TenantUser } from '@alfredaoo/auth-policies'

// Define system-wide and tenant-specific roles
type SystemRole = 'SUPER_ADMIN' | 'USER'
type TenantRole = 'OWNER' | 'ADMIN' | 'MEMBER'

interface User extends TenantUser<SystemRole, TenantRole> {
  id: string
  email: string
  role: SystemRole                                    // System-wide role
  tenantRoles?: Record<string, TenantRole>            // Per-tenant roles
}

// Example user with different roles in different businesses
const user: User = {
  id: '1',
  email: 'user@example.com',
  role: 'USER',
  tenantRoles: {
    'business-1': 'OWNER',    // Owner of business-1
    'business-2': 'MEMBER',   // Member of business-2
  },
}
```

### Configure Multi-Tenancy

```typescript
const auth = createAuth<User, SystemRole, 'Appointment'>({
  // System-level role permissions (apply globally)
  rolePermissions: {
    SUPER_ADMIN: ['*'],
    USER: ['view.profile'],
  },
  policies: {
    Appointment: AppointmentPolicy,
  },
  getUser: async () => getCurrentUser(),

  // Tenant configuration
  tenant: {
    // Tenant-level role permissions
    rolePermissions: {
      OWNER: ['manage.business', 'view.reports', 'manage.staff'],
      ADMIN: ['view.reports', 'manage.staff'],
      MEMBER: ['view.appointments'],
    },
    // How to get the current tenant context (e.g., from active business)
    getTenantId: async () => {
      const session = await getSession()
      return session?.activeBusinessId ?? null
    },
  },
})
```

### Tenant-Aware Policies

```typescript
import { getTenantRoles } from '@alfredaoo/auth-policies'

const AppointmentPolicy = {
  view: (user, resource, tenantId) => {
    // SUPER_ADMIN can view all
    if (user.role === 'SUPER_ADMIN') return true

    // Check tenant role
    if (!tenantId) return false
    const tenantRoles = getTenantRoles(user, tenantId)
    return tenantRoles.length > 0
  },

  manage: (user, resource, tenantId) => {
    if (user.role === 'SUPER_ADMIN') return true
    if (!tenantId) return false

    const tenantRoles = getTenantRoles(user, tenantId)
    return tenantRoles.includes('OWNER') || tenantRoles.includes('ADMIN')
  },
}
```

### Using Tenant Context

```typescript
// Uses tenant from config (getTenantId)
await auth.canApi('view', 'Appointment')

// Override tenant for specific check
await auth.canApi('view', 'Appointment', { tenantId: 'business-2' })

// In middleware, extract tenant from request
export const PUT = withAuth(handler, {
  action: 'manage',
  type: 'Appointment',
  getTenantId: (req) => {
    const url = new URL(req.url)
    return url.searchParams.get('businessId')
  },
})
```

### Tenant Permission Checker

```typescript
import { createTenantPermissionChecker } from '@alfredaoo/auth-policies'

const checker = createTenantPermissionChecker({
  systemRolePermissions: {
    SUPER_ADMIN: ['*'],
    USER: ['view.profile'],
  },
  tenantRolePermissions: {
    OWNER: ['manage.business', 'view.reports'],
    MEMBER: ['view.appointments'],
  },
})

// Check combined permissions (system + tenant)
checker.hasPermission(user, 'manage.business', 'business-1')  // true (OWNER)
checker.hasPermission(user, 'manage.business', 'business-2')  // false (MEMBER)
checker.hasPermission(user, 'view.profile', null)             // true (USER)

// Get all permissions in a tenant context
checker.getPermissions(user, 'business-1')
// ['view.profile', 'manage.business', 'view.reports']

// Get roles breakdown
checker.getRoles(user, 'business-1')
// { system: ['USER'], tenant: ['OWNER'] }
```

### Tenant Utilities on Auth Instance

```typescript
// Access tenant utilities
auth.tenant?.getTenantRoles(user, 'business-1')    // ['OWNER']
auth.tenant?.hasPermission(user, 'manage.business', 'business-1')
auth.tenant?.getPermissions(user, 'business-1')

// Check if multi-tenancy is enabled
auth.config.tenantEnabled  // true
```

### Cache Invalidation by Tenant

```typescript
// Invalidate cache for a specific tenant (e.g., after role changes)
auth.cache?.invalidateTenant('business-1')
```

### Audit Logging with Tenant

```typescript
const auth = createAuth({
  // ...
  onAudit: (entry) => {
    console.log('Tenant:', entry.tenantId)  // The tenant context used
  },
})
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
