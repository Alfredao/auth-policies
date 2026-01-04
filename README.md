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
