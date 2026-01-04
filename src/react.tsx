import {
  createContext,
  useContext,
  useState,
  useEffect,
  useCallback,
  useMemo,
  type ReactNode,
} from 'react'
import type { AuthInstance } from './create-auth'
import type { BaseUser } from './types'

/**
 * Context value type for the auth provider
 */
interface AuthContextValue<
  TUser extends BaseUser<TRole>,
  TRole extends string = string,
  TResourceType extends string = string
> {
  auth: AuthInstance<TUser, TRole, TResourceType>
  user: TUser | null
  isLoading: boolean
  isAuthenticated: boolean
  refresh: () => Promise<void>
}

// Create context with undefined default (must be used within provider)
const AuthContext = createContext<AuthContextValue<any, any, any> | undefined>(undefined)

/**
 * Props for the AuthProvider component
 */
export interface AuthProviderProps<
  TUser extends BaseUser<TRole>,
  TRole extends string = string,
  TResourceType extends string = string
> {
  /**
   * The auth instance created by createAuth()
   */
  auth: AuthInstance<TUser, TRole, TResourceType>
  /**
   * Children to render
   */
  children: ReactNode
  /**
   * Optional initial user (for SSR hydration)
   */
  initialUser?: TUser | null
}

/**
 * Provider component that makes auth available to all children
 *
 * @example
 * ```tsx
 * const auth = createAuth({ ... })
 *
 * function App() {
 *   return (
 *     <AuthProvider auth={auth}>
 *       <MyComponent />
 *     </AuthProvider>
 *   )
 * }
 * ```
 */
export function AuthProvider<
  TUser extends BaseUser<TRole>,
  TRole extends string = string,
  TResourceType extends string = string
>({
  auth,
  children,
  initialUser = null,
}: AuthProviderProps<TUser, TRole, TResourceType>) {
  const [user, setUser] = useState<TUser | null>(initialUser)
  const [isLoading, setIsLoading] = useState(!initialUser)

  const refresh = useCallback(async () => {
    setIsLoading(true)
    try {
      const currentUser = await auth.getUser()
      setUser(currentUser)
    } finally {
      setIsLoading(false)
    }
  }, [auth])

  useEffect(() => {
    // Only fetch if no initial user provided
    if (!initialUser) {
      refresh()
    }
  }, [initialUser, refresh])

  const value = useMemo(
    () => ({
      auth,
      user,
      isLoading,
      isAuthenticated: !!user,
      refresh,
    }),
    [auth, user, isLoading, refresh]
  )

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

/**
 * Hook to access the full auth context
 *
 * @example
 * ```tsx
 * function MyComponent() {
 *   const { auth, user, isLoading } = useAuth()
 *
 *   if (isLoading) return <div>Loading...</div>
 *   if (!user) return <div>Please log in</div>
 *
 *   return <div>Hello, {user.email}</div>
 * }
 * ```
 */
export function useAuth<
  TUser extends BaseUser<TRole>,
  TRole extends string = string,
  TResourceType extends string = string
>(): AuthContextValue<TUser, TRole, TResourceType> {
  const context = useContext(AuthContext)
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider')
  }
  return context as AuthContextValue<TUser, TRole, TResourceType>
}

/**
 * Hook to get the current user with loading state
 *
 * @example
 * ```tsx
 * function Profile() {
 *   const { user, isLoading, isAuthenticated } = useUser()
 *
 *   if (isLoading) return <Spinner />
 *   if (!isAuthenticated) return <LoginPrompt />
 *
 *   return <div>Welcome, {user.email}</div>
 * }
 * ```
 */
export function useUser<TUser extends BaseUser<TRole>, TRole extends string = string>(): {
  user: TUser | null
  isLoading: boolean
  isAuthenticated: boolean
  refresh: () => Promise<void>
} {
  const { user, isLoading, isAuthenticated, refresh } = useAuth<TUser, TRole>()
  return { user, isLoading, isAuthenticated, refresh }
}

/**
 * Result of usePermission hook
 */
export interface UsePermissionResult {
  /**
   * Whether the user has permission (false while loading)
   */
  allowed: boolean
  /**
   * Whether the permission check is in progress
   */
  isLoading: boolean
  /**
   * Re-check the permission
   */
  recheck: () => Promise<void>
}

/**
 * Hook to check if the current user has permission for an action
 *
 * @example
 * ```tsx
 * function DeleteButton({ postId }: { postId: string }) {
 *   const { allowed, isLoading } = usePermission('delete', 'Post')
 *
 *   if (isLoading) return <button disabled>...</button>
 *   if (!allowed) return null
 *
 *   return <button onClick={() => deletePost(postId)}>Delete</button>
 * }
 * ```
 */
export function usePermission(
  action: string,
  resourceType: string,
  options?: { resource?: unknown }
): UsePermissionResult {
  const { auth, user } = useAuth()
  const [allowed, setAllowed] = useState(false)
  const [isLoading, setIsLoading] = useState(true)

  const checkPermission = useCallback(async () => {
    if (!user) {
      setAllowed(false)
      setIsLoading(false)
      return
    }

    setIsLoading(true)
    try {
      const result = await auth.checkPermission(action, resourceType, options)
      setAllowed(result)
    } catch {
      setAllowed(false)
    } finally {
      setIsLoading(false)
    }
  }, [auth, action, resourceType, options, user])

  useEffect(() => {
    checkPermission()
  }, [checkPermission])

  return { allowed, isLoading, recheck: checkPermission }
}

/**
 * Hook to check multiple permissions at once
 *
 * @example
 * ```tsx
 * function AdminPanel() {
 *   const { permissions, isLoading } = usePermissions([
 *     { action: 'create', resourceType: 'User' },
 *     { action: 'delete', resourceType: 'User' },
 *   ])
 *
 *   if (isLoading) return <Spinner />
 *
 *   return (
 *     <div>
 *       {permissions['create:User'] && <CreateUserButton />}
 *       {permissions['delete:User'] && <DeleteUserButton />}
 *     </div>
 *   )
 * }
 * ```
 */
export function usePermissions(
  checks: Array<{ action: string; resourceType: string; resource?: unknown }>
): {
  permissions: Record<string, boolean>
  isLoading: boolean
  recheck: () => Promise<void>
} {
  const { auth, user } = useAuth()
  const [permissions, setPermissions] = useState<Record<string, boolean>>({})
  const [isLoading, setIsLoading] = useState(true)

  const checkAll = useCallback(async () => {
    if (!user) {
      const empty: Record<string, boolean> = {}
      checks.forEach((c) => {
        empty[`${c.action}:${c.resourceType}`] = false
      })
      setPermissions(empty)
      setIsLoading(false)
      return
    }

    setIsLoading(true)
    try {
      const results = await Promise.all(
        checks.map(async (check) => {
          const result = await auth.checkPermission(check.action, check.resourceType, {
            resource: check.resource,
          })
          return { key: `${check.action}:${check.resourceType}`, result }
        })
      )

      const permMap: Record<string, boolean> = {}
      results.forEach(({ key, result }) => {
        permMap[key] = result
      })
      setPermissions(permMap)
    } catch {
      const empty: Record<string, boolean> = {}
      checks.forEach((c) => {
        empty[`${c.action}:${c.resourceType}`] = false
      })
      setPermissions(empty)
    } finally {
      setIsLoading(false)
    }
  }, [auth, checks, user])

  useEffect(() => {
    checkAll()
  }, [checkAll])

  return { permissions, isLoading, recheck: checkAll }
}

/**
 * Props for the Can component
 */
export interface CanProps {
  /**
   * The action to check (e.g., 'delete', 'update')
   */
  action: string
  /**
   * The resource type to check (e.g., 'Post', 'User')
   */
  resourceType: string
  /**
   * Optional resource for context-aware checks
   */
  resource?: unknown
  /**
   * Content to render when allowed
   */
  children: ReactNode
  /**
   * Optional content to render when not allowed
   */
  fallback?: ReactNode
  /**
   * Optional content to render while loading
   */
  loading?: ReactNode
}

/**
 * Component for conditional rendering based on permissions
 *
 * @example
 * ```tsx
 * // Basic usage
 * <Can action="delete" resourceType="Post">
 *   <DeleteButton />
 * </Can>
 *
 * // With fallback
 * <Can action="update" resourceType="Post" fallback={<span>Read only</span>}>
 *   <EditButton />
 * </Can>
 *
 * // With loading state
 * <Can action="create" resourceType="User" loading={<Spinner />}>
 *   <CreateUserButton />
 * </Can>
 *
 * // Context-aware check
 * <Can action="update" resourceType="Post" resource={post}>
 *   <EditButton />
 * </Can>
 * ```
 */
export function Can({
  action,
  resourceType,
  resource,
  children,
  fallback = null,
  loading = null,
}: CanProps): ReactNode {
  const { allowed, isLoading } = usePermission(action, resourceType, { resource })

  if (isLoading) {
    return loading
  }

  return allowed ? children : fallback
}

/**
 * Props for the Cannot component
 */
export interface CannotProps {
  /**
   * The action to check (e.g., 'delete', 'update')
   */
  action: string
  /**
   * The resource type to check (e.g., 'Post', 'User')
   */
  resourceType: string
  /**
   * Optional resource for context-aware checks
   */
  resource?: unknown
  /**
   * Content to render when NOT allowed
   */
  children: ReactNode
  /**
   * Optional content to render while loading
   */
  loading?: ReactNode
}

/**
 * Component for rendering content when user does NOT have permission
 *
 * @example
 * ```tsx
 * <Cannot action="update" resourceType="Post">
 *   <span>You cannot edit this post</span>
 * </Cannot>
 * ```
 */
export function Cannot({
  action,
  resourceType,
  resource,
  children,
  loading = null,
}: CannotProps): ReactNode {
  const { allowed, isLoading } = usePermission(action, resourceType, { resource })

  if (isLoading) {
    return loading
  }

  return allowed ? null : children
}
