# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
npm run build        # Build with tsup (outputs to dist/)
npm run dev          # Build in watch mode
npm run test         # Run tests with vitest
npm run test:watch   # Run tests in watch mode
npm run test:coverage # Run tests with coverage (thresholds: 80% lines/functions/statements, 75% branches)
npm run typecheck    # Run TypeScript type checking
npm run lint         # Run ESLint on src/
```

Run a single test file:
```bash
npx vitest run tests/create-auth.test.ts
```

## Architecture

This is a TypeScript authorization library published as `@alfredaoo/auth-policies` with two entry points:

- **Main entry (`src/index.ts`)**: Core authorization - `createAuth`, `createNextAuth`, exceptions, types
- **React entry (`src/react.tsx`)**: React bindings - `AuthProvider`, `useAuth`, `usePermission`, `Can`/`Cannot` components

### Core Concepts

**createAuth** (`src/create-auth.ts`): Factory function that creates an authorization instance. Takes:
- `rolePermissions`: Maps roles to permission strings (e.g., `{ ADMIN: ['view.user', 'delete.user'] }`)
- `policies`: Maps resource types to policy objects with async action methods
- `getUser`: Async function returning the current user or null
- `handlers`: Optional redirect/throw handlers for unauthorized access

Returns authorization methods:
- `can(action, type, options?)` - For server components (redirects on failure)
- `canApi(action, type, options?)` - For API routes (throws on failure)
- `checkPermission(action, type, options?)` - Returns boolean, never throws
- `hasPermission/hasAnyPermission/hasAllPermissions` - Direct permission checks

**Policies**: Objects with async methods per action (e.g., `view`, `update`, `delete`). Each method receives `(user, resource?)` and returns boolean. Policies enable context-aware authorization (e.g., "users can edit their own posts").

**createNextAuth** (`src/nextjs.ts`): Convenience wrapper that pre-configures redirect handling for Next.js server components.

### Exception Hierarchy

All in `src/exceptions.ts`:
- `UnauthenticatedException` (401) - No user session
- `UnauthorizedException` (403) - User lacks permission, includes error context
- `PolicyConfigurationException` (500) - Missing policy or action

### Build Configuration

tsup builds two bundles (tsup.config.ts):
1. Core library from `src/index.ts` (ESM + CJS)
2. React bindings from `src/react.tsx` with `"use client"` banner (ESM + CJS)

React is marked as external peer dependency.
