import { defineConfig } from 'tsup'

export default defineConfig([
  // Core library (no React)
  {
    entry: ['src/index.ts'],
    format: ['cjs', 'esm'],
    dts: true,
    splitting: false,
    sourcemap: true,
    clean: true,
    treeshake: true,
    minify: false,
  },
  // React bindings
  {
    entry: ['src/react.tsx'],
    format: ['cjs', 'esm'],
    dts: true,
    splitting: false,
    sourcemap: true,
    clean: false,
    treeshake: true,
    minify: false,
    external: ['react', 'react/jsx-runtime'],
    banner: {
      js: '"use client";',
    },
  },
])
