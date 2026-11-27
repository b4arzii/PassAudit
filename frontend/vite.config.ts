import { readFileSync } from 'node:fs';

import react from '@vitejs/plugin-react';
import type { Plugin } from 'vite';
import { defineConfig } from 'vitest/config';

import { CONTENT_SECURITY_POLICY, META_CONTENT_SECURITY_POLICY } from './csp.ts';

// The API is only ever called through the dev proxy, so the browser stays same-origin.
const API_TARGET = 'http://127.0.0.1:8000';
const API_PROXY = { '/api': { target: API_TARGET, changeOrigin: false } };

const pkg = JSON.parse(readFileSync(new URL('./package.json', import.meta.url), 'utf-8')) as {
  version: string;
};

/**
 * Ship a strict Content-Security-Policy with the production build (docs/security.md).
 *
 * `connect-src 'self'` is the point: even if a script were ever compromised, the browser would
 * refuse to send a password anywhere but this origin. The dev server is exempt because React
 * Fast Refresh injects an inline script; `vite preview` serves the real build with the full
 * header, which is how the policy is tested.
 */
function contentSecurityPolicy(): Plugin {
  return {
    name: 'passaudit-csp',
    apply: 'build',
    transformIndexHtml: () => [
      {
        tag: 'meta',
        attrs: { 'http-equiv': 'Content-Security-Policy', content: META_CONTENT_SECURITY_POLICY },
        injectTo: 'head-prepend',
      },
    ],
  };
}

export default defineConfig({
  plugins: [react(), contentSecurityPolicy()],
  // Share the repo-root .env (only VITE_-prefixed variables are exposed to the client).
  envDir: '..',
  define: {
    __APP_VERSION__: JSON.stringify(pkg.version),
  },
  server: {
    host: '127.0.0.1',
    port: 5173,
    strictPort: true,
    proxy: API_PROXY,
  },
  preview: {
    host: '127.0.0.1',
    port: 4173,
    strictPort: true,
    proxy: API_PROXY,
    headers: {
      'Content-Security-Policy': CONTENT_SECURITY_POLICY,
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'Referrer-Policy': 'no-referrer',
    },
  },
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./src/test-setup.ts'],
    css: false,
  },
});
