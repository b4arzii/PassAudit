/// <reference types="vite/client" />

/** The app version from package.json, injected by Vite (`define`) at build time. */
declare const __APP_VERSION__: string;

interface ImportMetaEnv {
  /** Base URL of the PassAudit API (default `/api/v1`, served through the dev proxy). */
  readonly VITE_API_BASE_URL?: string;
}
