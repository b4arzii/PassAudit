import { readStorage, writeStorage } from '../lib/storage.ts';

export type ThemePreference = 'light' | 'dark' | 'system';
export type ResolvedTheme = 'light' | 'dark';

/** Keep in sync with public/theme-init.js, which applies the theme before first paint. */
export const THEME_STORAGE_KEY = 'passaudit.theme';

export const THEME_COLORS: Record<ResolvedTheme, string> = {
  dark: '#07080a',
  light: '#f4f6f9',
};

export function isThemePreference(value: unknown): value is ThemePreference {
  return value === 'light' || value === 'dark' || value === 'system';
}

export function readStoredPreference(): ThemePreference {
  const stored = readStorage(THEME_STORAGE_KEY);
  return isThemePreference(stored) ? stored : 'system';
}

export function storePreference(preference: ThemePreference): void {
  writeStorage(THEME_STORAGE_KEY, preference);
}

export function systemTheme(): ResolvedTheme {
  if (typeof window.matchMedia !== 'function') return 'dark';
  return window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
}

export function resolveTheme(preference: ThemePreference): ResolvedTheme {
  return preference === 'system' ? systemTheme() : preference;
}

/** Reflect the resolved theme on <html> (CSS tokens) and in the browser chrome colour. */
export function applyTheme(theme: ResolvedTheme): void {
  const root = document.documentElement;
  root.setAttribute('data-theme', theme);
  root.style.colorScheme = theme;
  document
    .querySelector<HTMLMetaElement>('meta[name="theme-color"]')
    ?.setAttribute('content', THEME_COLORS[theme]);
}
