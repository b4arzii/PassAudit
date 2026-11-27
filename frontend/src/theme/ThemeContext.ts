import { createContext } from 'react';

import type { ResolvedTheme, ThemePreference } from './theme.ts';

export interface ThemeContextValue {
  /** What the user chose: light, dark, or follow the system. */
  preference: ThemePreference;
  /** What is actually applied right now. */
  resolved: ResolvedTheme;
  setPreference: (preference: ThemePreference) => void;
  /** Flip between light and dark (leaves `system` mode). */
  toggle: () => void;
}

export const ThemeContext = createContext<ThemeContextValue | null>(null);
