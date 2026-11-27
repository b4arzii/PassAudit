import { useContext } from 'react';

import { ThemeContext } from './ThemeContext.ts';
import type { ThemeContextValue } from './ThemeContext.ts';

export function useTheme(): ThemeContextValue {
  const value = useContext(ThemeContext);
  if (!value) throw new Error('useTheme must be used inside <ThemeProvider>');
  return value;
}
