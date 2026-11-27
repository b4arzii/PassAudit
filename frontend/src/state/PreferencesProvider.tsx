import { useMemo } from 'react';
import type { ReactNode } from 'react';

import { usePersistentBoolean } from '../lib/usePersistentState.ts';
import { DEMO_STORAGE_KEY, KEEP_PASSWORD_STORAGE_KEY, PreferencesContext } from './preferences.ts';

/** UI preferences only - never anything derived from a password. Persisted in localStorage. */
export function PreferencesProvider({ children }: { children: ReactNode }) {
  const [demoMode, setDemoMode] = usePersistentBoolean(DEMO_STORAGE_KEY, false);
  const [keepPassword, setKeepPassword] = usePersistentBoolean(KEEP_PASSWORD_STORAGE_KEY, false);
  const value = useMemo(
    () => ({ demoMode, setDemoMode, keepPassword, setKeepPassword }),
    [demoMode, setDemoMode, keepPassword, setKeepPassword],
  );
  return <PreferencesContext.Provider value={value}>{children}</PreferencesContext.Provider>;
}
