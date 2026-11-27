import { createContext, useContext } from 'react';

export interface PreferencesValue {
  /** Show synthetic demonstration data on the dashboard and reports. Always labelled. */
  demoMode: boolean;
  setDemoMode: (value: boolean) => void;
  /** Keep the typed password in the analyser field after submitting (default: clear it). */
  keepPassword: boolean;
  setKeepPassword: (value: boolean) => void;
}

export const PreferencesContext = createContext<PreferencesValue | null>(null);

export const DEMO_STORAGE_KEY = 'passaudit.demo-mode';
export const KEEP_PASSWORD_STORAGE_KEY = 'passaudit.keep-password';

export function usePreferences(): PreferencesValue {
  const value = useContext(PreferencesContext);
  if (!value) throw new Error('usePreferences must be used inside <PreferencesProvider>');
  return value;
}
