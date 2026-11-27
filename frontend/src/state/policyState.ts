import { createContext, useContext } from 'react';

import type { PasswordPolicy } from '../api/types.ts';

export const POLICY_STORAGE_KEY = 'passaudit.policy';

export interface PolicyStateValue {
  /** The policy Analyzer, Batch and Policy Checker all use. */
  policy: PasswordPolicy;
  setPolicy: (policy: PasswordPolicy) => void;
  reset: () => void;
  /** True when the policy differs from the built-in default. */
  customised: boolean;
}

export const PolicyStateContext = createContext<PolicyStateValue | null>(null);

export function usePolicy(): PolicyStateValue {
  const value = useContext(PolicyStateContext);
  if (!value) throw new Error('usePolicy must be used inside <PolicyProvider>');
  return value;
}
