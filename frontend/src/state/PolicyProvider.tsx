import { useCallback, useMemo, useState } from 'react';
import type { ReactNode } from 'react';

import type { PasswordPolicy } from '../api/types.ts';
import { readStorage, writeStorage } from '../lib/storage.ts';
import { DEFAULT_POLICY, parsePolicyJson, samePolicy } from '../lib/policy.ts';
import { POLICY_STORAGE_KEY, PolicyStateContext } from './policyState.ts';
import type { PolicyStateValue } from './policyState.ts';

function loadPolicy(): PasswordPolicy {
  const stored = readStorage(POLICY_STORAGE_KEY);
  if (stored === null) return DEFAULT_POLICY;
  const parsed = parsePolicyJson(stored); // untrusted: validated like an uploaded file
  return parsed.ok ? parsed.policy : DEFAULT_POLICY;
}

/** The active password policy (a UI preference: rules only, nothing secret). */
export function PolicyProvider({ children }: { children: ReactNode }) {
  const [policy, setPolicyState] = useState<PasswordPolicy>(loadPolicy);

  const setPolicy = useCallback((next: PasswordPolicy) => {
    setPolicyState(next);
    writeStorage(POLICY_STORAGE_KEY, JSON.stringify(next));
  }, []);
  const reset = useCallback(() => {
    setPolicy(DEFAULT_POLICY);
  }, [setPolicy]);

  const value = useMemo<PolicyStateValue>(
    () => ({ policy, setPolicy, reset, customised: !samePolicy(policy, DEFAULT_POLICY) }),
    [policy, setPolicy, reset],
  );
  return <PolicyStateContext.Provider value={value}>{children}</PolicyStateContext.Provider>;
}
