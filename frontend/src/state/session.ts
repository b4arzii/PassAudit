import { createContext, useContext } from 'react';

import type {
  BatchSummary,
  PasswordAnalysis,
  PasswordPolicy,
  PasswordUsage,
  PolicyValidationResponse,
} from '../api/types.ts';
import type { AnalysisRecord, DataSource } from '../lib/records.ts';

/**
 * One completed action in this browser tab. A run holds **results only** - scores, findings,
 * advice - never the password(s) that produced them. Runs live in memory: they vanish when
 * the tab is closed or reloaded, and nothing is written to storage.
 */
export interface SessionRun {
  id: string;
  kind: 'analysis' | 'batch' | 'policy';
  title: string;
  at: string;
  source: DataSource;
  records: AnalysisRecord[];
  usage?: PasswordUsage;
  policy?: Partial<PasswordPolicy>;
  /** Server-computed roll-up (batch). */
  summary?: BatchSummary;
  /** Full analysis (single). */
  analysis?: PasswordAnalysis;
  policyResult?: PolicyValidationResponse;
}

export type NewRun = Omit<SessionRun, 'id' | 'at' | 'source'>;

export interface SessionValue {
  runs: readonly SessionRun[];
  /** Records of every live run, newest first - what the Overview aggregates. */
  records: readonly AnalysisRecord[];
  addRun: (run: NewRun) => string;
  clear: () => void;
}

export const MAX_RUNS = 25;

export const SessionContext = createContext<SessionValue | null>(null);

export function useSession(): SessionValue {
  const value = useContext(SessionContext);
  if (!value) throw new Error('useSession must be used inside <SessionProvider>');
  return value;
}
