import type { PasswordUsage } from '../../api/types.ts';

export interface ContextValue {
  usage: PasswordUsage;
  /** One personal detail per line. Sensitive: held in memory only, never stored. */
  personalText: string;
  reused: boolean;
}

export const EMPTY_CONTEXT: ContextValue = { usage: 'general', personalText: '', reused: false };
