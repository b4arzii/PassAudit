import type { LimitsResponse } from '../api/types.ts';
import type { BatchEntry } from './csv.ts';

/**
 * Client-side input checks that mirror the server's limits, so people get a clear message
 * before anything is sent. Messages state counts and line numbers - never the text itself.
 */

/** Length in Unicode code points (what the server counts), not UTF-16 units. */
export function codePointLength(text: string): number {
  let count = 0;
  for (let i = 0; i < text.length; i += 1) {
    const unit = text.charCodeAt(i);
    if (unit >= 0xd800 && unit <= 0xdbff && i + 1 < text.length) {
      const next = text.charCodeAt(i + 1);
      if (next >= 0xdc00 && next <= 0xdfff) i += 1;
    }
    count += 1;
  }
  return count;
}

/** `null` when the password may be sent. */
export function validatePasswordInput(password: string, limits: LimitsResponse): string | null {
  if (password.length === 0) return 'Enter a password to analyse.';
  const length = codePointLength(password);
  if (length > limits.max_password_length) {
    return `This password is ${String(length)} characters long; the limit is ${String(limits.max_password_length)}.`;
  }
  return null;
}

export interface ParsedPersonalInfo {
  items: string[];
  error: string | null;
}

/** One detail per line (name, username, employer...). Blank lines and duplicates are dropped. */
export function parsePersonalInfo(text: string, limits: LimitsResponse): ParsedPersonalInfo {
  const items: string[] = [];
  const seen = new Set<string>();
  const tooLong: number[] = [];
  text.split(/\r\n|\n|\r/).forEach((line, index) => {
    const item = line.trim();
    if (item === '' || seen.has(item)) return;
    seen.add(item);
    if (codePointLength(item) > limits.max_personal_info_item_length) tooLong.push(index + 1);
    items.push(item);
  });
  if (tooLong.length > 0) {
    return {
      items,
      error: `Line ${tooLong.slice(0, 5).join(', ')} is longer than ${String(limits.max_personal_info_item_length)} characters.`,
    };
  }
  if (items.length > limits.max_personal_info_items) {
    return {
      items,
      error: `At most ${String(limits.max_personal_info_items)} details are allowed (you entered ${String(items.length)}).`,
    };
  }
  return { items, error: null };
}

/** `null` when the batch may be sent. */
export function validateBatchEntries(
  entries: readonly BatchEntry[],
  limits: LimitsResponse,
): string | null {
  if (entries.length === 0) return 'Add at least one password.';
  if (entries.length > limits.batch_max_items) {
    return `This list has ${String(entries.length)} passwords; the service accepts at most ${String(limits.batch_max_items)} per batch. Split it into smaller lists.`;
  }
  const tooLong = entries
    .filter((e) => codePointLength(e.password) > limits.max_password_length)
    .map((e) => e.line);
  if (tooLong.length > 0) {
    const shown = tooLong.slice(0, 5).join(', ');
    const more = tooLong.length > 5 ? ` and ${String(tooLong.length - 5)} more` : '';
    return `${String(tooLong.length)} password${tooLong.length === 1 ? ' is' : 's are'} longer than ${String(limits.max_password_length)} characters (line ${shown}${more}).`;
  }
  return null;
}

let counter = 0;
/** A process-unique id for naming a run's records (not a secret, not random). */
export function nextRunPrefix(kind: string): string {
  counter += 1;
  return `${kind}${String(counter)}`;
}
