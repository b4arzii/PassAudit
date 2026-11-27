import type { Finding, FindingKind } from '../api/types.ts';
import { FINDING_PRIORITY } from './labels.ts';

/** For each character position, the highest-priority finding kind covering it (or null). */
export function kindsByPosition(
  length: number,
  findings: readonly Finding[],
): (FindingKind | null)[] {
  const cells: (FindingKind | null)[] = Array.from({ length }, () => null);
  const rank = (kind: FindingKind) => FINDING_PRIORITY.indexOf(kind);
  for (const f of findings) {
    for (let i = f.start; i < Math.min(length, f.start + f.length); i++) {
      const current = cells[i] ?? null;
      if (current === null || rank(f.kind) < rank(current)) cells[i] = f.kind;
    }
  }
  return cells;
}
