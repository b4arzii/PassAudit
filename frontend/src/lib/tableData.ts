import type { RiskLevel } from '../api/types.ts';
import type { AnalysisRecord } from './records.ts';

export type SortKey = 'label' | 'length' | 'risk' | 'strength' | 'bits';
export type SortDir = 'ascending' | 'descending';

export interface TableQuery {
  text: string;
  level: RiskLevel | 'all';
  policy: 'all' | 'pass' | 'fail';
  sortKey: SortKey;
  sortDir: SortDir;
}

export const DEFAULT_QUERY: TableQuery = {
  text: '',
  level: 'all',
  policy: 'all',
  sortKey: 'risk',
  sortDir: 'descending',
};

const SORTERS: Record<SortKey, (a: AnalysisRecord, b: AnalysisRecord) => number> = {
  label: (a, b) =>
    a.label.localeCompare(b.label, undefined, { numeric: true, sensitivity: 'base' }),
  length: (a, b) => a.length - b.length,
  risk: (a, b) => a.risk_score - b.risk_score,
  strength: (a, b) => a.strength_score - b.strength_score,
  bits: (a, b) => a.estimated_bits - b.estimated_bits,
};

/** Filter then sort; sorting is stable and ties fall back to the original order. */
export function filterAndSort(
  records: readonly AnalysisRecord[],
  query: TableQuery,
): AnalysisRecord[] {
  const needle = query.text.trim().toLowerCase();
  const kept = records
    .map((record, index) => ({ record, index }))
    .filter(({ record }) => {
      if (needle && !record.label.toLowerCase().includes(needle)) return false;
      if (query.level !== 'all' && record.risk_level !== query.level) return false;
      if (query.policy === 'pass' && !record.policy_compliant) return false;
      if (query.policy === 'fail' && record.policy_compliant) return false;
      return true;
    });
  const sign = query.sortDir === 'ascending' ? 1 : -1;
  kept.sort((a, b) => sign * SORTERS[query.sortKey](a.record, b.record) || a.index - b.index);
  return kept.map(({ record }) => record);
}

export function isDefaultFilter(query: TableQuery): boolean {
  return query.text === '' && query.level === 'all' && query.policy === 'all';
}
