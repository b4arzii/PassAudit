import type {
  BatchResponse,
  BatchResultItem,
  FindingKind,
  PasswordAnalysis,
  RecommendationCode,
  RiskLevel,
  StrengthLabel,
} from '../api/types.ts';

/** Where a number on screen came from. Demo data is never mixed silently with live data. */
export type DataSource = 'live' | 'demo';

/**
 * One analysed password, reduced to what dashboards need. By construction it holds **no
 * password and nothing derived from one** - only the engine's scores and finding kinds.
 */
export interface AnalysisRecord {
  id: string;
  /** User-visible label (batch id or "Analysis 3"). */
  label: string;
  length: number;
  risk_score: number;
  risk_level: RiskLevel;
  strength_score: number;
  strength_label: StrengthLabel;
  guesses_log10: number;
  estimated_bits: number;
  policy_compliant: boolean;
  findings: FindingKind[];
  recommendations: RecommendationCode[];
  reused: boolean;
  /** Opt-in breach check outcome; `null` = no check was requested (never "clean"). */
  breach: 'clean' | 'breached' | 'unavailable' | null;
  /** Names of authorised reuse datasets containing the password; `null` = not checked. */
  reuse_datasets: string[] | null;
}

export function recordFromAnalysis(id: string, label: string, a: PasswordAnalysis): AnalysisRecord {
  return {
    id,
    label,
    length: a.length,
    risk_score: a.risk.score,
    risk_level: a.risk.level,
    strength_score: a.strength.score,
    strength_label: a.strength.label,
    guesses_log10: a.strength.guesses_log10,
    estimated_bits: a.entropy.estimated_bits,
    policy_compliant: a.policy.compliant,
    findings: [...new Set(a.findings.map((f) => f.kind))],
    recommendations: a.recommendations.map((r) => r.code),
    reused: false,
    breach: a.exposure?.breach?.status ?? null,
    reuse_datasets: a.exposure?.reuse ? [...a.exposure.reuse.sources] : null,
  };
}

export function recordFromBatchItem(prefix: string, item: BatchResultItem): AnalysisRecord {
  return {
    id: `${prefix}-${String(item.index)}`,
    label: item.id ?? `Entry ${String(item.index)}`,
    length: item.length,
    risk_score: item.risk_score,
    risk_level: item.risk_level,
    strength_score: item.strength_score,
    strength_label: item.strength_label,
    guesses_log10: item.guesses_log10,
    estimated_bits: item.estimated_bits,
    policy_compliant: item.policy_compliant,
    findings: item.findings,
    recommendations: item.recommendations,
    reused: item.reused_in_batch,
    breach: item.breach ?? null,
    reuse_datasets: item.reuse_datasets ?? null,
  };
}

export function recordsFromBatch(prefix: string, batch: BatchResponse): AnalysisRecord[] {
  return batch.results.map((item) => recordFromBatchItem(prefix, item));
}

export interface RecordStats {
  total: number;
  averageRisk: number | null;
  maxRisk: number | null;
  compliant: number;
  reused: number;
  riskLevels: Record<RiskLevel, number>;
  strengthScores: [number, number, number, number, number];
  findings: Partial<Record<FindingKind, number>>;
  recommendations: Partial<Record<RecommendationCode, number>>;
  /** Share of passwords at high or critical risk (0-1). */
  atRiskShare: number;
  /** True when at least one record went through a breach check. */
  breachChecked: boolean;
  breached: number;
  reuseChecked: boolean;
  reusedInDatasets: number;
}

export function summarizeRecords(records: readonly AnalysisRecord[]): RecordStats {
  const riskLevels: Record<RiskLevel, number> = { low: 0, moderate: 0, high: 0, critical: 0 };
  const strengthScores: [number, number, number, number, number] = [0, 0, 0, 0, 0];
  const findings: Partial<Record<FindingKind, number>> = {};
  const recommendations: Partial<Record<RecommendationCode, number>> = {};
  let riskSum = 0;
  let maxRisk: number | null = null;
  let compliant = 0;
  let reused = 0;
  let breached = 0;
  let breachChecked = false;
  let reusedInDatasets = 0;
  let reuseChecked = false;
  for (const r of records) {
    riskLevels[r.risk_level] += 1;
    const slot = Math.min(4, Math.max(0, r.strength_score));
    strengthScores[slot] = (strengthScores[slot] ?? 0) + 1;
    riskSum += r.risk_score;
    maxRisk = maxRisk === null ? r.risk_score : Math.max(maxRisk, r.risk_score);
    if (r.policy_compliant) compliant += 1;
    if (r.reused) reused += 1;
    if (r.breach !== null) breachChecked = true;
    if (r.breach === 'breached') breached += 1;
    if (r.reuse_datasets !== null) reuseChecked = true;
    if (r.reuse_datasets !== null && r.reuse_datasets.length > 0) reusedInDatasets += 1;
    for (const kind of r.findings) findings[kind] = (findings[kind] ?? 0) + 1;
    for (const code of r.recommendations) recommendations[code] = (recommendations[code] ?? 0) + 1;
  }
  const total = records.length;
  return {
    total,
    averageRisk: total === 0 ? null : Math.round((riskSum / total) * 10) / 10,
    maxRisk,
    compliant,
    reused,
    riskLevels,
    strengthScores,
    findings,
    recommendations,
    atRiskShare: total === 0 ? 0 : (riskLevels.high + riskLevels.critical) / total,
    breachChecked,
    breached,
    reuseChecked,
    reusedInDatasets,
  };
}

/** Entries of a count map, largest first (ties by key so order is stable). */
export function topEntries<K extends string>(
  counts: Partial<Record<K, number>>,
  limit = 5,
): [K, number][] {
  return (Object.entries(counts) as [K, number][])
    .filter(([, n]) => n > 0)
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .slice(0, limit);
}
