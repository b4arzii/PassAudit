import type { BatchSummary, PasswordAnalysis, PolicyValidationResponse } from '../api/types.ts';
import type { AnalysisRecord, DataSource } from './records.ts';
import { summarizeRecords } from './records.ts';

/**
 * Sanitised report builders. Reports are assembled only from `AnalysisRecord`s and analysis
 * results, which never contain a password - so an export cannot either. The report states
 * its `source`: an export of demonstration data says so in the file itself, in every row,
 * and in its filename, so it cannot be mistaken for a real audit later.
 */

export const REPORT_SCHEMA_VERSION = '1';
export type ExportFormat = 'json' | 'csv';

export const CSV_COLUMNS = [
  'index',
  'label',
  'length',
  'risk_score',
  'risk_level',
  'strength_score',
  'strength_label',
  'guesses_log10',
  'estimated_bits',
  'policy_compliant',
  'findings',
  'recommendations',
  'reused_in_batch',
  'breach_check',
  'reuse_datasets',
  'data_source',
] as const;

const FORMULA_PREFIX = /^[=+\-@\t\r]/;

/** One CSV cell: neutralise spreadsheet formulas, then quote per RFC 4180 when needed. */
export function csvCell(value: string | number | boolean | null | undefined): string {
  if (value === null || value === undefined) return '';
  let text = typeof value === 'boolean' ? (value ? 'true' : 'false') : String(value);
  if (typeof value === 'string' && FORMULA_PREFIX.test(text)) text = `'${text}`;
  return /[",\r\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

export function recordsToCsv(records: readonly AnalysisRecord[], source: DataSource): string {
  const rows = records.map((r, i) =>
    [
      i + 1,
      r.label,
      r.length,
      r.risk_score,
      r.risk_level,
      r.strength_score,
      r.strength_label,
      Math.round(r.guesses_log10 * 100) / 100,
      Math.round(r.estimated_bits * 10) / 10,
      r.policy_compliant,
      r.findings.join(';'),
      r.recommendations.join(';'),
      r.reused,
      r.breach ?? '',
      r.reuse_datasets === null ? '' : r.reuse_datasets.join(';'),
      source,
    ]
      .map(csvCell)
      .join(','),
  );
  return [CSV_COLUMNS.join(','), ...rows].join('\n') + '\n';
}

export interface ReportInput {
  title: string;
  kind: 'analysis' | 'batch' | 'policy';
  source: DataSource;
  generatedAt: Date;
  records: readonly AnalysisRecord[];
  /** The API's own batch summary, when the report comes from a batch. */
  summary?: BatchSummary | undefined;
  /** Full single-password analysis, included when requested. */
  analysis?: PasswordAnalysis | undefined;
  includeRecommendations: boolean;
  /** Which external breach check ran (default `off`): recorded in the report, never data. */
  breachMode?: 'off' | 'local' | 'online';
  /** Names of reuse datasets consulted, if any. */
  reuseDatasets?: readonly string[] | undefined;
}

export function buildReportJson(input: ReportInput): string {
  const stats = summarizeRecords(input.records);
  const results = input.records.map((r, i) => ({
    index: i + 1,
    label: r.label,
    length: r.length,
    risk: { score: r.risk_score, level: r.risk_level },
    strength: {
      score: r.strength_score,
      label: r.strength_label,
      guesses_log10: Math.round(r.guesses_log10 * 100) / 100,
    },
    estimated_bits: Math.round(r.estimated_bits * 10) / 10,
    policy_compliant: r.policy_compliant,
    findings: r.findings,
    ...(input.includeRecommendations ? { recommendations: r.recommendations } : {}),
    reused_in_batch: r.reused,
    breach: r.breach,
    reuse_datasets: r.reuse_datasets,
  }));
  const report = {
    report: {
      title: input.title,
      type: input.kind,
      schema_version: REPORT_SCHEMA_VERSION,
      tool: 'passaudit-web',
      generated_at: input.generatedAt.toISOString(),
      source: input.source,
      ...(input.source === 'demo' ? { synthetic: true } : {}),
      sanitized: true,
      note:
        input.source === 'demo'
          ? 'SYNTHETIC DEMONSTRATION DATA - not derived from any real password. Contains no passwords.'
          : 'Contains no passwords, no password-derived values and no personal information.',
    },
    external_checks: {
      breach_check: input.breachMode ?? 'off',
      reuse_datasets: input.reuseDatasets ? [...input.reuseDatasets] : null,
    },
    summary: input.summary ?? {
      analyzed: stats.total,
      policy_compliant: stats.compliant,
      average_risk_score: stats.averageRisk,
      max_risk_score: stats.maxRisk,
      risk_levels: stats.riskLevels,
      reused_in_batch: stats.reused,
      breached: stats.breached,
      reused_in_datasets: stats.reusedInDatasets,
    },
    results,
    ...(input.analysis ? { analysis: input.analysis } : {}),
  };
  return JSON.stringify(report, null, 2) + '\n';
}

export function buildReport(input: ReportInput, format: ExportFormat): string {
  return format === 'json' ? buildReportJson(input) : recordsToCsv(input.records, input.source);
}

/** Restrict a user-typed file name to safe characters and the right extension. */
export function safeFilename(raw: string, format: ExportFormat, source: DataSource): string {
  const base = raw
    .trim()
    .replace(/\.(json|csv)$/i, '')
    .replace(/[^A-Za-z0-9._-]+/g, '-')
    .replace(/^[-.]+|[-.]+$/g, '')
    .slice(0, 80);
  const stem = base.length > 0 ? base : 'passaudit-report';
  const prefixed =
    source === 'demo' && !stem.toLowerCase().startsWith('demo') ? `demo-${stem}` : stem;
  return `${prefixed}.${format}`;
}

export const MIME: Record<ExportFormat, string> = {
  json: 'application/json',
  csv: 'text/csv',
};

/** Trigger a browser download of `text`. Nothing is sent anywhere. */
export function downloadText(text: string, filename: string, format: ExportFormat): void {
  const blob = new Blob([text], { type: `${MIME[format]};charset=utf-8` });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  link.rel = 'noopener';
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => {
    URL.revokeObjectURL(url);
  }, 0);
}

export async function copyText(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}

// ------------------------------------------------------------------ policy-check reports

export interface PolicyReportInput {
  title: string;
  source: DataSource;
  generatedAt: Date;
  policy: Record<string, unknown>;
  result: PolicyValidationResponse;
}

export function buildPolicyReportJson(input: PolicyReportInput): string {
  return (
    JSON.stringify(
      {
        report: {
          title: input.title,
          type: 'policy_check',
          schema_version: REPORT_SCHEMA_VERSION,
          tool: 'passaudit-web',
          generated_at: input.generatedAt.toISOString(),
          source: input.source,
          ...(input.source === 'demo' ? { synthetic: true } : {}),
          sanitized: true,
          note:
            input.source === 'demo'
              ? 'SYNTHETIC DEMONSTRATION DATA - not derived from any real password. Contains no passwords.'
              : 'Contains no passwords, no password-derived values and no personal information.',
        },
        policy: input.policy,
        verdict: { compliant: input.result.compliant },
        length: input.result.length,
        rules: input.result.rules,
      },
      null,
      2,
    ) + '\n'
  );
}

export const POLICY_CSV_COLUMNS = [
  'rule',
  'requirement',
  'status',
  'required',
  'actual',
  'message',
  'data_source',
] as const;

export function buildPolicyReportCsv(input: PolicyReportInput): string {
  const rows = input.result.rules.map((r) =>
    [r.rule, r.requirement, r.status, r.required, r.actual, r.message, input.source]
      .map(csvCell)
      .join(','),
  );
  return [POLICY_CSV_COLUMNS.join(','), ...rows].join('\n') + '\n';
}

export function buildPolicyReport(input: PolicyReportInput, format: ExportFormat): string {
  return format === 'json' ? buildPolicyReportJson(input) : buildPolicyReportCsv(input);
}
