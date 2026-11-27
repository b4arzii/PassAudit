import type {
  BatchResponse,
  PasswordAnalysis,
  PasswordPolicy,
  PasswordUsage,
  PolicyValidationResponse,
} from '../api/types.ts';
import { recordsFromBatch, recordFromAnalysis } from '../lib/records.ts';
import type { AnalysisRecord } from '../lib/records.ts';
import data from './demoData.json';

/**
 * SYNTHETIC DEMONSTRATION DATA.
 *
 * Produced by scripts/generate_demo_data.py: the real engine run over fabricated passwords,
 * keeping only the results (which never contain a password). It exists so the dashboard can be
 * previewed - and so pages have something to show - when no backend is reachable. The UI
 * always labels it as demo data; it is never mixed into live results or live exports.
 */

export const DEMO_TITLE = 'Demo data';
export const DEMO_EXPLANATION =
  'Synthetic demonstration data. It was generated from fabricated passwords and is not derived from any real password or from your activity.';

export interface DemoAnalysis {
  id: string;
  title: string;
  usage: PasswordUsage;
  analysis: PasswordAnalysis;
}

export interface DemoData {
  engine_version: string;
  analyses: DemoAnalysis[];
  batch: BatchResponse;
  policyCheck: { policy: Partial<PasswordPolicy>; result: PolicyValidationResponse };
}

export const demo = data as unknown as DemoData;

export const demoBatchRecords: AnalysisRecord[] = recordsFromBatch('demo', demo.batch);

export function demoSingleRecords(): AnalysisRecord[] {
  return demo.analyses.map((d) => recordFromAnalysis(`demo-${d.id}`, d.title, d.analysis));
}

/** Every demo record (batch plus the three single analyses), for the demo overview. */
export function demoAllRecords(): AnalysisRecord[] {
  return [...demoBatchRecords, ...demoSingleRecords()];
}
