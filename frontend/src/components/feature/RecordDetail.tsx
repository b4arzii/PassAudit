import type { PasswordAnalysis } from '../../api/types.ts';
import { formatBits, formatGuesses } from '../../lib/format.ts';
import { FINDING_LABEL, RECOMMENDATION_TITLE, RISK_LABEL, riskTone } from '../../lib/labels.ts';
import type { AnalysisRecord } from '../../lib/records.ts';
import { RiskMeter } from '../charts/RiskMeter.tsx';
import { StrengthGauge } from '../charts/StrengthGauge.tsx';
import { Badge } from '../ui/index.ts';
import { AnalysisView } from './AnalysisView.tsx';

export interface RecordDetailProps {
  record: AnalysisRecord;
  /** The full analysis, when the source provided it (live batch with detail=full). */
  analysis?: PasswordAnalysis | null | undefined;
}

/**
 * The body of a result's detail dialog. With a full analysis it shows the complete view;
 * otherwise (demo summaries) it shows what the summary record contains - and says so.
 */
export function RecordDetail({ record, analysis }: RecordDetailProps) {
  if (analysis) return <AnalysisView analysis={analysis} headingLevel={3} />;

  return (
    <div className="space-y-5">
      <div className="grid grid-cols-1 gap-5 sm:grid-cols-2">
        <StrengthGauge score={record.strength_score} />
        <RiskMeter score={record.risk_score} level={record.risk_level} className="self-center" />
      </div>
      <dl className="grid grid-cols-2 gap-3 text-sm sm:grid-cols-4">
        {[
          ['Risk', `${String(record.risk_score)} (${RISK_LABEL[record.risk_level]})`],
          ['Length', `${String(record.length)} chars`],
          ['Entropy', formatBits(record.estimated_bits)],
          ['Guesses', formatGuesses(record.guesses_log10)],
        ].map(([term, value]) => (
          <div key={term} className="rounded-xl border border-line/10 bg-surface-2/50 p-3">
            <dt className="text-xs text-fg-muted">{term}</dt>
            <dd className="tabular mt-1 font-medium">{value}</dd>
          </div>
        ))}
      </dl>
      <div className="flex flex-wrap gap-2">
        <Badge tone={riskTone(record.risk_level)} dot>
          {RISK_LABEL[record.risk_level]} risk
        </Badge>
        <Badge tone={record.policy_compliant ? 'success' : 'danger'} dot>
          {record.policy_compliant ? 'Policy met' : 'Policy broken'}
        </Badge>
        {record.reused && (
          <Badge tone="warning" dot>
            Reused in this batch
          </Badge>
        )}
      </div>
      <section aria-labelledby="rd-patterns">
        <h3 id="rd-patterns" className="mb-2 text-sm font-semibold">
          Detected pattern types
        </h3>
        {record.findings.length === 0 ? (
          <p className="text-sm text-fg-muted">None detected.</p>
        ) : (
          <ul className="flex flex-wrap gap-2">
            {record.findings.map((kind) => (
              <li key={kind}>
                <Badge>{FINDING_LABEL[kind].title}</Badge>
              </li>
            ))}
          </ul>
        )}
      </section>
      <section aria-labelledby="rd-advice">
        <h3 id="rd-advice" className="mb-2 text-sm font-semibold">
          Recommendations
        </h3>
        <ul className="list-disc space-y-1 pl-5 text-sm text-fg-muted">
          {record.recommendations.map((code) => (
            <li key={code}>{RECOMMENDATION_TITLE[code]}</li>
          ))}
        </ul>
      </section>
      <p className="text-xs text-fg-subtle">
        This is a summary record: positions and per-rule detail are only available for live
        analyses.
      </p>
    </div>
  );
}
