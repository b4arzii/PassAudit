import { CheckCircle2, ShieldAlert, ShieldCheck, Target } from 'lucide-react';
import type { ElementType } from 'react';

import type { PasswordAnalysis } from '../../api/types.ts';
import { formatBits, formatGuesses, formatRange } from '../../lib/format.ts';
import {
  FINDING_LABEL,
  POLICY_RULE_LABEL,
  PRIORITY_TONE,
  RECOMMENDATION_TITLE,
  RISK_FACTOR_LABEL,
} from '../../lib/labels.ts';
import { CHART_COLOR } from '../charts/chartColors.ts';
import { ExposureView } from './ExposureView.tsx';
import { PatternStrand } from '../charts/PatternStrand.tsx';
import { RiskMeter } from '../charts/RiskMeter.tsx';
import { StackedBar } from '../charts/StackedBar.tsx';
import { StrengthGauge } from '../charts/StrengthGauge.tsx';
import {
  Alert,
  Badge,
  Card,
  CardDescription,
  CardTitle,
  Disclosure,
  TBody,
  TD,
  TH,
  THead,
  TR,
  Table,
  Tabs,
} from '../ui/index.ts';
import type { HeadingLevel } from '../ui/index.ts';

const FACTOR_COLORS = [
  CHART_COLOR.danger,
  CHART_COLOR.warning,
  CHART_COLOR.secondary,
  CHART_COLOR.accent,
  CHART_COLOR.primary,
  CHART_COLOR.success,
  CHART_COLOR.muted,
];

export interface AnalysisViewProps {
  analysis: PasswordAnalysis;
  /** Heading level for the cards inside (pick it from the surrounding outline). */
  headingLevel?: HeadingLevel;
  className?: string;
}

/**
 * A full single-password result: strength gauge, risk meter, estimates, then tabs for pattern
 * detection, the risk breakdown, strength/entropy detail, recommendations and policy results.
 * Everything shown comes from the engine's result - which never contains the password.
 */
export function AnalysisView({ analysis, headingLevel = 3, className }: AnalysisViewProps) {
  const { strength, entropy, risk, findings, recommendations, policy } = analysis;
  const Heading = `h${String(headingLevel)}` as ElementType;
  const TabHeading = `h${String(Math.min(6, headingLevel + 1))}` as ElementType;

  const patternsTab = (
    <div className="space-y-6">
      <PatternStrand length={analysis.length} findings={findings} />
      {findings.length > 0 && (
        <Table
          label="Detected patterns"
          caption="Detected patterns, where they occur and why they matter"
        >
          <THead>
            <TR>
              <TH>Pattern</TH>
              <TH>Where</TH>
              <TH className="hidden sm:table-cell">Detail</TH>
            </TR>
          </THead>
          <TBody>
            {findings.map((f, i) => (
              <TR key={`${f.kind}-${String(f.start)}-${String(i)}`}>
                <TD>
                  <span className="font-medium">{FINDING_LABEL[f.kind].title}</span>
                  {f.match_type && (
                    <span className="ml-2 text-xs text-fg-subtle">({f.match_type})</span>
                  )}
                </TD>
                <TD className="tabular whitespace-nowrap">{formatRange(f.start, f.length)}</TD>
                <TD className="hidden text-fg-muted sm:table-cell">{f.description}</TD>
              </TR>
            ))}
          </TBody>
        </Table>
      )}
    </div>
  );

  const riskTab = (
    <div className="space-y-4">
      <StackedBar
        label="Risk score composition"
        total={100}
        segments={risk.components.map((c, i) => ({
          key: c.factor,
          label: RISK_FACTOR_LABEL[c.factor],
          value: c.points,
          max: c.max_points,
          color: FACTOR_COLORS[i % FACTOR_COLORS.length] ?? CHART_COLOR.muted,
          detail: c.explanation,
        }))}
      />
      <p className="text-xs text-fg-muted">
        The score is exactly the sum of these components. The engine&apos;s formula is described on
        the About &amp; methodology page.
      </p>
    </div>
  );

  const strengthTab = (
    <div className="space-y-6">
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <div>
          <TabHeading className="mb-3 text-sm font-semibold">Estimated time to crack</TabHeading>
          <Table
            label="Crack time estimates"
            caption="Estimated time to crack under four attack scenarios"
          >
            <THead>
              <TR>
                <TH>Attack scenario</TH>
                <TH>Estimate</TH>
              </TR>
            </THead>
            <TBody>
              <TR>
                <TD>Online, throttled (100 guesses/hour)</TD>
                <TD className="tabular">{strength.crack_times.online_throttled}</TD>
              </TR>
              <TR>
                <TD>Online, unthrottled (10/second)</TD>
                <TD className="tabular">{strength.crack_times.online_unthrottled}</TD>
              </TR>
              <TR>
                <TD>Offline, slow hash (10^4/second)</TD>
                <TD className="tabular">{strength.crack_times.offline_slow_hash}</TD>
              </TR>
              <TR>
                <TD>Offline, fast hash (10^10/second)</TD>
                <TD className="tabular">{strength.crack_times.offline_fast_hash}</TD>
              </TR>
            </TBody>
          </Table>
        </div>
        <div>
          <TabHeading className="mb-3 text-sm font-semibold">Entropy estimates</TabHeading>
          <dl className="grid grid-cols-2 gap-3 text-sm">
            {[
              ['Estimated (conservative)', formatBits(entropy.estimated_bits)],
              ['Guess-based', formatBits(entropy.guess_bits)],
              ['Character-set (naive)', formatBits(entropy.charset_bits)],
              ['Shannon (this string)', formatBits(entropy.shannon_bits)],
              ['Character pool', `${String(entropy.pool_size)} symbols`],
              ['Guesses', formatGuesses(strength.guesses_log10)],
            ].map(([term, value]) => (
              <div key={term} className="rounded-xl border border-line/10 bg-surface-2/50 p-3">
                <dt className="text-xs text-fg-muted">{term}</dt>
                <dd className="tabular mt-1 font-medium text-fg">{value}</dd>
              </div>
            ))}
          </dl>
        </div>
      </div>
      {strength.warning && (
        <Alert tone="warning" title="From the strength estimator">
          {strength.warning}
        </Alert>
      )}
      {strength.truncated && (
        <Alert tone="info" title="Long password">
          Only the first {strength.analyzed_length} characters were scored for strength, so the
          estimate is a lower bound.
        </Alert>
      )}
      <Disclosure summary="Limitations of these numbers">
        <ul className="list-disc space-y-1.5 pl-5">
          {entropy.limitations.map((text) => (
            <li key={text}>{text}</li>
          ))}
        </ul>
      </Disclosure>
    </div>
  );

  const recommendationsTab = (
    <ol className="space-y-3">
      {recommendations.map((rec) => (
        <li
          key={rec.code}
          className="flex items-start gap-3 rounded-xl border border-line/10 bg-surface-2/40 p-4"
        >
          <Badge
            tone={PRIORITY_TONE[rec.priority]}
            size="sm"
            className="mt-0.5 shrink-0 capitalize"
          >
            {rec.priority}
          </Badge>
          <div>
            <p className="font-medium text-fg">{RECOMMENDATION_TITLE[rec.code]}</p>
            <p className="mt-1 text-sm text-fg-muted">{rec.message}</p>
          </div>
        </li>
      ))}
    </ol>
  );

  const policyTab = policy.compliant ? (
    <Alert tone="success" title="Policy satisfied">
      This password meets every rule of the active policy.
    </Alert>
  ) : (
    <ul className="space-y-3">
      {policy.violations.map((v) => (
        <li
          key={v.rule}
          className="flex items-start gap-3 rounded-xl border border-danger/30 bg-danger/10 p-4"
        >
          <ShieldAlert aria-hidden="true" className="mt-0.5 size-5 shrink-0 text-danger" />
          <div>
            <p className="font-medium text-fg">{POLICY_RULE_LABEL[v.rule]}</p>
            <p className="mt-0.5 text-sm text-fg-muted">{v.message}</p>
          </div>
        </li>
      ))}
    </ul>
  );

  return (
    <div className={className}>
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <Card>
          <CardTitle level={headingLevel} className="mb-2 text-base">
            Strength
          </CardTitle>
          <StrengthGauge score={strength.score} />
          <p className="mt-2 text-center text-xs text-fg-muted">
            zxcvbn score, 0 (very weak) to 4 (very strong)
          </p>
        </Card>
        <Card>
          <CardTitle level={headingLevel} className="mb-4 text-base">
            Risk
          </CardTitle>
          <RiskMeter score={risk.score} level={risk.level} />
          <div className="mt-5 flex flex-wrap gap-2">
            <Badge tone={policy.compliant ? 'success' : 'danger'} dot>
              {policy.compliant
                ? 'Policy met'
                : `${String(policy.violations.length)} rule${policy.violations.length === 1 ? '' : 's'} broken`}
            </Badge>
            <Badge
              tone={analysis.meets_usage_target ? 'success' : 'warning'}
              dot
              icon={<Target aria-hidden="true" className="size-3" />}
            >
              {analysis.meets_usage_target ? 'Meets usage target' : 'Below usage target'}
            </Badge>
          </div>
        </Card>
        <Card>
          <Heading className="mb-3 text-base font-semibold">At a glance</Heading>
          <dl className="space-y-3 text-sm">
            <div className="flex justify-between gap-4">
              <dt className="text-fg-muted">Length</dt>
              <dd className="tabular font-medium">{analysis.length} characters</dd>
            </div>
            <div className="flex justify-between gap-4">
              <dt className="text-fg-muted">Estimated entropy</dt>
              <dd className="tabular font-medium">{formatBits(entropy.estimated_bits)}</dd>
            </div>
            <div className="flex justify-between gap-4">
              <dt className="text-fg-muted">Guesses needed</dt>
              <dd className="tabular font-medium">{formatGuesses(strength.guesses_log10)}</dd>
            </div>
            <div className="flex justify-between gap-4">
              <dt className="text-fg-muted">Offline (fast hash)</dt>
              <dd className="font-medium">{strength.crack_times.offline_fast_hash}</dd>
            </div>
            <div className="flex justify-between gap-4">
              <dt className="text-fg-muted">Patterns found</dt>
              <dd className="tabular font-medium">{findings.length}</dd>
            </div>
          </dl>
          <p className="mt-4 flex items-start gap-2 text-xs text-fg-muted">
            {findings.length === 0 && policy.compliant ? (
              <CheckCircle2 aria-hidden="true" className="mt-0.5 size-4 shrink-0 text-success" />
            ) : (
              <ShieldCheck aria-hidden="true" className="mt-0.5 size-4 shrink-0 text-fg-subtle" />
            )}
            Estimates, not guarantees - see the limitations under Strength details.
          </p>
        </Card>
      </div>

      {analysis.exposure && (
        <div className="mt-4">
          <ExposureView exposure={analysis.exposure} headingLevel={headingLevel} />
        </div>
      )}

      <Card className="mt-4">
        <CardDescription className="sr-only">Detailed results</CardDescription>
        <Tabs
          label="Analysis details"
          tabs={[
            { id: 'patterns', label: 'Patterns', count: findings.length, content: patternsTab },
            { id: 'risk', label: 'Risk breakdown', content: riskTab },
            { id: 'strength', label: 'Strength details', content: strengthTab },
            {
              id: 'advice',
              label: 'Recommendations',
              count: recommendations.length,
              content: recommendationsTab,
            },
            { id: 'policy', label: 'Policy', count: policy.violations.length, content: policyTab },
          ]}
        />
      </Card>
    </div>
  );
}
