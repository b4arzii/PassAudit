import { Gauge, Repeat2, ShieldAlert, ShieldCheck, Users } from 'lucide-react';

import { formatPercent } from '../../lib/format.ts';
import { FINDING_LABEL, RISK_LABEL, RISK_ORDER } from '../../lib/labels.ts';
import { topEntries } from '../../lib/records.ts';
import type { RecordStats } from '../../lib/records.ts';
import { FINDING_STYLE, RISK_COLOR, RISK_HATCHED } from '../charts/chartColors.ts';
import { BarList } from '../charts/BarList.tsx';
import { Card, CardTitle, StatCard } from '../ui/index.ts';

/** Headline numbers plus risk and pattern distributions for a set of analysed passwords. */
export function SummaryPanel({ stats }: { stats: RecordStats }) {
  const findings = topEntries(stats.findings, 6);
  return (
    <div className="space-y-4">
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard label="Passwords analysed" value={stats.total} icon={<Users />} />
        <StatCard
          label="Average risk"
          value={stats.averageRisk ?? '-'}
          hint={stats.maxRisk === null ? undefined : `Highest: ${String(stats.maxRisk)} / 100`}
          icon={<Gauge />}
          tone={stats.averageRisk !== null && stats.averageRisk >= 40 ? 'danger' : 'default'}
        />
        <StatCard
          label="At high or critical risk"
          value={formatPercent(stats.riskLevels.high + stats.riskLevels.critical, stats.total)}
          hint={`${String(stats.riskLevels.high + stats.riskLevels.critical)} of ${String(stats.total)}`}
          icon={<ShieldAlert />}
          tone={stats.atRiskShare > 0 ? 'warning' : 'success'}
        />
        <StatCard
          label="Meet the policy"
          value={formatPercent(stats.compliant, stats.total)}
          hint={
            stats.reused > 0
              ? `${String(stats.reused)} reused in this set`
              : `${String(stats.compliant)} of ${String(stats.total)}`
          }
          icon={stats.reused > 0 ? <Repeat2 /> : <ShieldCheck />}
          tone={stats.compliant === stats.total && stats.total > 0 ? 'success' : 'default'}
        />
      </div>
      {(stats.breachChecked || stats.reuseChecked) && (
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
          {stats.breachChecked && (
            <StatCard
              label="Found in breach data"
              value={stats.breached}
              hint="Of those checked; not found is not a guarantee"
              icon={<ShieldAlert />}
              tone={stats.breached > 0 ? 'danger' : 'success'}
            />
          )}
          {stats.reuseChecked && (
            <StatCard
              label="Reused in datasets"
              value={stats.reusedInDatasets}
              hint="Present in an authorised local dataset"
              icon={<Repeat2 />}
              tone={stats.reusedInDatasets > 0 ? 'danger' : 'success'}
            />
          )}
        </div>
      )}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Card>
          <CardTitle level={3} className="mb-4 text-base">
            Risk levels
          </CardTitle>
          <BarList
            label="Passwords by risk level"
            items={RISK_ORDER.map((level) => ({
              key: level,
              label: RISK_LABEL[level],
              value: stats.riskLevels[level],
              color: RISK_COLOR[level],
              hatched: RISK_HATCHED[level],
            }))}
          />
        </Card>
        <Card>
          <CardTitle level={3} className="mb-4 text-base">
            Most common weaknesses
          </CardTitle>
          <BarList
            label="Weaknesses found, by number of passwords"
            emptyText="No patterns were detected."
            items={findings.map(([kind, count]) => ({
              key: kind,
              label: FINDING_LABEL[kind].title,
              value: count,
              color: FINDING_STYLE[kind].color,
            }))}
          />
        </Card>
      </div>
    </div>
  );
}
