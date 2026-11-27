import { DatabaseZap, ShieldAlert, ShieldCheck, ShieldQuestion } from 'lucide-react';

import type { ExposureSignals } from '../../api/types.ts';
import { Alert, Badge, Card, CardTitle } from '../ui/index.ts';
import type { HeadingLevel } from '../ui/index.ts';

export interface ExposureViewProps {
  exposure: ExposureSignals;
  headingLevel?: HeadingLevel;
}

/**
 * The outcome of opt-in external checks. The wording is deliberate: "not found" is never shown
 * as "safe", and a check that did not complete is shown as UNCHECKED, never as clean.
 */
export function ExposureView({ exposure, headingLevel = 3 }: ExposureViewProps) {
  const { breach, reuse } = exposure;
  if (!breach && !reuse) return null;
  return (
    <Card>
      <CardTitle level={headingLevel} className="mb-4 text-base">
        External checks
      </CardTitle>
      <ul className="space-y-4">
        {breach && (
          <li className="flex items-start gap-3">
            {breach.status === 'breached' ? (
              <ShieldAlert aria-hidden="true" className="mt-0.5 size-5 shrink-0 text-danger" />
            ) : breach.status === 'clean' ? (
              <ShieldCheck aria-hidden="true" className="mt-0.5 size-5 shrink-0 text-success" />
            ) : (
              <ShieldQuestion aria-hidden="true" className="mt-0.5 size-5 shrink-0 text-warning" />
            )}
            <div className="space-y-2 text-sm">
              <p className="flex flex-wrap items-center gap-2 font-medium text-fg">
                Breach check ({breach.source === 'online' ? 'online, k-anonymity' : 'local dataset'}
                )
                <Badge
                  size="sm"
                  dot
                  tone={
                    breach.status === 'breached'
                      ? 'danger'
                      : breach.status === 'clean'
                        ? 'success'
                        : 'warning'
                  }
                >
                  {breach.status === 'breached'
                    ? 'Found in breaches'
                    : breach.status === 'clean'
                      ? 'Not found'
                      : 'Unchecked'}
                </Badge>
              </p>
              {breach.status === 'breached' && (
                <Alert tone="danger" title="This password is known to attackers">
                  It appears in breach data
                  {breach.count ? ` (seen at least ${breach.count.toLocaleString()} times)` : ''}.
                  Stop using it everywhere and choose a new, unique one.
                </Alert>
              )}
              {breach.status === 'clean' && (
                <p className="text-fg-muted">
                  Not found in the consulted corpus. That is not a guarantee: a password can be
                  exposed without appearing in this data.
                </p>
              )}
              {breach.status === 'unavailable' && (
                <p className="text-fg-muted">
                  The lookup did not complete, so this password is <strong>unchecked</strong> - this
                  says nothing about whether it was breached. Try again later.
                </p>
              )}
            </div>
          </li>
        )}
        {reuse && (
          <li className="flex items-start gap-3">
            <DatabaseZap
              aria-hidden="true"
              className={`mt-0.5 size-5 shrink-0 ${reuse.status === 'reused' ? 'text-danger' : 'text-success'}`}
            />
            <div className="space-y-1 text-sm">
              <p className="flex flex-wrap items-center gap-2 font-medium text-fg">
                Reuse check (authorised datasets)
                <Badge size="sm" dot tone={reuse.status === 'reused' ? 'danger' : 'success'}>
                  {reuse.status === 'reused' ? 'Reused' : 'Not found'}
                </Badge>
              </p>
              <p className="text-fg-muted">
                {reuse.status === 'reused'
                  ? `Also present in: ${reuse.sources.join(', ')}. One breach of any of them exposes every account sharing this password.`
                  : 'Not present in the datasets that were compared.'}
              </p>
            </div>
          </li>
        )}
      </ul>
    </Card>
  );
}
