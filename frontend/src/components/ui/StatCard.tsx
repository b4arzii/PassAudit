import type { ReactNode } from 'react';

import { cn } from '../../lib/cn.ts';
import { Skeleton } from './Loading.tsx';

export interface StatCardProps {
  label: string;
  value: ReactNode;
  /** Secondary line: a unit, comparison or explanation. */
  hint?: ReactNode;
  icon?: ReactNode;
  tone?: 'default' | 'success' | 'warning' | 'danger' | 'primary';
  /** Show a skeleton instead of the value (and mark the card busy). */
  loading?: boolean;
  className?: string;
}

const TONE_TEXT = {
  default: 'text-fg',
  primary: 'text-primary',
  success: 'text-success',
  warning: 'text-warning',
  danger: 'text-danger',
} as const;

/**
 * A single headline number. Rendered as a labelled group so a screen reader hears
 * "Average risk: 37.5, out of 100" as one unit rather than three loose fragments.
 */
export function StatCard({
  label,
  value,
  hint,
  icon,
  tone = 'default',
  loading = false,
  className,
}: StatCardProps) {
  return (
    <div
      role="group"
      aria-label={label}
      aria-busy={loading || undefined}
      className={cn(
        'relative rounded-2xl border border-line/10 bg-surface p-5 shadow-card',
        className,
      )}
    >
      <div className="mb-3 flex items-center justify-between gap-3">
        <p className="text-sm font-medium text-fg-muted">{label}</p>
        {icon && (
          <span
            aria-hidden="true"
            className="flex size-9 items-center justify-center rounded-xl bg-fg/5 text-fg-muted [&>svg]:size-4.5"
          >
            {icon}
          </span>
        )}
      </div>
      {loading ? (
        <Skeleton className="h-9 w-24" />
      ) : (
        <p className={cn('tabular text-3xl font-semibold tracking-tight', TONE_TEXT[tone])}>
          {value}
        </p>
      )}
      {hint && !loading && <p className="mt-1.5 text-xs text-fg-muted">{hint}</p>}
    </div>
  );
}
