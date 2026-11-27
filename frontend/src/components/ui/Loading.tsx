import { cn } from '../../lib/cn.ts';

/**
 * A shimmering placeholder. Purely visual: it is hidden from assistive technology, so wrap a
 * group of skeletons in an element with `aria-busy` and a visible/sr-only status message.
 */
export function Skeleton({ className }: { className?: string }) {
  return (
    <div
      aria-hidden="true"
      className={cn(
        'relative overflow-hidden rounded-lg bg-fg/10',
        'after:absolute after:inset-0 after:-translate-x-full after:animate-shimmer after:bg-gradient-to-r',
        'after:from-transparent after:via-fg/10 after:to-transparent motion-reduce:after:hidden',
        className,
      )}
    />
  );
}

export function SkeletonText({ lines = 3, className }: { lines?: number; className?: string }) {
  return (
    <div aria-hidden="true" className={cn('space-y-2.5', className)}>
      {Array.from({ length: lines }, (_, index) => (
        <Skeleton
          key={index}
          className={cn('h-3.5', index === lines - 1 && lines > 1 ? 'w-2/3' : 'w-full')}
        />
      ))}
    </div>
  );
}

export interface ProgressProps {
  /** 0-100. Omit for an indeterminate bar. */
  value?: number;
  /** Accessible name, e.g. "Analysing passwords". */
  label: string;
  tone?: 'primary' | 'secondary' | 'accent';
  className?: string;
}

const TONES = {
  primary: 'bg-primary',
  secondary: 'bg-secondary',
  accent: 'bg-accent',
} as const;

export function Progress({ value, label, tone = 'primary', className }: ProgressProps) {
  const determinate = value !== undefined;
  const clamped = determinate ? Math.min(100, Math.max(0, value)) : undefined;
  return (
    <div
      role="progressbar"
      aria-label={label}
      aria-valuemin={0}
      aria-valuemax={100}
      aria-valuenow={clamped}
      className={cn('h-2 w-full overflow-hidden rounded-full bg-fg/10', className)}
    >
      <div
        className={cn(
          'h-full rounded-full transition-[width] duration-300',
          TONES[tone],
          !determinate && 'w-2/5 animate-indeterminate motion-reduce:animate-none',
        )}
        style={determinate ? { width: `${String(clamped)}%` } : undefined}
      />
    </div>
  );
}
