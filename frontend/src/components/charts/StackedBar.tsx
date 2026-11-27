import { cn } from '../../lib/cn.ts';
import { Swatch } from './Hatch.tsx';

export interface StackSegment {
  key: string;
  label: string;
  value: number;
  /** Maximum this segment can contribute (shown as "points / max"). */
  max?: number | null;
  color: string;
  detail?: string;
}

export interface StackedBarProps {
  segments: readonly StackSegment[];
  /** What a full bar represents (e.g. 100). */
  total: number;
  /** Accessible name for the chart. */
  label: string;
  unit?: string;
  className?: string;
}

/** A single stacked bar plus a legend table listing each segment's value, max and explanation. */
export function StackedBar({
  segments,
  total,
  label,
  unit = 'points',
  className,
}: StackedBarProps) {
  const sum = segments.reduce((s, seg) => s + seg.value, 0);
  return (
    <div className={className}>
      <div
        role="img"
        aria-label={`${label}: ${String(sum)} of ${String(total)} ${unit}. ${
          segments
            .filter((s) => s.value > 0)
            .map((s) => `${s.label} ${String(s.value)}`)
            .join(', ') || 'none'
        }.`}
        className="flex h-4 overflow-hidden rounded-full bg-fg/10"
      >
        {segments.map((seg) =>
          seg.value > 0 ? (
            <div
              key={seg.key}
              style={{ width: `${String((seg.value / total) * 100)}%`, backgroundColor: seg.color }}
              className="border-r border-canvas/50 last:border-r-0"
            />
          ) : null,
        )}
      </div>
      <ul className="mt-4 divide-y divide-line/10 text-sm">
        {segments.map((seg) => (
          <li
            key={seg.key}
            className={cn(
              'flex items-start justify-between gap-4 py-2.5',
              seg.value === 0 && 'opacity-70',
            )}
          >
            <div className="flex min-w-0 items-start gap-2">
              <Swatch color={seg.color} className="mt-1.5 size-2.5" />
              <div className="min-w-0">
                <p className="font-medium text-fg">{seg.label}</p>
                {seg.detail && <p className="text-xs text-fg-muted">{seg.detail}</p>}
              </div>
            </div>
            <p className="tabular shrink-0 font-medium text-fg">
              {seg.value}
              {seg.max !== undefined && seg.max !== null && (
                <span className="text-fg-subtle"> / {seg.max}</span>
              )}
            </p>
          </li>
        ))}
      </ul>
    </div>
  );
}
