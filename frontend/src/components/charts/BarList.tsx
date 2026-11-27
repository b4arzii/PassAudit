import { cn } from '../../lib/cn.ts';
import { Swatch } from './Hatch.tsx';

export interface BarItem {
  key: string;
  label: string;
  value: number;
  /** CSS colour for the bar. */
  color: string;
  hatched?: boolean;
  /** Small text under the label. */
  hint?: string;
}

export interface BarListProps {
  items: readonly BarItem[];
  /** Scale maximum; defaults to the largest value. */
  max?: number;
  /** Accessible name for the list. */
  label: string;
  /** Shown when every value is zero / there are no items. */
  emptyText?: string;
  className?: string;
}

/**
 * Horizontal bars as a labelled list. The number is printed beside every bar, so the chart is
 * fully readable as text; the bar is a visual aid (`aria-hidden`).
 */
export function BarList({
  items,
  max,
  label,
  emptyText = 'Nothing to show yet.',
  className,
}: BarListProps) {
  const scale = max ?? Math.max(1, ...items.map((i) => i.value));
  const empty = items.length === 0 || items.every((i) => i.value === 0);
  if (empty) return <p className={cn('text-sm text-fg-muted', className)}>{emptyText}</p>;
  return (
    <ul aria-label={label} className={cn('space-y-3', className)}>
      {items.map((item) => (
        <li key={item.key}>
          <div className="mb-1.5 flex items-baseline justify-between gap-3 text-sm">
            <span className="flex min-w-0 items-center gap-2 text-fg">
              <Swatch color={item.color} hatched={item.hatched ?? false} />
              <span className="truncate">{item.label}</span>
            </span>
            <span className="tabular shrink-0 font-medium text-fg">{item.value}</span>
          </div>
          <div aria-hidden="true" className="h-2 overflow-hidden rounded-full bg-fg/10">
            <div
              className="h-full rounded-full transition-[width] duration-500 motion-reduce:transition-none"
              style={{
                width: `${String(Math.min(100, (item.value / scale) * 100))}%`,
                backgroundColor: item.color,
                ...(item.hatched
                  ? {
                      backgroundImage:
                        'repeating-linear-gradient(45deg, rgb(0 0 0 / 0.3) 0 3px, transparent 3px 6px)',
                    }
                  : {}),
              }}
            />
          </div>
          {item.hint && <p className="mt-1 text-xs text-fg-muted">{item.hint}</p>}
        </li>
      ))}
    </ul>
  );
}
