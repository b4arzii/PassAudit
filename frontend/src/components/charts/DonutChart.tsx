import { useId } from 'react';

import { cn } from '../../lib/cn.ts';
import { formatPercent } from '../../lib/format.ts';
import { CHART_COLOR } from './chartColors.ts';
import { HatchPattern, Swatch } from './Hatch.tsx';

export interface DonutItem {
  key: string;
  label: string;
  value: number;
  color: string;
  hatched?: boolean;
}

export interface DonutChartProps {
  items: readonly DonutItem[];
  /** Large number in the middle, e.g. the total. */
  centerValue: string;
  centerLabel: string;
  /** Accessible summary; the legend below is the full text alternative. */
  ariaLabel: string;
  className?: string;
}

const R = 15.915; // circumference = 100, so dash arrays are percentages
const STROKE = 6.5;

/** A donut with a legend that lists every value as text (the legend is the accessible data). */
export function DonutChart({
  items,
  centerValue,
  centerLabel,
  ariaLabel,
  className,
}: DonutChartProps) {
  const patternBase = useId();
  const total = items.reduce((sum, item) => sum + item.value, 0);
  let offset = 0;
  return (
    <div className={cn('flex flex-col items-center gap-5 sm:flex-row sm:items-center', className)}>
      <figure role="img" aria-label={ariaLabel} className="relative size-40 shrink-0">
        <svg viewBox="0 0 42 42" className="size-full -rotate-90" aria-hidden="true">
          <defs>
            {items
              .filter((i) => i.hatched)
              .map((i) => (
                <HatchPattern key={i.key} id={`${patternBase}-${i.key}`} color={i.color} />
              ))}
          </defs>
          <circle
            cx="21"
            cy="21"
            r={R}
            fill="none"
            stroke={CHART_COLOR.track}
            strokeWidth={STROKE}
          />
          {total > 0 &&
            items.map((item) => {
              if (item.value <= 0) return null;
              const share = (item.value / total) * 100;
              const gap = items.filter((i) => i.value > 0).length > 1 ? 0.6 : 0;
              const dash = Math.max(0, share - gap);
              const node = (
                <circle
                  key={item.key}
                  cx="21"
                  cy="21"
                  r={R}
                  fill="none"
                  stroke={item.hatched ? `url(#${patternBase}-${item.key})` : item.color}
                  strokeWidth={STROKE}
                  strokeDasharray={`${dash.toFixed(3)} ${(100 - dash).toFixed(3)}`}
                  strokeDashoffset={(-offset).toFixed(3)}
                />
              );
              offset += share;
              return node;
            })}
        </svg>
        <figcaption className="absolute inset-0 flex flex-col items-center justify-center text-center">
          <span className="tabular text-3xl font-semibold tracking-tight">{centerValue}</span>
          <span className="text-xs text-fg-muted">{centerLabel}</span>
        </figcaption>
      </figure>
      <ul className="w-full min-w-0 flex-1 space-y-2 text-sm">
        {items.map((item) => (
          <li key={item.key} className="flex items-center justify-between gap-3">
            <span className="flex min-w-0 items-center gap-2 text-fg-muted">
              <Swatch color={item.color} hatched={item.hatched ?? false} />
              <span className="truncate">{item.label}</span>
            </span>
            <span className="tabular shrink-0 text-fg">
              {item.value}{' '}
              <span className="text-fg-subtle">({formatPercent(item.value, total)})</span>
            </span>
          </li>
        ))}
      </ul>
    </div>
  );
}
