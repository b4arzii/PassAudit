import { CHART_COLOR, STRENGTH_COLORS } from './chartColors.ts';
import { STRENGTH_SCORE_LABEL } from '../../lib/labels.ts';
import { clamp } from '../../lib/format.ts';

const CX = 100;
const CY = 100;
const RADIUS = 80;
const SEGMENTS = 5;
const SWEEP = 180; // a half-circle
const GAP = 5; // degrees between segments

function point(angleDeg: number): [number, number] {
  const rad = (angleDeg * Math.PI) / 180;
  return [CX + RADIUS * Math.cos(rad), CY + RADIUS * Math.sin(rad)];
}

function arc(from: number, to: number): string {
  const [x1, y1] = point(from);
  const [x2, y2] = point(to);
  return `M ${x1.toFixed(2)} ${y1.toFixed(2)} A ${String(RADIUS)} ${String(RADIUS)} 0 0 1 ${x2.toFixed(2)} ${y2.toFixed(2)}`;
}

export interface StrengthGaugeProps {
  /** zxcvbn score, 0-4. */
  score: number;
  className?: string;
}

/**
 * A segmented half-circle gauge for the 0-4 strength score. Segments up to and including the
 * score are filled; the number and label in the middle carry the meaning for everyone.
 */
export function StrengthGauge({ score, className }: StrengthGaugeProps) {
  const value = clamp(Math.round(score), 0, 4);
  const label = STRENGTH_SCORE_LABEL[value] ?? 'Unknown';
  const per = SWEEP / SEGMENTS;
  return (
    <figure
      className={className}
      aria-label={`Strength ${String(value)} out of 4: ${label}`}
      role="img"
    >
      <svg viewBox="0 0 200 118" className="mx-auto w-full max-w-[260px]" aria-hidden="true">
        {Array.from({ length: SEGMENTS }, (_, i) => {
          const start = 180 + i * per + GAP / 2;
          const end = 180 + (i + 1) * per - GAP / 2;
          const filled = i <= value;
          return (
            <path
              key={i}
              d={arc(start, end)}
              fill="none"
              strokeWidth="14"
              strokeLinecap="round"
              stroke={filled ? STRENGTH_COLORS[value] : CHART_COLOR.track}
              opacity={filled ? 1 : 0.9}
            />
          );
        })}
        <text
          x="100"
          y="86"
          textAnchor="middle"
          className="fill-fg"
          style={{ fontSize: 40, fontWeight: 600 }}
        >
          {value}
          <tspan className="fill-fg-subtle" style={{ fontSize: 16, fontWeight: 500 }}>
            /4
          </tspan>
        </text>
        <text
          x="100"
          y="108"
          textAnchor="middle"
          className="fill-fg-muted"
          style={{ fontSize: 13, fontWeight: 500 }}
        >
          {label}
        </text>
      </svg>
    </figure>
  );
}
