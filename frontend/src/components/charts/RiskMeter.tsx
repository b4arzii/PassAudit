import type { RiskLevel } from '../../api/types.ts';
import { clamp } from '../../lib/format.ts';
import { RISK_LABEL, RISK_LEVELS } from '../../lib/labels.ts';
import { RISK_COLOR, RISK_HATCHED } from './chartColors.ts';

export interface RiskMeterProps {
  score: number;
  level: RiskLevel;
  className?: string;
}

/**
 * The 0-100 risk score on a banded scale (low / moderate / high / critical). The band the score
 * falls in is emphasised, a marker shows the exact position, and the numeric score and level
 * name are always printed, so colour is never the only signal.
 */
export function RiskMeter({ score, level, className }: RiskMeterProps) {
  const value = clamp(score, 0, 100);
  return (
    <div className={className}>
      <div className="mb-3 flex items-baseline justify-between gap-3">
        <p className="tabular text-4xl font-semibold tracking-tight">
          {Math.round(value)}
          <span className="text-lg font-medium text-fg-subtle">/100</span>
        </p>
        <p className="text-sm font-semibold" style={{ color: RISK_COLOR[level] }}>
          {RISK_LABEL[level]} risk
        </p>
      </div>
      <div
        role="meter"
        aria-label="Risk score"
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={Math.round(value)}
        aria-valuetext={`${String(Math.round(value))} out of 100, ${RISK_LABEL[level]} risk`}
        className="relative"
      >
        <div className="flex h-3 overflow-hidden rounded-full" aria-hidden="true">
          {RISK_LEVELS.map((band) => {
            const width = band.to + 1 - band.from;
            const active = band.level === level;
            const color = RISK_COLOR[band.level];
            return (
              <div
                key={band.level}
                style={{
                  width: `${String(width)}%`,
                  backgroundColor: color,
                  opacity: active ? 1 : 0.28,
                  ...(RISK_HATCHED[band.level]
                    ? {
                        backgroundImage: `repeating-linear-gradient(45deg, rgb(0 0 0 / 0.28) 0 3px, transparent 3px 6px)`,
                      }
                    : {}),
                }}
                className="border-r border-canvas/60 last:border-r-0"
              />
            );
          })}
        </div>
        <div
          aria-hidden="true"
          className="absolute -top-1 h-5 w-1 -translate-x-1/2 rounded-full bg-fg shadow-[0_0_0_2px_rgb(var(--canvas))]"
          style={{ left: `${String(value)}%` }}
        />
      </div>
      <div className="mt-2 flex text-xs text-fg-subtle" aria-hidden="true">
        {RISK_LEVELS.map((band) => (
          <span
            key={band.level}
            style={{ width: `${String(band.to + 1 - band.from)}%` }}
            className="tabular"
          >
            {band.from}
          </span>
        ))}
      </div>
    </div>
  );
}
