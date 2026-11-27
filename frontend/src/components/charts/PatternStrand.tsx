import type { Finding } from '../../api/types.ts';
import { cn } from '../../lib/cn.ts';
import { formatRange } from '../../lib/format.ts';
import { FINDING_LABEL, FINDING_PRIORITY } from '../../lib/labels.ts';
import { kindsByPosition } from '../../lib/patterns.ts';
import { FINDING_STYLE } from './chartColors.ts';

const MAX_CELLS = 96;

export interface PatternStrandProps {
  length: number;
  findings: readonly Finding[];
  className?: string;
}

/**
 * Shows *where* weaknesses sit in the password without ever showing the password: one cell per
 * character (masked), coloured and lettered by the pattern that covers it. The legend list
 * under it states every range in words and is the accessible version of the picture.
 */
export function PatternStrand({ length, findings, className }: PatternStrandProps) {
  const kinds = kindsByPosition(length, findings);
  const flagged = kinds.filter((k) => k !== null).length;
  const present = [...new Set(findings.map((f) => f.kind))].sort(
    (a, b) => FINDING_PRIORITY.indexOf(a) - FINDING_PRIORITY.indexOf(b),
  );
  const condensed = length > MAX_CELLS;

  return (
    <div className={className}>
      <p className="mb-3 text-sm text-fg-muted">
        {length === 0
          ? 'The password is empty.'
          : `${String(flagged)} of ${String(length)} characters are covered by a detected pattern. Characters are masked - the password itself is never shown.`}
      </p>

      {/* Visual only: the list below carries the same information as text. */}
      <div aria-hidden="true">
        {condensed ? (
          <div className="relative h-5 overflow-hidden rounded-md bg-fg/10">
            {findings.map((f, i) => (
              <div
                key={`${f.kind}-${String(f.start)}-${String(i)}`}
                className={cn('absolute inset-y-0 opacity-90', FINDING_STYLE[f.kind].bg)}
                style={{
                  left: `${String((f.start / length) * 100)}%`,
                  width: `${String(Math.max(0.8, (f.length / length) * 100))}%`,
                }}
              />
            ))}
          </div>
        ) : (
          <div className="flex flex-wrap gap-1">
            {kinds.map((kind, i) => (
              <span
                key={i}
                className={cn(
                  'flex size-6 items-center justify-center rounded-md font-mono text-[11px] font-semibold',
                  kind === null
                    ? 'bg-fg/10 text-fg-subtle'
                    : cn(FINDING_STYLE[kind].bg, 'text-canvas'),
                )}
              >
                {kind === null ? '•' : FINDING_STYLE[kind].letter}
              </span>
            ))}
          </div>
        )}
      </div>

      {present.length > 0 ? (
        <ul className="mt-4 space-y-2 text-sm" aria-label="Detected patterns and where they occur">
          {present.map((kind) => {
            const ranges = findings.filter((f) => f.kind === kind);
            return (
              <li key={kind} className="flex items-start gap-3">
                <span
                  aria-hidden="true"
                  className={cn(
                    'mt-0.5 flex size-5 shrink-0 items-center justify-center rounded font-mono text-[11px] font-semibold text-canvas',
                    FINDING_STYLE[kind].bg,
                  )}
                >
                  {FINDING_STYLE[kind].letter}
                </span>
                <span className="text-fg-muted">
                  <span className="font-medium text-fg">{FINDING_LABEL[kind].title}</span> -{' '}
                  {ranges.map((r) => formatRange(r.start, r.length)).join(', ')}
                </span>
              </li>
            );
          })}
        </ul>
      ) : (
        length > 0 && (
          <p className="mt-4 text-sm text-success">
            No repeated, sequential, keyboard or dictionary patterns were detected.
          </p>
        )
      )}
    </div>
  );
}
