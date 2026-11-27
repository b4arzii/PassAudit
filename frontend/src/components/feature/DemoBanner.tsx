import { FlaskConical } from 'lucide-react';

import { DEMO_EXPLANATION } from '../../demo/demo.ts';
import { cn } from '../../lib/cn.ts';
import { Badge, Button } from '../ui/index.ts';

/** A small marker placed next to any figure, chart or table that shows demo data. */
export function DemoBadge({ className }: { className?: string }) {
  return (
    <Badge
      tone="secondary"
      size="sm"
      icon={<FlaskConical aria-hidden="true" className="size-3" />}
      className={className}
    >
      Demo data
    </Badge>
  );
}

export interface DemoBannerProps {
  /** Why demo data is showing, e.g. "The backend is not connected." */
  reason?: string;
  /** Lets the user switch demo data off again. */
  onExit?: () => void;
  className?: string;
}

/**
 * The persistent notice shown above every page section that displays synthetic data. It is a
 * status region with a distinctive style, so demo data can never be mistaken for a real audit.
 */
export function DemoBanner({ reason, onExit, className }: DemoBannerProps) {
  return (
    <div
      role="status"
      data-demo-banner=""
      className={cn(
        'flex flex-col gap-3 rounded-xl border border-dashed border-secondary/60 bg-secondary/10 p-4 sm:flex-row sm:items-center sm:justify-between',
        className,
      )}
    >
      <div className="flex items-start gap-3">
        <FlaskConical aria-hidden="true" className="mt-0.5 size-5 shrink-0 text-secondary" />
        <div className="text-sm">
          <p className="font-semibold text-fg">
            You are viewing <span className="text-secondary">demo data</span>
          </p>
          <p className="mt-0.5 text-fg-muted">
            {reason ? `${reason} ` : ''}
            {DEMO_EXPLANATION}
          </p>
        </div>
      </div>
      {onExit && (
        <Button size="sm" variant="outline" onClick={onExit} className="shrink-0">
          Hide demo data
        </Button>
      )}
    </div>
  );
}
