import { ChevronRight } from 'lucide-react';
import type { ReactNode } from 'react';

import { cn } from '../../lib/cn.ts';

export interface DisclosureProps {
  summary: ReactNode;
  children: ReactNode;
  defaultOpen?: boolean;
  className?: string;
}

/** A native `<details>`: keyboard and screen-reader behaviour for free, styled to match. */
export function Disclosure({ summary, children, defaultOpen = false, className }: DisclosureProps) {
  return (
    <details
      open={defaultOpen}
      className={cn('group rounded-xl border border-line/10 bg-surface-2/50', className)}
    >
      <summary className="flex min-h-11 cursor-pointer list-none items-center gap-2 rounded-xl px-4 py-2.5 text-sm font-medium text-fg marker:hidden [&::-webkit-details-marker]:hidden">
        <ChevronRight
          aria-hidden="true"
          className="size-4 shrink-0 text-fg-subtle transition-transform group-open:rotate-90 motion-reduce:transition-none"
        />
        {summary}
      </summary>
      <div className="border-t border-line/10 px-4 py-4 text-sm text-fg-muted">{children}</div>
    </details>
  );
}
