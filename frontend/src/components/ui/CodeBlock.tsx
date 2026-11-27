import { cn } from '../../lib/cn.ts';

export interface CodeBlockProps {
  /** Accessible name; a scrollable region must be named and focusable. */
  label: string;
  code: string;
  className?: string;
}

export function CodeBlock({ label, code, className }: CodeBlockProps) {
  return (
    <pre
      role="region"
      aria-label={label}
      tabIndex={0}
      className={cn(
        'max-h-80 overflow-auto rounded-xl border border-line/10 bg-canvas/70 p-4 font-mono text-xs leading-relaxed text-fg-muted',
        className,
      )}
    >
      <code>{code}</code>
    </pre>
  );
}
