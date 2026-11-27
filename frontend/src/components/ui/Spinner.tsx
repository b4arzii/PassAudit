import { cn } from '../../lib/cn.ts';

export interface SpinnerProps {
  size?: 'sm' | 'md' | 'lg';
  /** Announced to screen readers. Pass `null` for a purely decorative spinner (e.g. inside a
   * button that already carries `aria-busy`). */
  label?: string | null;
  className?: string;
}

const SIZES = { sm: 'size-4', md: 'size-6', lg: 'size-10' } as const;

export function Spinner({ size = 'md', label = 'Loading', className }: SpinnerProps) {
  const svg = (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      aria-hidden="true"
      className={cn('animate-spin motion-reduce:animate-none', SIZES[size], className)}
    >
      <circle cx="12" cy="12" r="9" stroke="currentColor" strokeOpacity="0.2" strokeWidth="3" />
      <path d="M21 12a9 9 0 0 0-9-9" stroke="currentColor" strokeWidth="3" strokeLinecap="round" />
    </svg>
  );
  if (label === null) return svg;
  return (
    <span role="status" className="inline-flex items-center">
      {svg}
      <span className="sr-only">{label}</span>
    </span>
  );
}
