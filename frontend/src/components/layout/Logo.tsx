import { useId } from 'react';

import { cn } from '../../lib/cn.ts';

/** The PassAudit mark: a shield with a padlock, in the brand gradient. Decorative. */
export function LogoMark({ className }: { className?: string }) {
  const gradient = useId();
  return (
    <svg viewBox="0 0 64 64" aria-hidden="true" className={cn('size-9 shrink-0', className)}>
      <defs>
        <linearGradient id={gradient} x1="8" y1="4" x2="56" y2="60" gradientUnits="userSpaceOnUse">
          <stop stopColor="rgb(var(--primary))" />
          <stop offset="1" stopColor="rgb(var(--cyan))" />
        </linearGradient>
      </defs>
      <path
        d="M32 6 12 14v17c0 12.6 8.2 22.3 20 26.5C43.8 53.3 52 43.6 52 31V14L32 6Z"
        fill={`url(#${gradient})`}
      />
      <rect x="23" y="28" width="18" height="14" rx="3.5" fill="rgb(var(--canvas))" />
      <path
        d="M27 28v-4a5 5 0 0 1 10 0v4"
        fill="none"
        stroke="rgb(var(--canvas))"
        strokeWidth="3.4"
        strokeLinecap="round"
      />
    </svg>
  );
}

export function Logo({ showText = true, className }: { showText?: boolean; className?: string }) {
  return (
    <span className={cn('inline-flex items-center gap-2.5', className)}>
      <LogoMark />
      {showText ? (
        <span className="text-lg font-semibold tracking-tight text-fg">
          Pass<span className="gradient-text">Audit</span>
        </span>
      ) : (
        <span className="sr-only">PassAudit</span>
      )}
    </span>
  );
}
