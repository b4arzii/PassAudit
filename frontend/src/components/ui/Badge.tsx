import type { ComponentPropsWithRef, ReactNode } from 'react';

import { cn } from '../../lib/cn.ts';

export type BadgeTone =
  'neutral' | 'primary' | 'secondary' | 'accent' | 'success' | 'warning' | 'danger';

export interface BadgeProps extends ComponentPropsWithRef<'span'> {
  tone?: BadgeTone;
  size?: 'sm' | 'md';
  /** A coloured dot before the label. Never the only carrier of meaning: keep the text. */
  dot?: boolean;
  icon?: ReactNode;
  /** Outline style instead of a tinted fill. */
  outline?: boolean;
}

/** Tinted fill + coloured text/border. Text colours are checked for contrast in tokens.test.ts. */
const TONES: Record<BadgeTone, { fill: string; outline: string; dot: string }> = {
  neutral: {
    fill: 'bg-fg/10 text-fg-muted',
    outline: 'border-line/25 text-fg-muted',
    dot: 'bg-fg-muted',
  },
  primary: {
    fill: 'bg-primary/15 text-primary',
    outline: 'border-primary/50 text-primary',
    dot: 'bg-primary',
  },
  secondary: {
    fill: 'bg-secondary/15 text-secondary',
    outline: 'border-secondary/50 text-secondary',
    dot: 'bg-secondary',
  },
  accent: {
    fill: 'bg-accent/15 text-accent',
    outline: 'border-accent/50 text-accent',
    dot: 'bg-accent',
  },
  success: {
    fill: 'bg-success/15 text-success',
    outline: 'border-success/50 text-success',
    dot: 'bg-success',
  },
  warning: {
    fill: 'bg-warning/15 text-warning',
    outline: 'border-warning/50 text-warning',
    dot: 'bg-warning',
  },
  danger: {
    fill: 'bg-danger/15 text-danger',
    outline: 'border-danger/50 text-danger',
    dot: 'bg-danger',
  },
};

export function Badge({
  tone = 'neutral',
  size = 'md',
  dot = false,
  icon,
  outline = false,
  className,
  children,
  ...rest
}: BadgeProps) {
  const palette = TONES[tone];
  return (
    <span
      className={cn(
        'inline-flex w-fit items-center gap-1.5 whitespace-nowrap rounded-full font-medium',
        size === 'sm' ? 'px-2 py-0.5 text-xs' : 'px-2.5 py-1 text-xs',
        outline ? cn('border bg-transparent', palette.outline) : palette.fill,
        className,
      )}
      {...rest}
    >
      {dot && <span aria-hidden="true" className={cn('size-1.5 rounded-full', palette.dot)} />}
      {icon}
      {children}
    </span>
  );
}
