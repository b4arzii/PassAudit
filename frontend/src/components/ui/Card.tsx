import type { ComponentPropsWithRef, ElementType, ReactNode } from 'react';

import { cn } from '../../lib/cn.ts';

export type CardVariant = 'solid' | 'glass' | 'outline';
export type CardAccent = 'none' | 'primary' | 'secondary' | 'accent';
export type HeadingLevel = 1 | 2 | 3 | 4 | 5 | 6;

export interface CardProps extends ComponentPropsWithRef<'div'> {
  /** Render as another element, e.g. `section` or `article`. */
  as?: ElementType;
  variant?: CardVariant;
  /** A coloured hairline and soft glow along the top edge. */
  accent?: CardAccent;
  /** Lifts on hover; use for cards that are (or contain) a link. */
  interactive?: boolean;
  padding?: 'none' | 'sm' | 'md' | 'lg';
}

const VARIANTS: Record<CardVariant, string> = {
  solid: 'border border-line/10 bg-surface shadow-card',
  glass: 'glass',
  outline: 'border border-line/15 bg-transparent',
};

const ACCENTS: Record<CardAccent, string> = {
  none: '',
  primary:
    'before:bg-gradient-to-r before:from-transparent before:via-primary/70 before:to-transparent',
  secondary:
    'before:bg-gradient-to-r before:from-transparent before:via-secondary/70 before:to-transparent',
  accent:
    'before:bg-gradient-to-r before:from-transparent before:via-accent/70 before:to-transparent',
};

const PADDING = { none: '', sm: 'p-4', md: 'p-5 sm:p-6', lg: 'p-6 sm:p-8' } as const;

export function Card({
  as,
  variant = 'solid',
  accent = 'none',
  interactive = false,
  padding = 'md',
  className,
  ...rest
}: CardProps) {
  const Component: ElementType = as ?? 'div';
  return (
    <Component
      className={cn(
        'relative rounded-2xl text-fg',
        VARIANTS[variant],
        accent !== 'none' && 'before:absolute before:inset-x-6 before:top-0 before:h-px',
        ACCENTS[accent],
        interactive &&
          'transition-[transform,border-color,box-shadow] duration-200 hover:-translate-y-0.5 hover:border-line/25 hover:shadow-pop motion-reduce:transform-none',
        PADDING[padding],
        className,
      )}
      {...rest}
    />
  );
}

export function CardHeader({ className, ...rest }: ComponentPropsWithRef<'div'>) {
  return <div className={cn('mb-4 flex items-start justify-between gap-4', className)} {...rest} />;
}

export interface CardTitleProps extends ComponentPropsWithRef<'h2'> {
  /** The document-outline level. Pick it from context, not from the desired size. */
  level?: HeadingLevel;
}

export function CardTitle({ level = 3, className, ...rest }: CardTitleProps) {
  const Heading = `h${String(level)}` as ElementType;
  return <Heading className={cn('text-lg font-semibold text-fg', className)} {...rest} />;
}

export function CardDescription({ className, ...rest }: ComponentPropsWithRef<'p'>) {
  return <p className={cn('mt-1 text-sm text-fg-muted', className)} {...rest} />;
}

export function CardContent({ className, ...rest }: ComponentPropsWithRef<'div'>) {
  return <div className={cn('text-sm text-fg-muted', className)} {...rest} />;
}

export function CardFooter({
  className,
  children,
  ...rest
}: ComponentPropsWithRef<'div'> & { children?: ReactNode }) {
  return (
    <div
      className={cn(
        'mt-5 flex flex-wrap items-center gap-3 border-t border-line/10 pt-4',
        className,
      )}
      {...rest}
    >
      {children}
    </div>
  );
}
