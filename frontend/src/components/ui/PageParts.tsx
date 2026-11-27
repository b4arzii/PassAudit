import type { ComponentPropsWithRef, ElementType, ReactNode } from 'react';

import { cn } from '../../lib/cn.ts';
import type { HeadingLevel } from './Card.tsx';

export interface PageHeaderProps {
  title: string;
  description?: ReactNode;
  /** Small label above the title, e.g. the section name. */
  eyebrow?: ReactNode;
  /** Right-aligned actions (buttons). */
  actions?: ReactNode;
  className?: string;
}

/** The single `<h1>` of a page. */
export function PageHeader({ title, description, eyebrow, actions, className }: PageHeaderProps) {
  return (
    <header
      className={cn(
        'mb-8 flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between',
        className,
      )}
    >
      <div className="min-w-0">
        {eyebrow && (
          <p className="mb-2 text-xs font-semibold uppercase tracking-[0.14em] text-primary">
            {eyebrow}
          </p>
        )}
        <h1 className="text-3xl font-semibold tracking-tight sm:text-4xl">{title}</h1>
        {description && <p className="mt-2 max-w-2xl text-base text-fg-muted">{description}</p>}
      </div>
      {actions && <div className="flex shrink-0 flex-wrap items-center gap-3">{actions}</div>}
    </header>
  );
}

export interface SectionProps extends Omit<ComponentPropsWithRef<'section'>, 'title'> {
  title: string;
  description?: ReactNode;
  level?: HeadingLevel;
  headingId: string;
}

/** A labelled region: `<section aria-labelledby>` with a heading. */
export function Section({
  title,
  description,
  level = 2,
  headingId,
  className,
  children,
  ...rest
}: SectionProps) {
  const Heading = `h${String(level)}` as ElementType;
  return (
    <section aria-labelledby={headingId} className={cn('scroll-mt-24', className)} {...rest}>
      <div className="mb-4">
        <Heading id={headingId} className="text-xl font-semibold">
          {title}
        </Heading>
        {description && <p className="mt-1 max-w-2xl text-sm text-fg-muted">{description}</p>}
      </div>
      {children}
    </section>
  );
}

export interface EmptyStateProps {
  icon?: ReactNode;
  title: string;
  description?: ReactNode;
  action?: ReactNode;
  className?: string;
  /** Heading level for the title (default 2: below the page's h1). */
  level?: HeadingLevel;
}

export function EmptyState({
  icon,
  title,
  description,
  action,
  className,
  level = 2,
}: EmptyStateProps) {
  const Heading = `h${String(level)}` as ElementType;
  return (
    <div
      className={cn(
        'flex flex-col items-center rounded-2xl border border-dashed border-line/20 px-6 py-14 text-center',
        className,
      )}
    >
      {icon && (
        <div
          aria-hidden="true"
          className="mb-5 flex size-14 items-center justify-center rounded-2xl bg-brand-gradient-soft text-primary ring-1 ring-line/10"
        >
          {icon}
        </div>
      )}
      <Heading className="text-lg font-semibold">{title}</Heading>
      {description && <p className="mt-2 max-w-md text-sm text-fg-muted">{description}</p>}
      {action && <div className="mt-6">{action}</div>}
    </div>
  );
}

export function Separator({ className }: { className?: string }) {
  return <hr className={cn('border-0 border-t border-line/10', className)} />;
}

export function Kbd({ className, ...rest }: ComponentPropsWithRef<'kbd'>) {
  return (
    <kbd
      className={cn(
        'inline-flex min-w-6 items-center justify-center rounded-md border border-line/20 bg-surface-3 px-1.5 py-0.5 font-mono text-xs text-fg-muted',
        className,
      )}
      {...rest}
    />
  );
}
