import { ArrowDown, ArrowUp, ChevronsUpDown } from 'lucide-react';
import type { ComponentPropsWithRef, ReactNode } from 'react';

import { cn } from '../../lib/cn.ts';

export interface TableProps extends ComponentPropsWithRef<'table'> {
  /**
   * Accessible name for the scrollable region around the table. A horizontally scrollable
   * region must be focusable so keyboard users can scroll it, and focusable regions need a name.
   */
  label: string;
  /** A visible caption is announced with the table; use it when the context is not obvious. */
  caption?: ReactNode;
  wrapperClassName?: string;
}

export function Table({
  label,
  caption,
  className,
  wrapperClassName,
  children,
  ...rest
}: TableProps) {
  return (
    <div
      role="region"
      aria-label={label}
      tabIndex={0}
      className={cn(
        'overflow-x-auto rounded-2xl border border-line/10 bg-surface shadow-card',
        wrapperClassName,
      )}
    >
      <table className={cn('w-full border-collapse text-left text-sm', className)} {...rest}>
        {caption && <caption className="sr-only">{caption}</caption>}
        {children}
      </table>
    </div>
  );
}

export function THead({ className, ...rest }: ComponentPropsWithRef<'thead'>) {
  return <thead className={cn('border-b border-line/10 bg-surface-2/70', className)} {...rest} />;
}

export function TBody({ className, ...rest }: ComponentPropsWithRef<'tbody'>) {
  return <tbody className={cn('divide-y divide-line/10', className)} {...rest} />;
}

export function TR({ className, ...rest }: ComponentPropsWithRef<'tr'>) {
  return <tr className={cn('transition-colors hover:bg-fg/[0.03]', className)} {...rest} />;
}

export type SortDirection = 'ascending' | 'descending' | 'none';

export interface THProps extends Omit<ComponentPropsWithRef<'th'>, 'onClick'> {
  /** Present on a sortable column: the current direction. */
  sort?: SortDirection;
  /** Called when the column header button is activated. */
  onSort?: () => void;
  align?: 'left' | 'right';
}

const TH_BASE = 'px-4 py-3 text-xs font-semibold uppercase tracking-wider text-fg-muted';

/** A column header. With `sort`, it renders a button and sets `aria-sort` on the `<th>`. */
export function TH({ sort, onSort, align = 'left', className, children, ...rest }: THProps) {
  const sortable = sort !== undefined;
  const Icon = sort === 'ascending' ? ArrowUp : sort === 'descending' ? ArrowDown : ChevronsUpDown;
  return (
    <th
      scope="col"
      aria-sort={sortable ? sort : undefined}
      className={cn(TH_BASE, align === 'right' && 'text-right', className)}
      {...rest}
    >
      {sortable ? (
        <button
          type="button"
          onClick={onSort}
          className={cn(
            '-mx-2 inline-flex items-center gap-1.5 rounded-md px-2 py-1 uppercase tracking-wider transition-colors hover:text-fg',
            sort !== 'none' && 'text-fg',
          )}
        >
          {children}
          <Icon aria-hidden="true" className="size-3.5" />
        </button>
      ) : (
        children
      )}
    </th>
  );
}

export function TD({
  align = 'left',
  className,
  ...rest
}: ComponentPropsWithRef<'td'> & { align?: 'left' | 'right' }) {
  return (
    <td
      className={cn(
        'px-4 py-3.5 align-middle text-fg',
        align === 'right' && 'text-right',
        className,
      )}
      {...rest}
    />
  );
}

/** A full-width row for "nothing here". */
export function TableEmpty({ colSpan, children }: { colSpan: number; children: ReactNode }) {
  return (
    <tr>
      <td colSpan={colSpan} className="px-4 py-12 text-center text-sm text-fg-muted">
        {children}
      </td>
    </tr>
  );
}

/** Skeleton rows while data loads. Mark the `<Table>` (or its parent) `aria-busy`. */
export function TableSkeletonRows({ rows = 4, columns }: { rows?: number; columns: number }) {
  return (
    <>
      {Array.from({ length: rows }, (_, r) => (
        <tr key={r} aria-hidden="true">
          {Array.from({ length: columns }, (_, c) => (
            <td key={c} className="px-4 py-4">
              <div className="h-3.5 animate-pulse rounded bg-fg/10 motion-reduce:animate-none" />
            </td>
          ))}
        </tr>
      ))}
    </>
  );
}
