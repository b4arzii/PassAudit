import { ChevronLeft, ChevronRight } from 'lucide-react';

import { pageCount } from '../../lib/paginate.ts';
import { IconButton } from './Button.tsx';

export interface PaginationProps {
  page: number; // 1-based
  pageSize: number;
  total: number;
  onPageChange: (page: number) => void;
  /** Noun for the summary, e.g. "passwords". */
  noun?: string;
}

export function Pagination({
  page,
  pageSize,
  total,
  onPageChange,
  noun = 'results',
}: PaginationProps) {
  const pages = pageCount(total, pageSize);
  const from = total === 0 ? 0 : (page - 1) * pageSize + 1;
  const to = Math.min(total, page * pageSize);
  return (
    <nav
      aria-label="Pagination"
      className="flex items-center justify-between gap-3 px-1 pt-3 text-sm text-fg-muted"
    >
      <p aria-live="polite" className="tabular">
        Showing {from}-{to} of {total} {noun}
      </p>
      <div className="flex items-center gap-1">
        <IconButton
          label="Previous page"
          size="sm"
          disabled={page <= 1}
          onClick={() => {
            onPageChange(page - 1);
          }}
        >
          <ChevronLeft aria-hidden="true" className="size-4" />
        </IconButton>
        <span className="tabular px-2">
          Page {page} of {pages}
        </span>
        <IconButton
          label="Next page"
          size="sm"
          disabled={page >= pages}
          onClick={() => {
            onPageChange(page + 1);
          }}
        >
          <ChevronRight aria-hidden="true" className="size-4" />
        </IconButton>
      </div>
    </nav>
  );
}
