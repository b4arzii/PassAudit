import { useEffect, useState } from 'react';
import type { ReactNode } from 'react';

import { friendlyError } from '../../lib/errors.ts';
import { Alert, Button } from '../ui/index.ts';

export interface ErrorPanelProps {
  error: unknown;
  onRetry?: () => void;
  /** Offered only when the backend is unreachable. */
  onUseDemo?: () => void;
  onDismiss?: () => void;
  className?: string;
}

// Each distinct error object gets an id, so a fresh error restarts the retry countdown.
const errorIds = new WeakMap<object, number>();
let nextErrorId = 0;
function errorId(error: unknown): number {
  if (typeof error !== 'object' || error === null) return 0;
  let id = errorIds.get(error);
  if (id === undefined) {
    nextErrorId += 1;
    id = nextErrorId;
    errorIds.set(error, id);
  }
  return id;
}

/** A Retry button that stays disabled while the server-requested wait counts down. */
function RetryButton({ seconds, onRetry }: { seconds: number; onRetry: () => void }) {
  const [wait, setWait] = useState(seconds);
  const counting = wait > 0;
  useEffect(() => {
    if (!counting) return;
    const timer = window.setInterval(() => {
      setWait((w) => Math.max(0, w - 1));
    }, 1000);
    return () => {
      window.clearInterval(timer);
    };
  }, [counting]);
  return (
    <Button size="sm" variant="outline" onClick={onRetry} disabled={counting}>
      {counting ? `Retry in ${String(wait)}s` : 'Retry'}
    </Button>
  );
}

/** The one place API failures are shown. Errors are announced immediately (role="alert"). */
export function ErrorPanel({ error, onRetry, onUseDemo, onDismiss, className }: ErrorPanelProps) {
  const info = friendlyError(error);

  const actions: ReactNode[] = [];
  if (info.retryable && onRetry) {
    actions.push(
      <RetryButton
        key={`retry-${String(errorId(error))}`}
        seconds={info.retryAfter ?? 0}
        onRetry={onRetry}
      />,
    );
  }
  if (info.offline && onUseDemo) {
    actions.push(
      <Button key="demo" size="sm" variant="ghost" onClick={onUseDemo}>
        Preview with demo data
      </Button>,
    );
  }

  return (
    <Alert
      tone={info.tone}
      title={info.title}
      {...(onDismiss ? { onDismiss } : {})}
      {...(actions.length > 0
        ? { action: <div className="flex flex-wrap gap-2">{actions}</div> }
        : {})}
      className={className}
      // Warnings (rate limit, busy) are announced politely; hard errors assertively.
      role={info.tone === 'danger' ? 'alert' : 'status'}
    >
      <p>{info.message}</p>
      {info.issues.length > 0 && (
        <ul className="mt-2 list-disc space-y-1 pl-5">
          {info.issues.map((issue, i) => (
            <li key={`${issue.field}-${String(i)}`}>
              <span className="font-medium text-fg">{issue.field}:</span> {issue.message}
            </li>
          ))}
        </ul>
      )}
      {info.hints.length > 0 && (
        <ul className="mt-2 space-y-1">
          {info.hints.map((hint) => (
            <li key={hint}>{hint}</li>
          ))}
        </ul>
      )}
      {info.requestId && (
        <p className="mt-2 text-xs text-fg-subtle">
          Request ID: <code className="font-mono">{info.requestId}</code>
        </p>
      )}
    </Alert>
  );
}
