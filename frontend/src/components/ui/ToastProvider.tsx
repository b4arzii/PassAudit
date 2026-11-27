import { X } from 'lucide-react';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import { createPortal } from 'react-dom';

import { cn } from '../../lib/cn.ts';
import { TONE_STYLES } from './alertStyles.ts';
import { Button, IconButton } from './Button.tsx';
import { ToastContext } from './ToastContext.ts';
import type { ToastApi, ToastOptions, ToastTone } from './ToastContext.ts';

const MAX_VISIBLE = 4;
const DEFAULT_DURATION = 6000;
const DANGER_DURATION = 10000;

interface Announcement {
  key: number;
  text: string;
}

interface ToastRecord extends ToastOptions {
  id: string;
  tone: ToastTone;
}

const PROGRESS_COLOR: Record<ToastTone, string> = {
  info: 'bg-accent',
  success: 'bg-success',
  warning: 'bg-warning',
  danger: 'bg-danger',
};

function durationFor(toast: ToastRecord): number | null {
  if (toast.duration !== undefined) return toast.duration;
  return toast.tone === 'danger' ? DANGER_DURATION : DEFAULT_DURATION;
}

function ToastItem({ toast, onDismiss }: { toast: ToastRecord; onDismiss: (id: string) => void }) {
  const total = durationFor(toast);
  const [paused, setPaused] = useState(false);
  const remaining = useRef(total ?? 0);
  const startedAt = useRef(0);
  const { icon: Icon, text } = TONE_STYLES[toast.tone];

  // Count down, pausing while the pointer is over the toast or focus is inside it (so a user
  // reading or reaching for the action button is never raced).
  useEffect(() => {
    if (total === null || paused) return;
    startedAt.current = Date.now();
    const timer = window.setTimeout(() => {
      onDismiss(toast.id);
    }, remaining.current);
    return () => {
      window.clearTimeout(timer);
      remaining.current = Math.max(0, remaining.current - (Date.now() - startedAt.current));
    };
  }, [paused, total, toast.id, onDismiss]);

  return (
    <li
      onMouseEnter={() => {
        setPaused(true);
      }}
      onMouseLeave={() => {
        setPaused(false);
      }}
      onFocus={() => {
        setPaused(true);
      }}
      onBlur={() => {
        setPaused(false);
      }}
      onKeyDown={(event) => {
        if (event.key === 'Escape') onDismiss(toast.id);
      }}
      className="glass-strong pointer-events-auto relative w-full max-w-sm animate-toast-in overflow-hidden rounded-xl"
    >
      <div className="flex gap-3 p-4">
        <Icon aria-hidden="true" className={cn('mt-0.5 size-5 shrink-0', text)} />
        <div className="min-w-0 flex-1">
          <p className="text-sm font-semibold text-fg">{toast.title}</p>
          {toast.description && <p className="mt-1 text-sm text-fg-muted">{toast.description}</p>}
          {toast.action && (
            <Button
              variant="outline"
              size="sm"
              className="mt-3"
              onClick={() => {
                toast.action?.onClick();
                onDismiss(toast.id);
              }}
            >
              {toast.action.label}
            </Button>
          )}
        </div>
        <IconButton
          label="Dismiss notification"
          size="sm"
          onClick={() => {
            onDismiss(toast.id);
          }}
          className="-mr-2 -mt-2"
        >
          <X aria-hidden="true" className="size-4" />
        </IconButton>
      </div>
      {total !== null && (
        <div
          aria-hidden="true"
          className={cn(
            'absolute inset-x-0 bottom-0 h-0.5 origin-left animate-toast-progress motion-reduce:hidden',
            PROGRESS_COLOR[toast.tone],
          )}
          style={{
            animationDuration: `${String(total)}ms`,
            animationPlayState: paused ? 'paused' : 'running',
          }}
        />
      )}
    </li>
  );
}

/**
 * Provides `useToast()` and renders the notification stack.
 *
 * Accessibility: two visually hidden live regions (polite / assertive) carry the announcement,
 * so a toast is read once at the right urgency (errors interrupt), instead of relying on
 * live-region behaviour of freshly inserted elements. The visible toasts pause their timer on
 * hover/focus, can be dismissed with the button or Escape, and never steal focus.
 */
export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<ToastRecord[]>([]);
  const [polite, setPolite] = useState<Announcement | null>(null);
  const [assertive, setAssertive] = useState<Announcement | null>(null);
  const counter = useRef(0);

  const dismiss = useCallback((id: string) => {
    setToasts((current) => current.filter((t) => t.id !== id));
  }, []);
  const dismissAll = useCallback(() => {
    setToasts([]);
  }, []);

  const show = useCallback((options: ToastOptions): string => {
    counter.current += 1;
    const id = `toast-${String(counter.current)}`;
    const record: ToastRecord = { ...options, id, tone: options.tone ?? 'info' };
    setToasts((current) => [...current, record].slice(-MAX_VISIBLE));
    const spoken =
      typeof options.description === 'string'
        ? `${options.title}. ${options.description}`
        : options.title;
    const announcement = { key: counter.current, text: spoken };
    if (record.tone === 'danger') {
      setAssertive(announcement);
    } else {
      setPolite(announcement);
    }
    return id;
  }, []);

  const api = useMemo<ToastApi>(
    () => ({
      show,
      info: (title, description) => show({ title, description, tone: 'info' }),
      success: (title, description) => show({ title, description, tone: 'success' }),
      warning: (title, description) => show({ title, description, tone: 'warning' }),
      error: (title, description) => show({ title, description, tone: 'danger' }),
      dismiss,
      dismissAll,
    }),
    [show, dismiss, dismissAll],
  );

  return (
    <ToastContext.Provider value={api}>
      {children}
      {/* Portalled to <body> and marked data-keep-active, so an open dialog (which makes the
          rest of the page inert) never silences or traps notifications. */}
      {createPortal(
        <div data-keep-active="">
          {/* Announcers. A fresh `key` per message re-inserts the text, so repeats are re-announced. */}
          <div role="status" aria-live="polite" aria-atomic="true" className="sr-only">
            {polite && <span key={polite.key}>{polite.text}</span>}
          </div>
          <div role="alert" aria-live="assertive" aria-atomic="true" className="sr-only">
            {assertive && <span key={assertive.key}>{assertive.text}</span>}
          </div>
          <section
            aria-label="Notifications"
            className="pointer-events-none fixed inset-x-0 bottom-0 z-[60] flex justify-end p-4 sm:p-6"
          >
            <ol className="flex w-full max-w-sm flex-col items-end gap-3">
              {toasts.map((toast) => (
                <ToastItem key={toast.id} toast={toast} onDismiss={dismiss} />
              ))}
            </ol>
          </section>
        </div>,
        document.body,
      )}
    </ToastContext.Provider>
  );
}
