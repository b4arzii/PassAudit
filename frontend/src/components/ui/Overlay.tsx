import { useRef } from 'react';
import type { ReactNode } from 'react';
import { createPortal } from 'react-dom';

import { cn } from '../../lib/cn.ts';
import { useEscapeKey, useFocusTrap, useInertOutside, useScrollLock } from '../../lib/overlay.ts';

export interface OverlayProps {
  open: boolean;
  onClose: () => void;
  /** Id of the element that names the dialog (`aria-labelledby`). */
  labelledBy?: string | undefined;
  /** Used when there is no visible title element. */
  ariaLabel?: string | undefined;
  describedBy?: string | undefined;
  placement?: 'center' | 'left';
  /** Escape and backdrop click close the overlay. Disable for forced-choice dialogs. */
  dismissible?: boolean;
  panelClassName?: string | undefined;
  children: ReactNode;
}

/**
 * The accessible modal primitive behind Dialog and Drawer:
 *  - rendered in a portal on <body>
 *  - `role="dialog"` + `aria-modal`, named by `aria-labelledby`/`aria-label`
 *  - focus moves in on open (to `[data-autofocus]` or the first control), Tab is trapped,
 *    and focus returns to the opener on close
 *  - Escape and backdrop click close it (unless `dismissible={false}`)
 *  - the page behind is made `inert` and cannot scroll
 */
export function Overlay({
  open,
  onClose,
  labelledBy,
  ariaLabel,
  describedBy,
  placement = 'center',
  dismissible = true,
  panelClassName,
  children,
}: OverlayProps) {
  if (!open) return null;
  return createPortal(
    <OverlayContent
      onClose={onClose}
      labelledBy={labelledBy}
      ariaLabel={ariaLabel}
      describedBy={describedBy}
      placement={placement}
      dismissible={dismissible}
      panelClassName={panelClassName}
    >
      {children}
    </OverlayContent>,
    document.body,
  );
}

function OverlayContent({
  onClose,
  labelledBy,
  ariaLabel,
  describedBy,
  placement,
  dismissible,
  panelClassName,
  children,
}: Omit<OverlayProps, 'open'> & { placement: 'center' | 'left'; dismissible: boolean }) {
  const rootRef = useRef<HTMLDivElement>(null);
  const panelRef = useRef<HTMLDivElement>(null);

  useFocusTrap(panelRef, true);
  useScrollLock(true);
  useInertOutside(rootRef, true);
  useEscapeKey(dismissible, onClose);

  return (
    <div
      ref={rootRef}
      className={cn(
        'fixed inset-0 z-50 flex',
        placement === 'center' ? 'items-center justify-center p-4' : 'items-stretch justify-start',
      )}
    >
      <div
        aria-hidden="true"
        className="absolute inset-0 animate-fade-in bg-black/60 backdrop-blur-sm"
        onMouseDown={dismissible ? onClose : undefined}
      />
      <div
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby={labelledBy}
        aria-label={labelledBy ? undefined : ariaLabel}
        aria-describedby={describedBy}
        tabIndex={-1}
        className={cn(
          'glass-strong relative max-h-full outline-none',
          placement === 'center'
            ? 'w-full animate-pop-in rounded-2xl'
            : 'animate-slide-in-left h-full w-72 max-w-[85vw] rounded-r-2xl',
          panelClassName,
        )}
      >
        {children}
      </div>
    </div>
  );
}
