import { X } from 'lucide-react';
import { useId } from 'react';
import type { ReactNode } from 'react';

import { cn } from '../../lib/cn.ts';
import { Button, IconButton } from './Button.tsx';
import { Overlay } from './Overlay.tsx';

export interface DialogProps {
  open: boolean;
  onClose: () => void;
  title: string;
  description?: ReactNode;
  children?: ReactNode;
  /** Buttons, right-aligned. Put the primary action last. */
  footer?: ReactNode;
  size?: 'sm' | 'md' | 'lg';
  dismissible?: boolean;
}

const SIZES = { sm: 'max-w-sm', md: 'max-w-lg', lg: 'max-w-2xl' } as const;

export function Dialog({
  open,
  onClose,
  title,
  description,
  children,
  footer,
  size = 'md',
  dismissible = true,
}: DialogProps) {
  const titleId = useId();
  const descriptionId = useId();
  return (
    <Overlay
      open={open}
      onClose={onClose}
      labelledBy={titleId}
      describedBy={description ? descriptionId : undefined}
      dismissible={dismissible}
      panelClassName={SIZES[size]}
    >
      <div className="flex max-h-[calc(100dvh-2rem)] flex-col">
        <div className="flex items-start justify-between gap-4 p-6 pb-0">
          <div className="min-w-0">
            <h2 id={titleId} className="text-lg font-semibold">
              {title}
            </h2>
            {description && (
              <p id={descriptionId} className="mt-1.5 text-sm text-fg-muted">
                {description}
              </p>
            )}
          </div>
          {dismissible && (
            <IconButton label="Close dialog" size="sm" onClick={onClose} className="-mr-2 -mt-1">
              <X aria-hidden="true" className="size-5" />
            </IconButton>
          )}
        </div>
        {children && <div className={cn('overflow-y-auto px-6 py-5 text-sm')}>{children}</div>}
        {footer && (
          <div className="flex flex-wrap justify-end gap-3 border-t border-line/10 p-4 px-6">
            {footer}
          </div>
        )}
      </div>
    </Overlay>
  );
}

export interface ConfirmDialogProps {
  open: boolean;
  onClose: () => void;
  onConfirm: () => void;
  title: string;
  description?: ReactNode;
  confirmLabel?: string;
  cancelLabel?: string;
  tone?: 'primary' | 'danger';
  loading?: boolean;
}

/** A yes/no question. Focus starts on "Cancel" so a stray Enter cannot confirm. */
export function ConfirmDialog({
  open,
  onClose,
  onConfirm,
  title,
  description,
  confirmLabel = 'Confirm',
  cancelLabel = 'Cancel',
  tone = 'primary',
  loading = false,
}: ConfirmDialogProps) {
  return (
    <Dialog
      open={open}
      onClose={onClose}
      title={title}
      description={description}
      size="sm"
      footer={
        <>
          <Button variant="outline" onClick={onClose} data-autofocus>
            {cancelLabel}
          </Button>
          <Button
            variant={tone === 'danger' ? 'danger' : 'primary'}
            onClick={onConfirm}
            loading={loading}
          >
            {confirmLabel}
          </Button>
        </>
      }
    />
  );
}
