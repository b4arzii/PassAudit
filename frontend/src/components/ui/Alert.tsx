import { X } from 'lucide-react';
import type { ComponentPropsWithRef, ReactNode } from 'react';

import { cn } from '../../lib/cn.ts';
import { TONE_STYLES } from './alertStyles.ts';
import type { AlertTone } from './alertStyles.ts';
import { IconButton } from './Button.tsx';

export type { AlertTone } from './alertStyles.ts';

export interface AlertProps extends Omit<ComponentPropsWithRef<'div'>, 'title'> {
  tone?: AlertTone;
  title?: ReactNode;
  onDismiss?: () => void;
  /** An action, usually a Button or link, aligned under the message. */
  action?: ReactNode;
}

/**
 * An inline message. Errors use `role="alert"` (announced immediately); everything else uses
 * `role="status"` (announced politely).
 */
export function Alert({
  tone = 'info',
  title,
  onDismiss,
  action,
  className,
  children,
  ...rest
}: AlertProps) {
  const { icon: Icon, box, text } = TONE_STYLES[tone];
  return (
    <div
      role={tone === 'danger' ? 'alert' : 'status'}
      className={cn('flex gap-3 rounded-xl border p-4 text-sm', box, className)}
      {...rest}
    >
      <Icon aria-hidden="true" className={cn('mt-0.5 size-5 shrink-0', text)} />
      <div className="min-w-0 flex-1">
        {title && <p className="font-semibold text-fg">{title}</p>}
        {children && (
          <div className={cn('text-fg-muted', Boolean(title) && 'mt-1')}>{children}</div>
        )}
        {action && <div className="mt-3">{action}</div>}
      </div>
      {onDismiss && (
        <IconButton label="Dismiss" size="sm" onClick={onDismiss} className="-mr-1 -mt-1">
          <X aria-hidden="true" className="size-4" />
        </IconButton>
      )}
    </div>
  );
}
