import { CircleAlert } from 'lucide-react';
import { useId } from 'react';
import type { ReactNode } from 'react';

import { cn } from '../../lib/cn.ts';
import { FieldContext } from './FieldContext.ts';

export interface FieldProps {
  label: ReactNode;
  /** Help text shown under the control and announced with it. */
  hint?: ReactNode;
  /** Validation message. Its presence marks the control `aria-invalid`. */
  error?: ReactNode;
  required?: boolean;
  disabled?: boolean;
  /** Hide the label visually but keep it for assistive technology. */
  hideLabel?: boolean;
  className?: string;
  children: ReactNode;
}

/**
 * Connects a label, hint and error message to the single form control inside it:
 * `<label for>`, `aria-describedby`, `aria-invalid` and `required` are all wired for you.
 */
export function Field({
  label,
  hint,
  error,
  required = false,
  disabled = false,
  hideLabel = false,
  className,
  children,
}: FieldProps) {
  const baseId = useId();
  const id = `${baseId}-control`;
  const hintId = `${baseId}-hint`;
  const errorId = `${baseId}-error`;
  const describedBy = [hint ? hintId : null, error ? errorId : null].filter(Boolean).join(' ');

  return (
    <FieldContext.Provider
      value={{
        id,
        describedBy: describedBy || undefined,
        invalid: Boolean(error),
        required,
        disabled,
      }}
    >
      <div className={cn('space-y-1.5', className)}>
        <label
          htmlFor={id}
          className={cn('block text-sm font-medium text-fg', hideLabel && 'sr-only')}
        >
          {label}
          {required && (
            <span aria-hidden="true" className="ml-0.5 text-danger">
              *
            </span>
          )}
        </label>
        {children}
        {hint && (
          <p id={hintId} className="text-xs text-fg-muted">
            {hint}
          </p>
        )}
        {error && (
          <p id={errorId} className="flex items-start gap-1.5 text-xs font-medium text-danger">
            <CircleAlert aria-hidden="true" className="mt-px size-3.5 shrink-0" />
            <span>{error}</span>
          </p>
        )}
      </div>
    </FieldContext.Provider>
  );
}
