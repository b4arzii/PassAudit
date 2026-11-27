import { ChevronDown, Eye, EyeOff } from 'lucide-react';
import { useState } from 'react';
import type { ComponentPropsWithRef, ReactNode } from 'react';

import { cn } from '../../lib/cn.ts';
import { IconButton } from './Button.tsx';
import { useFieldControl } from './FieldContext.ts';

/** The shared "control box": border, fill, hover and focus-within states. */
function shell(invalid: boolean, disabled: boolean): string {
  return cn(
    'flex w-full items-center gap-2 rounded-xl border bg-surface-2/70 px-3 transition-colors',
    'focus-within:outline focus-within:outline-2 focus-within:outline-ring',
    invalid
      ? 'border-danger/70 hover:border-danger'
      : 'border-line/15 hover:border-line/30 focus-within:border-transparent',
    disabled && 'cursor-not-allowed opacity-60 hover:border-line/15',
  );
}

const INNER =
  'h-10 w-full min-w-0 bg-transparent text-sm text-fg placeholder:text-fg-subtle ' +
  'focus-visible:outline-none disabled:cursor-not-allowed [@media(pointer:coarse)]:h-11';

export interface InputProps extends Omit<ComponentPropsWithRef<'input'>, 'size'> {
  leadingIcon?: ReactNode;
  /** Content after the text, e.g. a button or unit. */
  trailing?: ReactNode;
  invalid?: boolean;
}

export function Input({
  leadingIcon,
  trailing,
  invalid: invalidProp,
  className,
  id,
  required,
  disabled,
  'aria-describedby': describedByProp,
  ...rest
}: InputProps) {
  const control = useFieldControl({
    id,
    required,
    disabled,
    invalid: invalidProp,
    'aria-describedby': describedByProp,
  });
  return (
    <div className={cn(shell(control.invalid, control.disabled), className)}>
      {leadingIcon && (
        <span aria-hidden="true" className="flex shrink-0 text-fg-subtle [&>svg]:size-4">
          {leadingIcon}
        </span>
      )}
      <input
        id={control.id}
        required={control.required}
        disabled={control.disabled}
        aria-invalid={control.invalid || undefined}
        aria-describedby={control.describedBy}
        className={INNER}
        {...rest}
      />
      {trailing}
    </div>
  );
}

export interface PasswordInputProps extends Omit<InputProps, 'type' | 'trailing'> {
  /** Offer the show/hide toggle (default true). */
  revealable?: boolean;
}

/**
 * A password field with safe defaults: no autofill/suggestions/spell-check, and a labelled
 * show/hide toggle that exposes its state with `aria-pressed`. It holds no state about the
 * value itself - the parent owns it, and should never persist or log it.
 */
export function PasswordInput({ revealable = true, ...props }: PasswordInputProps) {
  const [visible, setVisible] = useState(false);
  return (
    <Input
      autoComplete="off"
      autoCapitalize="off"
      autoCorrect="off"
      spellCheck={false}
      {...props}
      type={visible ? 'text' : 'password'}
      trailing={
        revealable ? (
          <IconButton
            label="Show password"
            size="sm"
            aria-pressed={visible}
            onClick={() => {
              setVisible((v) => !v);
            }}
            className="-mr-1.5"
          >
            {visible ? (
              <EyeOff aria-hidden="true" className="size-4" />
            ) : (
              <Eye aria-hidden="true" className="size-4" />
            )}
          </IconButton>
        ) : undefined
      }
    />
  );
}

export interface TextareaProps extends ComponentPropsWithRef<'textarea'> {
  invalid?: boolean;
}

export function Textarea({
  invalid: invalidProp,
  className,
  id,
  required,
  disabled,
  'aria-describedby': describedByProp,
  ...rest
}: TextareaProps) {
  const control = useFieldControl({
    id,
    required,
    disabled,
    invalid: invalidProp,
    'aria-describedby': describedByProp,
  });
  return (
    <div className={cn(shell(control.invalid, control.disabled), 'py-2', className)}>
      <textarea
        id={control.id}
        required={control.required}
        disabled={control.disabled}
        aria-invalid={control.invalid || undefined}
        aria-describedby={control.describedBy}
        rows={4}
        className="min-h-24 w-full resize-y bg-transparent text-sm text-fg placeholder:text-fg-subtle focus-visible:outline-none disabled:cursor-not-allowed"
        {...rest}
      />
    </div>
  );
}

export interface SelectProps extends Omit<ComponentPropsWithRef<'select'>, 'size'> {
  invalid?: boolean;
}

/** A native `<select>` (best keyboard and screen-reader behaviour) with themed chrome. */
export function Select({
  invalid: invalidProp,
  className,
  id,
  required,
  disabled,
  'aria-describedby': describedByProp,
  children,
  ...rest
}: SelectProps) {
  const control = useFieldControl({
    id,
    required,
    disabled,
    invalid: invalidProp,
    'aria-describedby': describedByProp,
  });
  return (
    <div className={cn('relative', className)}>
      <div className={shell(control.invalid, control.disabled)}>
        <select
          id={control.id}
          required={control.required}
          disabled={control.disabled}
          aria-invalid={control.invalid || undefined}
          aria-describedby={control.describedBy}
          className={cn(INNER, 'cursor-pointer appearance-none pr-7')}
          {...rest}
        >
          {children}
        </select>
      </div>
      <ChevronDown
        aria-hidden="true"
        className="pointer-events-none absolute right-3 top-1/2 size-4 -translate-y-1/2 text-fg-subtle"
      />
    </div>
  );
}
