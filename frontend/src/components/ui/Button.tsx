import type { ComponentPropsWithRef, MouseEvent, ReactNode } from 'react';

import { cn } from '../../lib/cn.ts';
import { BUTTON_BASE, BUTTON_SIZES, BUTTON_VARIANTS } from './buttonStyles.ts';
import type { ButtonSize, ButtonVariant } from './buttonStyles.ts';
import { Spinner } from './Spinner.tsx';

export interface ButtonProps extends ComponentPropsWithRef<'button'> {
  variant?: ButtonVariant;
  size?: ButtonSize;
  /** Shows a spinner and ignores clicks, but stays focusable so keyboard users keep their place. */
  loading?: boolean;
  leadingIcon?: ReactNode;
  trailingIcon?: ReactNode;
  fullWidth?: boolean;
}

export function Button({
  variant = 'primary',
  size = 'md',
  loading = false,
  leadingIcon,
  trailingIcon,
  fullWidth = false,
  className,
  children,
  type = 'button',
  onClick,
  disabled,
  ...rest
}: ButtonProps) {
  function handleClick(event: MouseEvent<HTMLButtonElement>): void {
    if (loading) {
      event.preventDefault();
      return;
    }
    onClick?.(event);
  }

  return (
    <button
      type={type}
      disabled={disabled}
      aria-busy={loading || undefined}
      aria-disabled={loading || undefined}
      onClick={handleClick}
      className={cn(
        BUTTON_BASE,
        BUTTON_VARIANTS[variant],
        BUTTON_SIZES[size],
        fullWidth && 'w-full',
        className,
      )}
      {...rest}
    >
      {loading ? <Spinner size="sm" label={null} /> : leadingIcon}
      {children}
      {!loading && trailingIcon}
    </button>
  );
}

export interface IconButtonProps extends Omit<ComponentPropsWithRef<'button'>, 'aria-label'> {
  /** Required: icon-only buttons have no visible text, so this is their accessible name. */
  label: string;
  variant?: ButtonVariant;
  size?: ButtonSize;
  loading?: boolean;
}

const ICON_SIZES: Record<ButtonSize, string> = {
  sm: 'size-9',
  md: 'size-10',
  lg: 'size-12',
};

export function IconButton({
  label,
  variant = 'ghost',
  size = 'md',
  loading = false,
  className,
  children,
  type = 'button',
  onClick,
  ...rest
}: IconButtonProps) {
  return (
    <button
      type={type}
      aria-label={label}
      title={label}
      aria-busy={loading || undefined}
      aria-disabled={loading || undefined}
      onClick={(event) => {
        if (loading) {
          event.preventDefault();
          return;
        }
        onClick?.(event);
      }}
      className={cn(
        BUTTON_BASE,
        'shrink-0 p-0',
        BUTTON_VARIANTS[variant],
        ICON_SIZES[size],
        '[@media(pointer:coarse)]:min-w-11',
        className,
      )}
      {...rest}
    >
      {loading ? <Spinner size="sm" label={null} /> : children}
    </button>
  );
}
