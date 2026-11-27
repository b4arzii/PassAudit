import { cn } from '../../lib/cn.ts';

export type ButtonVariant = 'primary' | 'secondary' | 'outline' | 'ghost' | 'danger';
export type ButtonSize = 'sm' | 'md' | 'lg';

export const BUTTON_BASE =
  'relative inline-flex select-none items-center justify-center gap-2 whitespace-nowrap rounded-xl font-medium ' +
  'transition-[background-color,box-shadow,filter,color,border-color] duration-150 ' +
  'disabled:pointer-events-none disabled:opacity-50 aria-disabled:cursor-not-allowed aria-disabled:opacity-70 ' +
  '[@media(pointer:coarse)]:min-h-11';

export const BUTTON_VARIANTS: Record<ButtonVariant, string> = {
  primary:
    'bg-primary text-primary-fg shadow-glow-primary hover:brightness-110 active:brightness-95',
  secondary:
    'border border-line/10 bg-surface-3 text-fg hover:border-line/20 hover:bg-surface-3/70 active:bg-surface-3',
  outline: 'border border-line/20 bg-transparent text-fg hover:border-line/40 hover:bg-fg/5',
  ghost: 'bg-transparent text-fg-muted hover:bg-fg/5 hover:text-fg',
  danger: 'bg-danger text-primary-fg hover:brightness-110 active:brightness-95',
};

export const BUTTON_SIZES: Record<ButtonSize, string> = {
  sm: 'h-9 px-3 text-sm',
  md: 'h-10 px-4 text-sm',
  lg: 'h-12 px-6 text-base',
};

/**
 * The button look as a class string, for links that should look like buttons
 * (`<Link className={buttonClasses({ variant: 'outline' })}>`). Keeps the UI kit router-agnostic.
 */
export function buttonClasses({
  variant = 'primary',
  size = 'md',
  fullWidth = false,
}: {
  variant?: ButtonVariant;
  size?: ButtonSize;
  fullWidth?: boolean;
} = {}): string {
  return cn(BUTTON_BASE, BUTTON_VARIANTS[variant], BUTTON_SIZES[size], fullWidth && 'w-full');
}
