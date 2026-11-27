import { Check } from 'lucide-react';
import { useId } from 'react';
import type { ComponentPropsWithRef, ReactNode } from 'react';

import { cn } from '../../lib/cn.ts';

interface ChoiceProps extends Omit<ComponentPropsWithRef<'input'>, 'type' | 'children'> {
  label: ReactNode;
  description?: ReactNode;
}

/** A native checkbox with themed chrome: real form semantics and keyboard behaviour for free. */
export function Checkbox({ label, description, className, id, ...rest }: ChoiceProps) {
  const generated = useId();
  const inputId = id ?? generated;
  const descId = `${inputId}-desc`;
  return (
    <div className={cn('flex items-start gap-3', className)}>
      <span className="relative mt-0.5 flex size-5 shrink-0">
        <input
          id={inputId}
          type="checkbox"
          aria-describedby={description ? descId : undefined}
          className="peer size-5 cursor-pointer appearance-none rounded-md border border-line/30 bg-surface-2 transition-colors checked:border-primary checked:bg-primary hover:border-line/50 disabled:cursor-not-allowed disabled:opacity-50"
          {...rest}
        />
        <Check
          aria-hidden="true"
          strokeWidth={3}
          className="pointer-events-none absolute inset-0 m-auto size-3.5 text-primary-fg opacity-0 peer-checked:opacity-100"
        />
      </span>
      <span className="min-w-0">
        <label htmlFor={inputId} className="cursor-pointer text-sm font-medium text-fg">
          {label}
        </label>
        {description && (
          <span id={descId} className="block text-xs text-fg-muted">
            {description}
          </span>
        )}
      </span>
    </div>
  );
}

/**
 * A switch for settings that apply immediately. It is a real checkbox with `role="switch"`,
 * so it is focusable, toggles with Space, and reports its state without extra JavaScript.
 */
export function Switch({ label, description, className, id, ...rest }: ChoiceProps) {
  const generated = useId();
  const inputId = id ?? generated;
  const descId = `${inputId}-desc`;
  return (
    <div className={cn('flex items-start justify-between gap-4', className)}>
      <span className="min-w-0">
        <label htmlFor={inputId} className="cursor-pointer text-sm font-medium text-fg">
          {label}
        </label>
        {description && (
          <span id={descId} className="block text-xs text-fg-muted">
            {description}
          </span>
        )}
      </span>
      <span className="relative mt-0.5 inline-flex h-6 w-10 shrink-0">
        <input
          id={inputId}
          type="checkbox"
          role="switch"
          aria-describedby={description ? descId : undefined}
          className="peer h-6 w-10 cursor-pointer appearance-none rounded-full border border-line/20 bg-fg/15 transition-colors checked:border-transparent checked:bg-primary disabled:cursor-not-allowed disabled:opacity-50"
          {...rest}
        />
        <span
          aria-hidden="true"
          className="pointer-events-none absolute left-1 top-1 size-4 rounded-full bg-fg shadow transition-transform peer-checked:translate-x-4 peer-checked:bg-primary-fg motion-reduce:transition-none"
        />
      </span>
    </div>
  );
}

export interface SegmentedOption<T extends string> {
  value: T;
  label: string;
  icon?: ReactNode;
}

export interface SegmentedControlProps<T extends string> {
  /** Visible or screen-reader-only group name. */
  legend: string;
  hideLegend?: boolean;
  options: readonly SegmentedOption<T>[];
  value: T;
  onChange: (value: T) => void;
  className?: string;
}

/**
 * A radio group presented as a segmented control. Native radios give arrow-key navigation
 * and a single tab stop; the visuals are drawn on the label.
 */
export function SegmentedControl<T extends string>({
  legend,
  hideLegend = false,
  options,
  value,
  onChange,
  className,
}: SegmentedControlProps<T>) {
  const name = useId();
  return (
    <fieldset className={cn('min-w-0', className)}>
      <legend className={cn('mb-2 text-sm font-medium text-fg', hideLegend && 'sr-only')}>
        {legend}
      </legend>
      <div className="inline-flex rounded-xl border border-line/15 bg-surface-2/70 p-1">
        {options.map((option) => (
          <label key={option.value} className="relative cursor-pointer">
            <input
              type="radio"
              name={name}
              value={option.value}
              checked={value === option.value}
              onChange={() => {
                onChange(option.value);
              }}
              className="peer sr-only"
            />
            <span
              className={cn(
                'flex h-9 items-center gap-2 rounded-lg px-3.5 text-sm font-medium text-fg-muted transition-colors',
                'hover:text-fg peer-checked:bg-surface-3 peer-checked:text-fg peer-checked:shadow-sm',
                'peer-focus-visible:outline peer-focus-visible:outline-2 peer-focus-visible:outline-ring',
                '[@media(pointer:coarse)]:h-11',
              )}
            >
              {option.icon}
              {option.label}
            </span>
          </label>
        ))}
      </div>
    </fieldset>
  );
}
