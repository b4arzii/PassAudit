import { Check, Copy } from 'lucide-react';
import { useEffect, useRef, useState } from 'react';

import { copyText } from '../../lib/export.ts';
import { Button } from './Button.tsx';
import type { ButtonProps } from './Button.tsx';

export interface CopyButtonProps extends Pick<ButtonProps, 'variant' | 'size'> {
  /** Computed lazily so large reports are only built when the button is used. */
  getText: () => string;
  label?: string;
  disabled?: boolean;
}

type CopyState = 'idle' | 'copied' | 'failed';

/** Copies text and confirms in a polite live region (the button label alone would not be re-read). */
export function CopyButton({
  getText,
  label = 'Copy',
  variant = 'outline',
  size = 'md',
  disabled,
}: CopyButtonProps) {
  const [state, setState] = useState<CopyState>('idle');
  const timer = useRef<number | undefined>(undefined);

  useEffect(
    () => () => {
      window.clearTimeout(timer.current);
    },
    [],
  );

  async function onClick(): Promise<void> {
    const ok = await copyText(getText());
    setState(ok ? 'copied' : 'failed');
    window.clearTimeout(timer.current);
    timer.current = window.setTimeout(() => {
      setState('idle');
    }, 2500);
  }

  return (
    <>
      <Button
        variant={variant}
        size={size}
        {...(disabled === undefined ? {} : { disabled })}
        onClick={() => {
          void onClick();
        }}
        leadingIcon={
          state === 'copied' ? (
            <Check aria-hidden="true" className="size-4 text-success" />
          ) : (
            <Copy aria-hidden="true" className="size-4" />
          )
        }
      >
        {label}
      </Button>
      <span role="status" className="sr-only">
        {state === 'copied'
          ? 'Copied to clipboard'
          : state === 'failed'
            ? 'Copy failed. Select the text and copy it manually.'
            : ''}
      </span>
    </>
  );
}
