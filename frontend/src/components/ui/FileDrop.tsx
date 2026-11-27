import { FileUp } from 'lucide-react';
import { useId, useRef, useState } from 'react';
import type { DragEvent } from 'react';

import { cn } from '../../lib/cn.ts';

export interface FileDropProps {
  label: string;
  hint?: string;
  /** Passed to the input's `accept` (e.g. ".txt,.csv"). */
  accept: string;
  onFile: (file: File) => void;
  disabled?: boolean;
}

/**
 * A drag-and-drop target that is also a real, keyboard-operable file picker: the visible
 * control is a `<label>` for a native `<input type="file">`, so it works with Enter/Space,
 * with screen readers, and without any drag-and-drop at all.
 */
export function FileDrop({ label, hint, accept, onFile, disabled = false }: FileDropProps) {
  const id = useId();
  const input = useRef<HTMLInputElement>(null);
  const [over, setOver] = useState(false);

  function onDrop(event: DragEvent): void {
    event.preventDefault();
    setOver(false);
    if (disabled) return;
    const file = event.dataTransfer.files[0];
    if (file) onFile(file);
  }

  return (
    <div
      onDragOver={(event) => {
        event.preventDefault();
        if (!disabled) setOver(true);
      }}
      onDragLeave={() => {
        setOver(false);
      }}
      onDrop={onDrop}
      className={cn(
        'rounded-xl border border-dashed p-5 text-center transition-colors',
        over ? 'border-primary bg-primary/10' : 'border-line/25 bg-surface-2/40',
        disabled && 'opacity-60',
      )}
    >
      <FileUp aria-hidden="true" className="mx-auto mb-2 size-6 text-secondary" />
      <label
        htmlFor={id}
        className={cn(
          'text-sm font-medium text-fg',
          disabled
            ? 'cursor-not-allowed'
            : 'cursor-pointer underline decoration-line/40 underline-offset-4 hover:decoration-primary',
        )}
      >
        {label}
      </label>
      <input
        ref={input}
        id={id}
        type="file"
        accept={accept}
        disabled={disabled}
        className="sr-only"
        onChange={(event) => {
          const file = event.target.files?.[0];
          if (file) onFile(file);
          event.target.value = ''; // allow choosing the same file again
        }}
      />
      {hint && <p className="mt-1 text-xs text-fg-muted">{hint}</p>}
    </div>
  );
}
