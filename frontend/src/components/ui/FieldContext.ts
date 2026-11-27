import { createContext, useContext } from 'react';

export interface FieldContextValue {
  /** The id the control must carry, so `<label htmlFor>` works. */
  id: string;
  /** Ids of the hint/error elements, for `aria-describedby`. */
  describedBy: string | undefined;
  invalid: boolean;
  required: boolean;
  disabled: boolean;
}

export const FieldContext = createContext<FieldContextValue | null>(null);

interface OwnProps {
  id?: string | undefined;
  'aria-describedby'?: string | undefined;
  'aria-invalid'?: boolean | 'true' | 'false' | 'grammar' | 'spelling' | undefined;
  required?: boolean | undefined;
  disabled?: boolean | undefined;
  invalid?: boolean | undefined;
}

/** Merge a control's own props with those supplied by an enclosing `<Field>`. */
export function useFieldControl(own: OwnProps) {
  const field = useContext(FieldContext);
  const invalid = own.invalid ?? (own['aria-invalid'] === true || own['aria-invalid'] === 'true');
  const isInvalid = invalid || (field?.invalid ?? false);
  const describedBy =
    [own['aria-describedby'], field?.describedBy].filter(Boolean).join(' ') || undefined;
  return {
    id: own.id ?? field?.id,
    describedBy,
    invalid: isInvalid,
    required: own.required ?? field?.required ?? false,
    disabled: own.disabled ?? field?.disabled ?? false,
  };
}
