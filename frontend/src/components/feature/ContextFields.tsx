import type { ContextValue } from './contextValue.ts';
import { USAGE_OPTIONS } from '../../lib/labels.ts';
import { Checkbox, Field, Select, Textarea } from '../ui/index.ts';

export interface ContextFieldsProps {
  value: ContextValue;
  onChange: (next: ContextValue) => void;
  personalError?: string | null;
  disabled?: boolean;
  /** Batch audits detect reuse themselves, so they hide the "reused elsewhere" switch. */
  showReused?: boolean;
}

/** What the password protects, and personal details an attacker could guess. */
export function ContextFields({
  value,
  onChange,
  personalError,
  disabled = false,
  showReused = true,
}: ContextFieldsProps) {
  const usage = USAGE_OPTIONS.find((o) => o.value === value.usage);
  return (
    <div className="space-y-4">
      <Field label="What does it protect?" hint={usage?.hint} disabled={disabled}>
        <Select
          value={value.usage}
          onChange={(event) => {
            onChange({ ...value, usage: event.target.value as ContextValue['usage'] });
          }}
        >
          {USAGE_OPTIONS.map((option) => (
            <option key={option.value} value={option.value}>
              {option.label}
            </option>
          ))}
        </Select>
      </Field>
      <Field
        label="Personal details to check against (optional)"
        hint="One per line: a name, username, employer, pet... PassAudit flags passwords that contain them. Sent with the request only and never stored; they stay in this form until you clear it."
        error={personalError ?? undefined}
        disabled={disabled}
      >
        <Textarea
          rows={3}
          value={value.personalText}
          autoComplete="off"
          autoCapitalize="off"
          autoCorrect="off"
          spellCheck={false}
          onChange={(event) => {
            onChange({ ...value, personalText: event.target.value });
          }}
        />
      </Field>
      {showReused && (
        <Checkbox
          label="This password is used on more than one service"
          description="Reuse raises the risk score."
          checked={value.reused}
          disabled={disabled}
          onChange={(event) => {
            onChange({ ...value, reused: event.target.checked });
          }}
        />
      )}
    </div>
  );
}
