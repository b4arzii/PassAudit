import { useState } from 'react';

import type { PasswordPolicy } from '../../api/types.ts';
import { isPolicyValid, validatePolicy } from '../../lib/policy.ts';
import type { PolicyErrors } from '../../lib/policy.ts';
import { Field, Input, Switch } from '../ui/index.ts';

interface NumberField {
  key: keyof PasswordPolicy;
  label: string;
  hint: string;
  /** Empty means "no limit" (the rule is off). */
  nullable: boolean;
}

const NUMBER_FIELDS: readonly NumberField[] = [
  {
    key: 'min_length',
    label: 'Minimum length',
    hint: 'Characters. 0 turns the rule off.',
    nullable: false,
  },
  { key: 'max_length', label: 'Maximum length', hint: 'Leave empty for no limit.', nullable: true },
  {
    key: 'min_lowercase',
    label: 'Lowercase letters',
    hint: 'At least this many. 0 = off.',
    nullable: false,
  },
  {
    key: 'min_uppercase',
    label: 'Uppercase letters',
    hint: 'At least this many. 0 = off.',
    nullable: false,
  },
  { key: 'min_digits', label: 'Digits', hint: 'At least this many. 0 = off.', nullable: false },
  { key: 'min_symbols', label: 'Symbols', hint: 'At least this many. 0 = off.', nullable: false },
  {
    key: 'min_unique_characters',
    label: 'Distinct characters',
    hint: 'At least this many different characters. 0 = off.',
    nullable: false,
  },
  {
    key: 'max_repeat_run',
    label: 'Longest repeated run',
    hint: '3 allows "aaa" but not "aaaa". Empty = off.',
    nullable: true,
  },
  {
    key: 'max_sequence_length',
    label: 'Longest sequence',
    hint: '3 allows "abc" or "123". Empty = off.',
    nullable: true,
  },
  {
    key: 'max_keyboard_run',
    label: 'Longest keyboard run',
    hint: '4 allows "asdf". Empty = off.',
    nullable: true,
  },
  {
    key: 'min_strength_score',
    label: 'Minimum strength score',
    hint: '0 to 4 (zxcvbn). 0 = off.',
    nullable: false,
  },
];

type Draft = Record<string, string>;

function toDraft(policy: PasswordPolicy): Draft {
  return Object.fromEntries(
    NUMBER_FIELDS.map((f) => [f.key, policy[f.key] === null ? '' : String(policy[f.key])]),
  );
}

/** Build a candidate policy from the text boxes. Unparseable input becomes NaN so validation flags it. */
function fromDraft(
  draft: Draft,
  flags: Pick<
    PasswordPolicy,
    | 'allow_whitespace'
    | 'block_common_passwords'
    | 'forbid_personal_info'
    | 'block_dictionary_words'
    | 'block_breached_passwords'
  >,
): PasswordPolicy {
  const out: Record<string, number | null> = {};
  for (const field of NUMBER_FIELDS) {
    const raw = (draft[field.key] ?? '').trim();
    out[field.key] = raw === '' ? (field.nullable ? null : Number.NaN) : Number(raw);
  }
  return { ...out, ...flags } as unknown as PasswordPolicy;
}

export interface PolicyEditorProps {
  policy: PasswordPolicy;
  /** Called with a complete, valid policy whenever the form becomes (or stays) valid. */
  onChange: (policy: PasswordPolicy) => void;
}

/**
 * Edits a policy. Text boxes keep what the person typed (so clearing a box to type a new number
 * is allowed); a change is applied only when the whole policy is valid, otherwise the problems
 * are listed and the previously applied policy stays in force. To load a different policy from
 * outside, remount with a new `key`.
 */
export function PolicyEditor({ policy, onChange }: PolicyEditorProps) {
  const [draft, setDraft] = useState<Draft>(() => toDraft(policy));
  const [flags, setFlags] = useState({
    allow_whitespace: policy.allow_whitespace,
    block_common_passwords: policy.block_common_passwords,
    forbid_personal_info: policy.forbid_personal_info,
    block_dictionary_words: policy.block_dictionary_words,
    block_breached_passwords: policy.block_breached_passwords,
  });
  const [errors, setErrors] = useState<PolicyErrors>({});

  function apply(nextDraft: Draft, nextFlags: typeof flags): void {
    const candidate = fromDraft(nextDraft, nextFlags);
    const found = validatePolicy(candidate);
    setErrors(found);
    if (isPolicyValid(candidate)) onChange(candidate);
  }

  const problems = Object.keys(errors).length;

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {NUMBER_FIELDS.map((field) => (
          <Field key={field.key} label={field.label} hint={field.hint} error={errors[field.key]}>
            <Input
              type="text"
              inputMode="numeric"
              autoComplete="off"
              value={draft[field.key] ?? ''}
              onChange={(event) => {
                const next = { ...draft, [field.key]: event.target.value };
                setDraft(next);
                apply(next, flags);
              }}
            />
          </Field>
        ))}
      </div>
      <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
        <Switch
          label="Allow spaces"
          description="Off rejects passwords containing whitespace."
          checked={flags.allow_whitespace}
          onChange={(event) => {
            const next = { ...flags, allow_whitespace: event.target.checked };
            setFlags(next);
            apply(draft, next);
          }}
        />
        <Switch
          label="Block common passwords"
          description="Reject passwords found in the built-in list."
          checked={flags.block_common_passwords}
          onChange={(event) => {
            const next = { ...flags, block_common_passwords: event.target.checked };
            setFlags(next);
            apply(draft, next);
          }}
        />
        <Switch
          label="Reject personal details"
          description="Reject passwords containing details you supply."
          checked={flags.forbid_personal_info}
          onChange={(event) => {
            const next = { ...flags, forbid_personal_info: event.target.checked };
            setFlags(next);
            apply(draft, next);
          }}
        />
        <Switch
          label="Reject dictionary-built passwords"
          description="Reject passwords made mostly (60%+) of common words and names. Off by default: long word passphrases are fine."
          checked={flags.block_dictionary_words}
          onChange={(event) => {
            const next = { ...flags, block_dictionary_words: event.target.checked };
            setFlags(next);
            apply(draft, next);
          }}
        />
        <Switch
          label="Reject breached passwords"
          description="Needs the opt-in breach check; without it this rule shows as not checked, never as passed."
          checked={flags.block_breached_passwords}
          onChange={(event) => {
            const next = { ...flags, block_breached_passwords: event.target.checked };
            setFlags(next);
            apply(draft, next);
          }}
        />
      </div>
      <p role="status" className="text-xs text-fg-muted">
        {problems === 0
          ? 'Changes apply automatically and are remembered in this browser (rules only - never passwords).'
          : `${String(problems)} ${problems === 1 ? 'field needs' : 'fields need'} attention. The last valid policy stays in force until fixed.`}
      </p>
    </div>
  );
}
