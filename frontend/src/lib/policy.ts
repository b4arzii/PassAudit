import type { PasswordPolicy } from '../api/types.ts';

/** The engine's default policy (backend `PasswordPolicy()`); `GET /policy/default` is authoritative. */
export const DEFAULT_POLICY: PasswordPolicy = {
  min_length: 12,
  max_length: null,
  min_lowercase: 0,
  min_uppercase: 0,
  min_digits: 0,
  min_symbols: 0,
  min_unique_characters: 0,
  max_repeat_run: null,
  max_sequence_length: null,
  max_keyboard_run: null,
  allow_whitespace: true,
  block_common_passwords: true,
  forbid_personal_info: true,
  min_strength_score: 2,
  block_dictionary_words: false,
  block_breached_passwords: false,
};

export interface PolicyPreset {
  id: string;
  name: string;
  description: string;
  policy: PasswordPolicy;
}

export const POLICY_PRESETS: readonly PolicyPreset[] = [
  {
    id: 'default',
    name: 'Default (NIST-style)',
    description: 'Length and blocklist checks, no forced character mix.',
    policy: DEFAULT_POLICY,
  },
  {
    id: 'strict',
    name: 'Strict',
    description: 'Longer minimum, pattern limits and a high strength score.',
    policy: {
      ...DEFAULT_POLICY,
      min_length: 16,
      min_unique_characters: 8,
      max_repeat_run: 2,
      max_sequence_length: 3,
      max_keyboard_run: 4,
      min_strength_score: 3,
    },
  },
  {
    id: 'legacy',
    name: 'Legacy complexity',
    description: 'Classic upper/lower/digit/symbol rules (not recommended by NIST).',
    policy: {
      ...DEFAULT_POLICY,
      min_length: 8,
      min_lowercase: 1,
      min_uppercase: 1,
      min_digits: 1,
      min_symbols: 1,
      min_strength_score: 0,
    },
  },
  {
    id: 'minimal',
    name: 'Minimal',
    description: 'Only blocks common passwords and very short ones.',
    policy: {
      ...DEFAULT_POLICY,
      min_length: 8,
      min_strength_score: 0,
      forbid_personal_info: false,
    },
  },
];

export const POLICY_FIELDS = Object.keys(DEFAULT_POLICY) as (keyof PasswordPolicy)[];

export type PolicyErrors = Partial<Record<keyof PasswordPolicy, string>>;

function intIn(value: unknown, min: number, max: number): boolean {
  return typeof value === 'number' && Number.isInteger(value) && value >= min && value <= max;
}

/** Client-side validation mirroring the backend model, so users see problems before sending. */
export function validatePolicy(policy: PasswordPolicy): PolicyErrors {
  const errors: PolicyErrors = {};
  const counts: (keyof PasswordPolicy)[] = [
    'min_length',
    'min_lowercase',
    'min_uppercase',
    'min_digits',
    'min_symbols',
    'min_unique_characters',
  ];
  for (const key of counts) {
    if (!intIn(policy[key], 0, 1024)) errors[key] = 'Enter a whole number from 0 to 1024.';
  }
  if (policy.max_length !== null) {
    if (!intIn(policy.max_length, 1, 65536))
      errors.max_length = 'Enter a whole number from 1 to 65536, or leave empty.';
    else if (!errors.min_length && policy.max_length < policy.min_length)
      errors.max_length = 'Must be at least the minimum length.';
  }
  if (policy.max_repeat_run !== null && !intIn(policy.max_repeat_run, 1, 1024))
    errors.max_repeat_run = 'Enter a whole number from 1 to 1024, or leave empty.';
  if (policy.max_sequence_length !== null && !intIn(policy.max_sequence_length, 2, 1024))
    errors.max_sequence_length = 'Enter a whole number from 2 to 1024, or leave empty.';
  if (policy.max_keyboard_run !== null && !intIn(policy.max_keyboard_run, 2, 1024))
    errors.max_keyboard_run = 'Enter a whole number from 2 to 1024, or leave empty.';
  if (!intIn(policy.min_strength_score, 0, 4))
    errors.min_strength_score = 'Enter a whole number from 0 to 4.';
  return errors;
}

export function isPolicyValid(policy: PasswordPolicy): boolean {
  return Object.keys(validatePolicy(policy)).length === 0;
}

export type PolicyParseResult = { ok: true; policy: PasswordPolicy } | { ok: false; error: string };

/**
 * Parse a policy from untrusted JSON text (an uploaded file, local storage). Unknown fields are
 * rejected (the API does the same), missing ones fall back to the defaults, and the result must
 * pass validation. Error messages never quote file content.
 */
export function parsePolicyJson(text: string): PolicyParseResult {
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch {
    return { ok: false, error: 'The file is not valid JSON.' };
  }
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
    return { ok: false, error: 'A policy must be a JSON object of policy fields.' };
  }
  const input = raw as Record<string, unknown>;
  const source =
    'policy' in input &&
    Object.keys(input).length === 1 &&
    typeof input.policy === 'object' &&
    input.policy !== null
      ? (input.policy as Record<string, unknown>)
      : input;
  const unknown = Object.keys(source).filter((key) => !(POLICY_FIELDS as string[]).includes(key));
  if (unknown.length > 0) {
    return {
      ok: false,
      error: `Unknown policy field${unknown.length === 1 ? '' : 's'}: ${unknown
        .slice(0, 3)
        .map((k) => k.slice(0, 40))
        .join(', ')}.`,
    };
  }
  // Untrusted values: typed loosely until validated below.
  const loose: Record<string, unknown> = { ...DEFAULT_POLICY, ...source };
  const merged = loose as unknown as PasswordPolicy;
  for (const key of [
    'allow_whitespace',
    'block_common_passwords',
    'forbid_personal_info',
    'block_dictionary_words',
    'block_breached_passwords',
  ] as const) {
    if (typeof loose[key] !== 'boolean')
      return { ok: false, error: `${key} must be true or false.` };
  }
  const errors = validatePolicy(merged);
  const first = Object.entries(errors)[0];
  if (first) return { ok: false, error: `${first[0]}: ${first[1]}` };
  return { ok: true, policy: merged };
}

export function samePolicy(a: PasswordPolicy, b: PasswordPolicy): boolean {
  return POLICY_FIELDS.every((key) => a[key] === b[key]);
}

/** Only the fields that differ from the default - keeps requests small and readable. */
export function policyOverrides(policy: PasswordPolicy): Partial<PasswordPolicy> {
  const diff: Partial<PasswordPolicy> = {};
  for (const key of POLICY_FIELDS) {
    if (policy[key] !== DEFAULT_POLICY[key]) (diff as Record<string, unknown>)[key] = policy[key];
  }
  return diff;
}
