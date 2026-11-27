import type { BadgeTone } from '../components/ui/index.ts';
import type {
  FindingKind,
  PasswordUsage,
  PolicyRuleId,
  Priority,
  RecommendationCode,
  RiskFactor,
  RiskLevel,
  StrengthLabel,
} from '../api/types.ts';

/** Risk levels, lowest to highest, with the score bands used by the engine. */
export const RISK_LEVELS: readonly { level: RiskLevel; label: string; from: number; to: number }[] =
  [
    { level: 'low', label: 'Low', from: 0, to: 19 },
    { level: 'moderate', label: 'Moderate', from: 20, to: 39 },
    { level: 'high', label: 'High', from: 40, to: 69 },
    { level: 'critical', label: 'Critical', from: 70, to: 100 },
  ];

export const RISK_LABEL: Record<RiskLevel, string> = {
  low: 'Low',
  moderate: 'Moderate',
  high: 'High',
  critical: 'Critical',
};

export function riskTone(level: RiskLevel): BadgeTone {
  return { low: 'success', moderate: 'warning', high: 'danger', critical: 'danger' }[
    level
  ] as BadgeTone;
}

/** Order used by every risk list/legend. */
export const RISK_ORDER: readonly RiskLevel[] = ['low', 'moderate', 'high', 'critical'];

export const STRENGTH_LABEL: Record<StrengthLabel, string> = {
  very_weak: 'Very weak',
  weak: 'Weak',
  fair: 'Fair',
  strong: 'Strong',
  very_strong: 'Very strong',
};

export const STRENGTH_SCORE_LABEL = ['Very weak', 'Weak', 'Fair', 'Strong', 'Very strong'] as const;

export const FINDING_LABEL: Record<FindingKind, { title: string; short: string }> = {
  common_password: { title: 'Common password', short: 'Common' },
  personal_info: { title: 'Personal information', short: 'Personal' },
  keyboard_pattern: { title: 'Keyboard pattern', short: 'Keyboard' },
  sequence: { title: 'Sequence', short: 'Sequence' },
  repeated_characters: { title: 'Repeated characters', short: 'Repeats' },
  repeated_block: { title: 'Repeated block', short: 'Repeats' },
  date_pattern: { title: 'Date or year', short: 'Date' },
  dictionary_word: { title: 'Dictionary word', short: 'Word' },
};

/** Which finding wins when several overlap the same characters (first = highest). */
export const FINDING_PRIORITY: readonly FindingKind[] = [
  'common_password',
  'personal_info',
  'keyboard_pattern',
  'sequence',
  'repeated_block',
  'repeated_characters',
  'date_pattern',
  'dictionary_word',
];

export const POLICY_RULE_LABEL: Record<PolicyRuleId, string> = {
  min_length: 'Minimum length',
  max_length: 'Maximum length',
  min_lowercase: 'Lowercase letters',
  min_uppercase: 'Uppercase letters',
  min_digits: 'Digits',
  min_symbols: 'Symbols',
  min_unique_characters: 'Distinct characters',
  max_repeat_run: 'Repeated characters',
  max_sequence_length: 'Sequences',
  max_keyboard_run: 'Keyboard runs',
  forbid_whitespace: 'Whitespace',
  block_common_passwords: 'Common passwords',
  forbid_personal_info: 'Personal information',
  min_strength_score: 'Strength score',
  block_dictionary_words: 'Dictionary words',
  block_breached_passwords: 'Known breaches',
};

export const RECOMMENDATION_TITLE: Record<RecommendationCode, string> = {
  avoid_common_password: 'Avoid common passwords',
  avoid_personal_info: 'Remove personal information',
  lengthen: 'Make it longer',
  avoid_repeats: 'Avoid repetition',
  avoid_sequences: 'Avoid sequences',
  avoid_keyboard_patterns: 'Avoid keyboard patterns',
  meet_policy: 'Meet the password policy',
  below_usage_target: 'Strengthen for its purpose',
  use_passphrase: 'Use a passphrase',
  use_password_manager: 'Use a password manager',
  enable_mfa: 'Turn on multi-factor authentication',
  unique_per_service: 'Never reuse passwords',
  add_variety: 'Add variety or length',
  looks_good: 'No weaknesses detected',
  avoid_dates: 'Leave out dates and years',
  avoid_dictionary_words: 'Avoid common words and names',
  change_breached_password: 'Replace this breached password',
};

export const PRIORITY_TONE: Record<Priority, BadgeTone> = {
  high: 'danger',
  medium: 'warning',
  low: 'accent',
};

export const USAGE_OPTIONS: readonly { value: PasswordUsage; label: string; hint: string }[] = [
  { value: 'general', label: 'General use', hint: 'Target: about 10^8 guesses' },
  { value: 'online_account', label: 'Online account', hint: 'Rate-limited login' },
  {
    value: 'privileged_account',
    label: 'Privileged account',
    hint: 'Admin, financial or recovery',
  },
  { value: 'master_password', label: 'Master password', hint: 'Password-manager or vault' },
  { value: 'encryption_key', label: 'Encryption key', hint: 'Attackable offline' },
];

export const USAGE_LABEL: Record<PasswordUsage, string> = Object.fromEntries(
  USAGE_OPTIONS.map((o) => [o.value, o.label]),
) as Record<PasswordUsage, string>;

/** Engine v1 risk-score components (max points sum to 100). See docs/analysis-engine.md. */
export const RISK_FACTORS: readonly {
  factor: RiskFactor;
  label: string;
  max: number | null;
  how: string;
}[] = [
  {
    factor: 'guessability',
    label: 'Guessability',
    max: 50,
    how: '50 x (1 - min(log10 guesses, 12) / 12), from zxcvbn',
  },
  {
    factor: 'length',
    label: 'Length',
    max: 10,
    how: 'Under 8 characters: 10; under 12: 6; under 16: 3; else 0',
  },
  {
    factor: 'common_password',
    label: 'Common password',
    max: 15,
    how: 'Exact 15, reversed 12, leetspeak 12, decorated 10, embedded 5 (capped)',
  },
  {
    factor: 'patterns',
    label: 'Patterns',
    max: 10,
    how: 'Repeat 3, sequence 3, keyboard run 4 per finding (capped)',
  },
  {
    factor: 'personal_info',
    label: 'Personal information',
    max: 10,
    how: '10 if the password contains supplied personal details',
  },
  { factor: 'policy', label: 'Policy', max: 5, how: '1 point per violated rule (capped)' },
  {
    factor: 'known_weak_floor',
    label: 'Known-weak floor',
    max: null,
    how: 'Raises the score to at least 85 for a known common password',
  },
];

export const RISK_FACTOR_LABEL: Record<RiskFactor, string> = Object.fromEntries(
  RISK_FACTORS.map((f) => [f.factor, f.label]),
) as Record<RiskFactor, string>;
