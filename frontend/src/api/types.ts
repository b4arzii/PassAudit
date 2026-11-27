/**
 * TypeScript mirror of the PassAudit API v1 (docs/api.md). Kept deliberately close to the wire
 * format. The demo fixtures in src/demo are produced by the real engine, and tests check them
 * against these shapes, so a backend change that breaks the contract fails a test here.
 *
 * Nothing in these types ever contains a password: the engine returns positions, scores and
 * fixed-text advice only.
 */

export type RiskLevel = 'low' | 'moderate' | 'high' | 'critical';
export type StrengthLabel = 'very_weak' | 'weak' | 'fair' | 'strong' | 'very_strong';
export type Priority = 'high' | 'medium' | 'low';
export type PasswordUsage =
  'general' | 'online_account' | 'privileged_account' | 'master_password' | 'encryption_key';

export type FindingKind =
  | 'repeated_characters'
  | 'repeated_block'
  | 'sequence'
  | 'keyboard_pattern'
  | 'common_password'
  | 'personal_info'
  | 'date_pattern'
  | 'dictionary_word';

export type WordMatchType = 'exact' | 'reversed' | 'leet' | 'decorated' | 'embedded' | 'segmented';

export type PolicyRuleId =
  | 'min_length'
  | 'max_length'
  | 'min_lowercase'
  | 'min_uppercase'
  | 'min_digits'
  | 'min_symbols'
  | 'min_unique_characters'
  | 'max_repeat_run'
  | 'max_sequence_length'
  | 'max_keyboard_run'
  | 'forbid_whitespace'
  | 'block_common_passwords'
  | 'forbid_personal_info'
  | 'min_strength_score'
  | 'block_dictionary_words'
  | 'block_breached_passwords';

export type RiskFactor =
  | 'guessability'
  | 'length'
  | 'common_password'
  | 'patterns'
  | 'personal_info'
  | 'policy'
  | 'known_weak_floor';

export type RecommendationCode =
  | 'avoid_common_password'
  | 'avoid_personal_info'
  | 'lengthen'
  | 'avoid_repeats'
  | 'avoid_sequences'
  | 'avoid_keyboard_patterns'
  | 'meet_policy'
  | 'below_usage_target'
  | 'use_passphrase'
  | 'use_password_manager'
  | 'enable_mfa'
  | 'unique_per_service'
  | 'add_variety'
  | 'looks_good'
  | 'avoid_dates'
  | 'avoid_dictionary_words'
  | 'change_breached_password';

export interface PasswordPolicy {
  min_length: number;
  max_length: number | null;
  min_lowercase: number;
  min_uppercase: number;
  min_digits: number;
  min_symbols: number;
  min_unique_characters: number;
  max_repeat_run: number | null;
  max_sequence_length: number | null;
  max_keyboard_run: number | null;
  allow_whitespace: boolean;
  block_common_passwords: boolean;
  forbid_personal_info: boolean;
  min_strength_score: number;
  block_dictionary_words: boolean;
  block_breached_passwords: boolean;
}

export interface AnalysisContext {
  usage?: PasswordUsage;
  personal_info?: string[];
  reused_elsewhere?: boolean;
}

export interface CrackTimes {
  online_throttled: string;
  online_unthrottled: string;
  offline_slow_hash: string;
  offline_fast_hash: string;
}

export interface StrengthSegment {
  pattern: string;
  start: number;
  length: number;
  guesses_log10: number;
  dictionary: string | null;
  l33t: boolean;
  reversed: boolean;
}

export interface StrengthEstimate {
  score: number;
  label: StrengthLabel;
  guesses_log10: number;
  crack_times: CrackTimes;
  segments: StrengthSegment[];
  warning: string;
  suggestions: string[];
  truncated: boolean;
  analyzed_length: number;
}

export interface EntropyEstimate {
  pool_size: number;
  charset_bits: number;
  shannon_bits_per_char: number;
  shannon_bits: number;
  guess_bits: number;
  estimated_bits: number;
  limitations: string[];
}

export interface Finding {
  kind: FindingKind;
  start: number;
  length: number;
  description: string;
  match_type: WordMatchType | null;
  repeat_count: number | null;
  direction: 'ascending' | 'descending' | null;
  layout: string | null;
  /** SEQUENCE only: distance between neighbours (1, 2 or 3). */
  step?: number | null;
  /** DICTIONARY_WORD only: which dictionary matched ("words" or "names"). */
  dictionary?: string | null;
}

export interface PolicyViolation {
  rule: PolicyRuleId;
  message: string;
  required: number | null;
  actual: number | null;
}

export interface RiskComponent {
  factor: RiskFactor;
  points: number;
  max_points: number | null;
  explanation: string;
}

export interface Recommendation {
  code: RecommendationCode;
  priority: Priority;
  message: string;
}

/**
 * Outcome of an opt-in breach lookup. Never contains the password or its hash.
 * `unavailable` means the lookup was requested but did not complete: the password is UNCHECKED.
 */
export interface BreachExposure {
  status: 'clean' | 'breached' | 'unavailable';
  source: 'local' | 'online';
  count?: number | null;
}

/** Which of the operator's authorised local reuse datasets (by name) contain the password. */
export interface ReuseExposure {
  status: 'clean' | 'reused';
  sources: string[];
}

export interface ExposureSignals {
  breach?: BreachExposure | null;
  reuse?: ReuseExposure | null;
}

export type BreachMode = 'off' | 'local' | 'online';

/** Opt-in lookups for a request. Omitted (or all off) means nothing external happens. */
export interface ExposureOptions {
  breach: BreachMode;
  reuse: boolean;
}

export interface PasswordAnalysis {
  version: string;
  length: number;
  strength: StrengthEstimate;
  entropy: EntropyEstimate;
  findings: Finding[];
  policy: { compliant: boolean; violations: PolicyViolation[] };
  risk: { score: number; level: RiskLevel; components: RiskComponent[] };
  meets_usage_target: boolean;
  recommendations: Recommendation[];
  exposure?: ExposureSignals | null;
}

export interface AuditRequest {
  password: string;
  policy?: Partial<PasswordPolicy>;
  context?: AnalysisContext;
  /** Only sent when something is switched on. */
  exposure?: ExposureOptions;
}

export interface PolicyRuleResult {
  rule: PolicyRuleId;
  requirement: string;
  /** `unchecked`: the rule needs an opt-in lookup that was not run. */
  status: 'pass' | 'fail' | 'unchecked';
  required: number | null;
  actual: number | null;
  message: string | null;
}

export interface PolicyValidationResponse {
  compliant: boolean;
  length: number;
  rules: PolicyRuleResult[];
  violations: PolicyViolation[];
}

export interface BatchItem {
  id?: string | null;
  password: string;
}

export interface BatchRequest {
  items: BatchItem[];
  policy?: Partial<PasswordPolicy>;
  context?: AnalysisContext;
  detail?: 'summary' | 'full';
  exposure?: ExposureOptions;
}

export interface BatchResultItem {
  index: number;
  id: string | null;
  length: number;
  reused_in_batch: boolean;
  risk_score: number;
  risk_level: RiskLevel;
  strength_score: number;
  strength_label: StrengthLabel;
  guesses_log10: number;
  estimated_bits: number;
  policy_compliant: boolean;
  policy_violations: PolicyRuleId[];
  findings: FindingKind[];
  recommendations: RecommendationCode[];
  /** `null`/absent: no breach check was requested. */
  breach?: 'clean' | 'breached' | 'unavailable' | null;
  reuse_datasets?: string[] | null;
  analysis: PasswordAnalysis | null;
}

export interface BatchSummary {
  analyzed: number;
  policy_compliant: number;
  policy_violations: number;
  average_risk_score: number | null;
  max_risk_score: number | null;
  risk_levels: Record<RiskLevel, number>;
  strength_scores: Record<'0' | '1' | '2' | '3' | '4', number>;
  finding_kinds: Partial<Record<FindingKind, number>>;
  recommendation_codes: Partial<Record<RecommendationCode, number>>;
  reused_in_batch: number;
  breached?: number;
  reused_in_datasets?: number;
}

export interface BatchResponse {
  count: number;
  summary: BatchSummary;
  results: BatchResultItem[];
}

export interface HealthResponse {
  status: 'ok';
  version: string;
}

export interface LimitsResponse {
  max_password_length: number;
  max_body_bytes: number;
  batch_max_items: number;
  batch_max_body_bytes: number;
  max_personal_info_items: number;
  max_personal_info_item_length: number;
  rate_limit: {
    enabled: boolean;
    burst: number;
    refill_per_minute: number;
    cost_per_password: number;
  };
}

export interface PolicyProfile {
  name: string;
  title: string;
  description: string;
  policy: PasswordPolicy;
  usage: PasswordUsage;
  references: string[];
  builtin: boolean;
}

export interface ProfileSummary {
  name: string;
  title: string;
  description: string;
  usage: string;
  builtin: boolean;
}

/** What this server can do beyond the basics, so the UI offers only real options. */
export interface CapabilitiesResponse {
  external_lookups_enabled: boolean;
  breach: { local: boolean; online: boolean; online_host: string | null; protocol: string };
  reuse_index: { available: boolean; datasets: string[]; authorization_reference: string | null };
  profiles: ProfileSummary[];
  dictionaries: { words: number; names: number; passwords: number };
}

export interface ApiErrorDetail {
  loc: (string | number)[];
  type: string;
  message: string;
}

export interface ApiErrorEnvelope {
  error: {
    code: string;
    message: string;
    request_id?: string;
    details?: ApiErrorDetail[];
  };
}
