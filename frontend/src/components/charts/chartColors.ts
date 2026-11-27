import type { FindingKind, RiskLevel } from '../../api/types.ts';

/** CSS colour strings from the design tokens, so charts re-theme with the rest of the UI. */
export const CHART_COLOR = {
  success: 'rgb(var(--success))',
  warning: 'rgb(var(--warning))',
  danger: 'rgb(var(--danger))',
  primary: 'rgb(var(--primary))',
  secondary: 'rgb(var(--purple))',
  accent: 'rgb(var(--cyan))',
  muted: 'rgb(var(--fg) / 0.45)',
  track: 'rgb(var(--fg) / 0.12)',
} as const;

export const RISK_COLOR: Record<RiskLevel, string> = {
  low: CHART_COLOR.success,
  moderate: CHART_COLOR.warning,
  high: CHART_COLOR.danger,
  critical: CHART_COLOR.danger,
};

/** "high" is drawn with diagonal hatching so it differs from "critical" without relying on colour. */
export const RISK_HATCHED: Record<RiskLevel, boolean> = {
  low: false,
  moderate: false,
  high: true,
  critical: false,
};

/** One colour and one letter per finding kind: the letter keeps charts readable without colour. */
export const FINDING_STYLE: Record<FindingKind, { color: string; letter: string; bg: string }> = {
  common_password: { color: CHART_COLOR.danger, letter: 'C', bg: 'bg-danger' },
  personal_info: { color: CHART_COLOR.secondary, letter: 'P', bg: 'bg-secondary' },
  keyboard_pattern: { color: CHART_COLOR.warning, letter: 'K', bg: 'bg-warning' },
  sequence: { color: CHART_COLOR.accent, letter: 'S', bg: 'bg-accent' },
  repeated_block: { color: CHART_COLOR.muted, letter: 'R', bg: 'bg-fg/50' },
  repeated_characters: { color: CHART_COLOR.muted, letter: 'R', bg: 'bg-fg/50' },
  date_pattern: { color: CHART_COLOR.primary, letter: 'D', bg: 'bg-primary' },
  dictionary_word: { color: CHART_COLOR.success, letter: 'W', bg: 'bg-success' },
};

/** Strength 0-4 segment colours (weakest to strongest). */
export const STRENGTH_COLORS = [
  CHART_COLOR.danger,
  CHART_COLOR.danger,
  CHART_COLOR.warning,
  CHART_COLOR.success,
  CHART_COLOR.primary,
] as const;
