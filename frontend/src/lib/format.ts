export function plural(count: number, singular: string, pluralForm = `${singular}s`): string {
  return `${String(count)} ${count === 1 ? singular : pluralForm}`;
}

export function formatBits(bits: number): string {
  return `${String(Math.round(bits))} bits`;
}

/** `7.44` -> "10^7.4 guesses" in a compact form. */
export function formatGuesses(log10: number): string {
  return `10^${log10.toFixed(1)} guesses`;
}

export function formatPercent(part: number, total: number): string {
  if (total <= 0) return '0%';
  return `${String(Math.round((part / total) * 100))}%`;
}

export function formatDateTime(iso: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  return date.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
}

/** 1-based inclusive character range, as shown to users: "chars 3-6" / "char 3". */
export function formatRange(start: number, length: number): string {
  return length <= 1
    ? `char ${String(start + 1)}`
    : `chars ${String(start + 1)}-${String(start + length)}`;
}

export function clamp(value: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, value));
}
