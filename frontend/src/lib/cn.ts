export type ClassValue = string | false | null | undefined;

/** Join class names, ignoring falsy values. Later classes win only by CSS order, so
 * components keep variant classes disjoint and append the caller's `className` last. */
export function cn(...values: ClassValue[]): string {
  return values.filter(Boolean).join(' ');
}
