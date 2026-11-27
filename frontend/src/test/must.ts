/** Narrow a possibly-missing value in a test, failing with a clear message instead of a TypeError. */
export function must<T>(value: T | null | undefined, what = 'value'): T {
  if (value === null || value === undefined) throw new Error(`Expected ${what} to exist`);
  return value;
}
