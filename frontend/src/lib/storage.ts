/**
 * localStorage helpers that never throw (private windows, blocked storage, quota).
 * Only UI preferences are stored - never passwords or anything derived from them.
 */
export function readStorage(key: string): string | null {
  try {
    return window.localStorage.getItem(key);
  } catch {
    return null;
  }
}

export function writeStorage(key: string, value: string): void {
  try {
    window.localStorage.setItem(key, value);
  } catch {
    /* preference simply isn't remembered */
  }
}
