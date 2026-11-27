import type { ExposureOptions } from '../api/types.ts';

/** Everything external is OFF by default and is never remembered between visits. */
export const NO_EXPOSURE: ExposureOptions = { breach: 'off', reuse: false };

export function isExposureRequested(options: ExposureOptions): boolean {
  return options.breach !== 'off' || options.reuse;
}

/**
 * The `exposure` field of a request - or nothing at all when no external check is wanted, so an
 * ordinary audit sends exactly what it always did (and works against an older backend).
 */
export function exposureField(options: ExposureOptions): { exposure?: ExposureOptions } {
  return isExposureRequested(options) ? { exposure: { ...options } } : {};
}
