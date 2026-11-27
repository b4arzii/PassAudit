import { ApiRequestError } from '../api/client.ts';

export interface FieldIssue {
  field: string;
  message: string;
}

export interface FriendlyError {
  tone: 'danger' | 'warning';
  title: string;
  message: string;
  /** Concrete things the user can do. */
  hints: string[];
  /** The backend could not be reached at all (offer demo data). */
  offline: boolean;
  retryable: boolean;
  /** Seconds before a retry is sensible (rate limit / busy). */
  retryAfter: number | undefined;
  requestId: string | undefined;
  issues: FieldIssue[];
}

/** A readable name for an API validation `loc` such as ["body","items",2,"password"]. */
export function describeLoc(loc: readonly (string | number)[]): string {
  const parts = loc.filter((p) => p !== 'body');
  if (parts.length === 0) return 'request';
  const out: string[] = [];
  for (const part of parts) {
    out.push(
      typeof part === 'number'
        ? `item ${String(part + 1)}`
        : part === '<unknown field>'
          ? 'unrecognised field'
          : part.replace(/_/g, ' '),
    );
  }
  return out.join(' / ');
}

const START_BACKEND = 'Start the backend with ".\\scripts\\dev.ps1 -Only backend", then retry.';

/**
 * Turn any thrown value into something a person can act on. Messages come from the server's
 * sanitised envelope or fixed text here - they never quote what the user typed.
 */
export function friendlyError(error: unknown): FriendlyError {
  const base: FriendlyError = {
    tone: 'danger',
    title: 'Something went wrong',
    message: 'An unexpected problem occurred. Nothing was stored.',
    hints: [],
    offline: false,
    retryable: true,
    retryAfter: undefined,
    requestId: undefined,
    issues: [],
  };
  if (!(error instanceof ApiRequestError)) return base;

  const withRequest = { ...base, requestId: error.requestId };
  switch (error.kind) {
    case 'network':
      return {
        ...withRequest,
        title: "Can't reach the PassAudit service",
        message: error.message,
        hints: [START_BACKEND, 'Your input was not sent anywhere else.'],
        offline: true,
      };
    case 'timeout':
      return {
        ...withRequest,
        tone: 'warning',
        title: 'The service took too long',
        message: error.message,
        hints: ['Try a smaller batch, or retry in a moment.'],
      };
    case 'aborted':
      return {
        ...withRequest,
        tone: 'warning',
        title: 'Cancelled',
        message: error.message,
        hints: [],
      };
    case 'invalid-response':
      return {
        ...withRequest,
        title: 'Unexpected response',
        message: error.message,
        hints: ['The frontend and backend versions may not match. Update both and retry.'],
        retryable: false,
      };
    case 'http':
      break;
  }

  const status = error.status ?? 0;
  const issues: FieldIssue[] = error.details.map((d) => ({
    field: describeLoc(d.loc),
    message: d.message,
  }));
  if (status === 429) {
    return {
      ...withRequest,
      tone: 'warning',
      title: 'Too many requests',
      message: error.message,
      hints: ['The local service rate-limits requests. Wait a moment, then retry.'],
      retryAfter: error.retryAfter,
    };
  }
  if (status === 503) {
    return {
      ...withRequest,
      tone: 'warning',
      title: 'The service is busy',
      message: error.message,
      hints: ['It is analysing other requests. Retry shortly.'],
      retryAfter: error.retryAfter ?? 2,
    };
  }
  if (error.code === 'external_lookups_disabled') {
    return {
      ...withRequest,
      tone: 'warning',
      title: 'Online checks are turned off',
      message: error.message,
      hints: [
        'Choose "Off" or a local dataset. The server operator can enable online checks in the server settings.',
        'Nothing was sent anywhere.',
      ],
      retryable: false,
    };
  }
  if (error.code === 'feature_unavailable') {
    return {
      ...withRequest,
      tone: 'warning',
      title: 'That check is not available',
      message: error.message,
      hints: ['Switch the optional check off, or ask the server operator to configure it.'],
      retryable: false,
    };
  }
  if (error.code === 'unknown_profile') {
    return {
      ...withRequest,
      title: 'Unknown policy profile',
      message: error.message,
      hints: ['Pick one of the profiles listed on the Policies page.'],
      retryable: false,
    };
  }
  if (status === 422 || error.code === 'validation_error') {
    return {
      ...withRequest,
      title:
        error.code === 'password_too_long' || error.code === 'batch_too_large'
          ? 'Over the size limit'
          : 'The request was not valid',
      message: error.message,
      hints: issues.length === 0 ? ['Check the form and try again.'] : [],
      retryable: false,
      issues,
    };
  }
  if (status === 413) {
    return {
      ...withRequest,
      title: 'The request is too large',
      message: error.message,
      hints: ['Reduce the number or length of passwords.'],
      retryable: false,
    };
  }
  if (status === 400 || status === 415) {
    return {
      ...withRequest,
      title: 'The request was rejected',
      message: error.message,
      retryable: false,
    };
  }
  if (status >= 500) {
    return {
      ...withRequest,
      title: 'The service hit an error',
      message: error.message,
      hints: error.requestId ? [`If it keeps happening, report request ${error.requestId}.`] : [],
    };
  }
  return { ...withRequest, title: 'The request failed', message: error.message };
}
