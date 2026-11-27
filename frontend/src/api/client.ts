import type {
  ApiErrorDetail,
  ApiErrorEnvelope,
  AuditRequest,
  BatchRequest,
  BatchResponse,
  CapabilitiesResponse,
  HealthResponse,
  LimitsResponse,
  PasswordAnalysis,
  PasswordPolicy,
  PolicyProfile,
  PolicyValidationResponse,
} from './types.ts';

/**
 * The PassAudit API client.
 *
 * Privacy rules enforced here (docs/api.md, security.md):
 *  - passwords are only ever sent in the JSON body of a POST - never in a URL or header;
 *  - requests are `no-store`, carry no credentials, and send no Referer;
 *  - nothing is logged, and request bodies are never kept after the call;
 *  - error messages come from the server's sanitised envelope or from fixed text - they never
 *    include what was sent.
 */

export type ApiErrorKind =
  /** The service could not be reached (not running, blocked, offline). */
  | 'network'
  | 'timeout'
  | 'aborted'
  /** The service answered with an error status. */
  | 'http'
  /** The service answered, but not with the expected shape. */
  | 'invalid-response';

export class ApiRequestError extends Error {
  readonly kind: ApiErrorKind;
  readonly status: number | undefined;
  readonly code: string | undefined;
  readonly requestId: string | undefined;
  /** Seconds to wait before retrying (429/503). */
  readonly retryAfter: number | undefined;
  readonly details: readonly ApiErrorDetail[];

  constructor(
    kind: ApiErrorKind,
    message: string,
    extra: {
      status?: number;
      code?: string;
      requestId?: string;
      retryAfter?: number;
      details?: readonly ApiErrorDetail[];
    } = {},
  ) {
    super(message);
    this.name = 'ApiRequestError';
    this.kind = kind;
    this.status = extra.status;
    this.code = extra.code;
    this.requestId = extra.requestId;
    this.retryAfter = extra.retryAfter;
    this.details = extra.details ?? [];
  }
}

export const DEFAULT_BASE_URL: string = import.meta.env.VITE_API_BASE_URL ?? '/api/v1';
export const DEFAULT_TIMEOUT_MS = 30_000;

interface RequestOptions {
  body?: unknown;
  signal?: AbortSignal | undefined;
  timeoutMs?: number;
}

export interface ClientConfig {
  baseUrl?: string;
  fetchImpl?: typeof fetch;
}

function isEnvelope(value: unknown): value is ApiErrorEnvelope {
  if (typeof value !== 'object' || value === null || !('error' in value)) return false;
  const error = value.error;
  return (
    typeof error === 'object' &&
    error !== null &&
    typeof (error as { code?: unknown }).code === 'string' &&
    typeof (error as { message?: unknown }).message === 'string'
  );
}

function expectObject(value: unknown, keys: readonly string[], what: string): void {
  if (typeof value !== 'object' || value === null || keys.some((key) => !(key in value))) {
    throw new ApiRequestError('invalid-response', `The service returned an unexpected ${what}.`);
  }
}

async function request<T>(
  config: ClientConfig,
  method: 'GET' | 'POST',
  path: string,
  options: RequestOptions,
): Promise<T> {
  const doFetch = config.fetchImpl ?? fetch;
  const controller = new AbortController();
  const flags = { timedOut: false };
  const timer = setTimeout(() => {
    flags.timedOut = true;
    controller.abort();
  }, options.timeoutMs ?? DEFAULT_TIMEOUT_MS);
  const outer = options.signal;
  const onOuterAbort = () => {
    controller.abort();
  };
  if (outer?.aborted) controller.abort();
  outer?.addEventListener('abort', onOuterAbort);

  try {
    let response: Response;
    try {
      response = await doFetch(`${config.baseUrl ?? DEFAULT_BASE_URL}${path}`, {
        method,
        headers:
          options.body === undefined
            ? { Accept: 'application/json' }
            : { Accept: 'application/json', 'Content-Type': 'application/json' },
        body: options.body === undefined ? null : JSON.stringify(options.body),
        cache: 'no-store',
        credentials: 'omit',
        referrerPolicy: 'no-referrer',
        signal: controller.signal,
      });
    } catch {
      if (flags.timedOut) {
        throw new ApiRequestError('timeout', 'The service took too long to respond.');
      }
      if (outer?.aborted) throw new ApiRequestError('aborted', 'The request was cancelled.');
      throw new ApiRequestError(
        'network',
        'PassAudit could not reach its local service. Is the backend running?',
      );
    }

    let payload: unknown = null;
    try {
      payload = await response.json();
    } catch {
      payload = null;
    }

    if (!response.ok) {
      const retryAfterHeader = Number(response.headers.get('Retry-After'));
      const retryAfter =
        Number.isFinite(retryAfterHeader) && retryAfterHeader > 0 ? retryAfterHeader : undefined;
      if (isEnvelope(payload)) {
        throw new ApiRequestError('http', payload.error.message, {
          status: response.status,
          code: payload.error.code,
          ...(payload.error.request_id ? { requestId: payload.error.request_id } : {}),
          ...(retryAfter !== undefined ? { retryAfter } : {}),
          details: payload.error.details ?? [],
        });
      }
      // The PassAudit API always answers errors with its JSON envelope. A bare 5xx therefore
      // comes from something in front of it (the dev proxy, a gateway) that could not reach
      // the service - report that as "unreachable" so the user is told to start it.
      if (response.status >= 500) {
        throw new ApiRequestError(
          'network',
          'PassAudit could not reach its local service. Is the backend running?',
          { status: response.status },
        );
      }
      throw new ApiRequestError(
        'http',
        `The service answered with status ${String(response.status)}.`,
        {
          status: response.status,
          ...(retryAfter !== undefined ? { retryAfter } : {}),
        },
      );
    }
    return payload as T;
  } finally {
    clearTimeout(timer);
    outer?.removeEventListener('abort', onOuterAbort);
  }
}

/** Create a client. Tests inject `fetchImpl`; the app uses the default. */
export function createApiClient(config: ClientConfig = {}) {
  return {
    async health(signal?: AbortSignal): Promise<HealthResponse> {
      const data = await request<HealthResponse>(config, 'GET', '/health', {
        signal,
        timeoutMs: 5000,
      });
      expectObject(data, ['status', 'version'], 'health response');
      return data;
    },
    async limits(signal?: AbortSignal): Promise<LimitsResponse> {
      const data = await request<LimitsResponse>(config, 'GET', '/limits', {
        signal,
        timeoutMs: 5000,
      });
      expectObject(
        data,
        ['max_password_length', 'batch_max_items', 'rate_limit'],
        'limits response',
      );
      return data;
    },
    async capabilities(signal?: AbortSignal): Promise<CapabilitiesResponse> {
      const data = await request<CapabilitiesResponse>(config, 'GET', '/capabilities', {
        signal,
        timeoutMs: 5000,
      });
      expectObject(
        data,
        ['external_lookups_enabled', 'breach', 'reuse_index', 'profiles'],
        'capabilities',
      );
      return data;
    },
    async policyProfile(name: string, signal?: AbortSignal): Promise<PolicyProfile> {
      const data = await request<PolicyProfile>(
        config,
        'GET',
        `/policy/profiles/${encodeURIComponent(name)}`,
        { signal },
      );
      expectObject(data, ['name', 'policy', 'usage'], 'policy profile');
      return data;
    },
    async defaultPolicy(signal?: AbortSignal): Promise<PasswordPolicy> {
      const data = await request<PasswordPolicy>(config, 'GET', '/policy/default', { signal });
      expectObject(data, ['min_length', 'block_common_passwords'], 'policy');
      return data;
    },
    async audit(body: AuditRequest, signal?: AbortSignal): Promise<PasswordAnalysis> {
      const data = await request<PasswordAnalysis>(config, 'POST', '/audit', { body, signal });
      expectObject(
        data,
        ['strength', 'entropy', 'findings', 'policy', 'risk', 'recommendations'],
        'analysis',
      );
      return data;
    },
    async validatePolicy(
      body: AuditRequest,
      signal?: AbortSignal,
    ): Promise<PolicyValidationResponse> {
      const data = await request<PolicyValidationResponse>(config, 'POST', '/policy/validate', {
        body,
        signal,
      });
      expectObject(data, ['compliant', 'rules', 'violations'], 'policy result');
      return data;
    },
    async batch(body: BatchRequest, signal?: AbortSignal): Promise<BatchResponse> {
      const data = await request<BatchResponse>(config, 'POST', '/audit/batch', { body, signal });
      expectObject(data, ['count', 'summary', 'results'], 'batch result');
      return data;
    },
  };
}

export type ApiClient = ReturnType<typeof createApiClient>;

/** The shared client used by the app. */
export const api: ApiClient = createApiClient();
