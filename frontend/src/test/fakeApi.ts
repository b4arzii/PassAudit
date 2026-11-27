import { createApiClient } from '../api/client.ts';
import type { ApiClient } from '../api/client.ts';
import type {
  BatchRequest,
  BatchResponse,
  BatchResultItem,
  CapabilitiesResponse,
  ExposureSignals,
  PasswordAnalysis,
  PolicyProfile,
} from '../api/types.ts';
import { DEFAULT_POLICY } from '../lib/policy.ts';
import { demo } from '../demo/demo.ts';
import { FALLBACK_LIMITS } from '../state/api.ts';

/**
 * A fake PassAudit backend for tests: a `fetch` replacement that answers like the real API
 * (using the engine-generated demo fixtures for result shapes) and records every request, so
 * tests can assert on exactly what the browser sent.
 */

export interface RecordedCall {
  method: string;
  url: string;
  headers: Record<string, string>;
  /** Parsed JSON body, if any. */
  body: unknown;
  /** Raw body text, to search for leaked values. */
  rawBody: string;
  init: RequestInit;
}

export type Responder = (call: RecordedCall) => Response | Promise<Response>;

export function json(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', ...headers },
  });
}

export function errorResponse(
  status: number,
  code: string,
  message: string,
  extra: { details?: unknown[]; headers?: Record<string, string>; requestId?: string } = {},
): Response {
  return json(
    {
      error: {
        code,
        message,
        request_id: extra.requestId ?? 'req-test-0001',
        ...(extra.details ? { details: extra.details } : {}),
      },
    },
    status,
    extra.headers,
  );
}

/** Build a batch response for the submitted items, in the demo records' shapes. */
export function batchResponseFor(request: BatchRequest): BatchResponse {
  const seen = new Map<string, number>();
  for (const item of request.items) seen.set(item.password, (seen.get(item.password) ?? 0) + 1);
  const templates = demo.batch.results;
  const results: BatchResultItem[] = request.items.map((item, index) => {
    const template = templates[index % templates.length];
    if (!template) throw new Error('demo batch has no results');
    return {
      ...template,
      index,
      id: item.id ?? null,
      length: item.password.length,
      reused_in_batch: (seen.get(item.password) ?? 0) > 1,
      analysis: request.detail === 'full' ? (demo.analyses[0]?.analysis ?? null) : null,
    };
  });
  return {
    count: results.length,
    summary: { ...demo.batch.summary, analyzed: results.length },
    results,
  };
}

/** What a backend with no optional features reports (and what the app assumes by default). */
export const NO_FEATURES: CapabilitiesResponse = {
  external_lookups_enabled: false,
  breach: { local: false, online: false, online_host: null, protocol: 'k-anonymity range query' },
  reuse_index: { available: false, datasets: [], authorization_reference: null },
  profiles: [
    {
      name: 'default',
      title: 'Default',
      description: 'Sensible defaults.',
      usage: 'general',
      builtin: true,
    },
    {
      name: 'high-security',
      title: 'High security',
      description: 'For privileged accounts.',
      usage: 'privileged_account',
      builtin: true,
    },
  ],
  dictionaries: { words: 278, names: 182, passwords: 120 },
};

export function capabilitiesWith(overrides: Partial<CapabilitiesResponse>): CapabilitiesResponse {
  return { ...NO_FEATURES, ...overrides };
}

export const FAKE_PROFILES: Record<string, PolicyProfile> = {
  default: {
    name: 'default',
    title: 'Default',
    description: 'Sensible defaults.',
    policy: DEFAULT_POLICY,
    usage: 'general',
    references: [],
    builtin: true,
  },
  'high-security': {
    name: 'high-security',
    title: 'High security',
    description: 'For privileged accounts.',
    policy: {
      ...DEFAULT_POLICY,
      min_length: 16,
      block_dictionary_words: true,
      block_breached_passwords: true,
    },
    usage: 'privileged_account',
    references: [],
    builtin: true,
  },
};

/** The demo analysis with opt-in lookup results attached, as the backend would return it. */
export function analysisWithExposure(exposure: ExposureSignals): PasswordAnalysis {
  const base = demo.analyses[0]?.analysis;
  if (!base) throw new Error('demo has no analyses');
  return { ...base, exposure };
}

export interface FakeApi {
  client: ApiClient;
  fetch: typeof fetch;
  calls: RecordedCall[];
  /** Calls to the analysis endpoints only (not health/limits). */
  analysisCalls: () => RecordedCall[];
  /** Replace how one path is answered (`/audit`, `/audit/batch`, `/policy/validate`, ...). */
  on: (path: string, responder: Responder) => void;
}

export function createFakeApi(overrides: Record<string, Responder> = {}): FakeApi {
  const calls: RecordedCall[] = [];
  const responders = new Map<string, Responder>(Object.entries(overrides));

  const defaults: Record<string, Responder> = {
    '/health': () => json({ status: 'ok', version: '9.9.9-test' }),
    '/limits': () => json(FALLBACK_LIMITS),
    '/audit': () => json(demo.analyses[0]?.analysis),
    '/audit/batch': (call) => json(batchResponseFor(call.body as BatchRequest)),
    '/policy/validate': () => json(demo.policyCheck.result),
    '/policy/default': () => json({}),
    '/capabilities': () => json(NO_FEATURES),
  };

  const fakeFetch = (async (input: RequestInfo | URL, init: RequestInit = {}) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
    const rawBody = typeof init.body === 'string' ? init.body : '';
    const headers = Object.fromEntries(new Headers(init.headers).entries());
    const call: RecordedCall = {
      method: init.method ?? 'GET',
      url,
      headers,
      body: rawBody ? (JSON.parse(rawBody) as unknown) : undefined,
      rawBody,
      init,
    };
    calls.push(call);
    const path = url.replace(/^.*\/api\/v1/, '').split('?')[0] ?? url;
    const profileName = /^\/policy\/profiles\/(.+)$/.exec(path)?.[1];
    const profile = profileName ? FAKE_PROFILES[decodeURIComponent(profileName)] : undefined;
    const responder =
      responders.get(path) ??
      defaults[path] ??
      (profileName
        ? () =>
            profile
              ? json(profile)
              : errorResponse(422, 'unknown_profile', 'Unknown policy profile.')
        : undefined);
    if (!responder) return errorResponse(404, 'not_found', 'Not found.');
    return responder(call);
  }) as typeof fetch;

  return {
    client: createApiClient({ baseUrl: '/api/v1', fetchImpl: fakeFetch }),
    fetch: fakeFetch,
    calls,
    analysisCalls: () => calls.filter((c) => c.method === 'POST'),
    on: (path, responder) => {
      responders.set(path, responder);
    },
  };
}
