import { ApiRequestError, createApiClient } from './client.ts';
import { errorResponse, json } from '../test/fakeApi.ts';

const CANARY = 'Zq9-canary-Secret-4471';

function clientWith(impl: (url: string, init: RequestInit) => Response | Promise<Response>) {
  const calls: { url: string; init: RequestInit }[] = [];
  const fetchImpl = ((input: RequestInfo | URL, init: RequestInit = {}) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
    calls.push({ url, init });
    return Promise.resolve(impl(url, init));
  }) as typeof fetch;
  return { client: createApiClient({ baseUrl: '/api/v1', fetchImpl }), calls };
}

const ANALYSIS = {
  strength: {},
  entropy: {},
  findings: [],
  policy: {},
  risk: {},
  recommendations: [],
};

describe('API client requests', () => {
  it('POSTs the password in the JSON body only, with privacy-preserving fetch options', async () => {
    const { client, calls } = clientWith(() => json(ANALYSIS));
    await client.audit({ password: CANARY });
    const [call] = calls;
    expect(call?.url).toBe('/api/v1/audit');
    expect(call?.url).not.toContain(CANARY);
    expect(call?.init.method).toBe('POST');
    expect(JSON.parse(call?.init.body as string)).toEqual({ password: CANARY });
    expect(call?.init.credentials).toBe('omit');
    expect(call?.init.cache).toBe('no-store');
    expect(call?.init.referrerPolicy).toBe('no-referrer');
    expect(JSON.stringify(call?.init.headers)).not.toContain(CANARY);
  });

  it('GET requests carry no body and no Content-Type', async () => {
    const { client, calls } = clientWith(() => json({ status: 'ok', version: '1' }));
    await client.health();
    expect(calls[0]?.init.body).toBeNull();
    expect(JSON.stringify(calls[0]?.init.headers)).not.toContain('Content-Type');
  });

  it('never logs anything, even on failure', async () => {
    const spies = (['log', 'info', 'warn', 'error', 'debug'] as const).map((m) =>
      vi.spyOn(console, m).mockImplementation(() => undefined),
    );
    const { client } = clientWith(() => errorResponse(500, 'internal_error', 'Boom.'));
    await expect(client.audit({ password: CANARY })).rejects.toBeInstanceOf(ApiRequestError);
    const failing = createApiClient({
      fetchImpl: () => Promise.reject(new TypeError(`Failed to fetch ${CANARY}`)),
    });
    await expect(failing.audit({ password: CANARY })).rejects.toBeInstanceOf(ApiRequestError);
    expect(JSON.stringify(spies.flatMap((s) => s.mock.calls))).toBe('[]');
    vi.restoreAllMocks();
  });
});

describe('API client errors', () => {
  it('parses the server error envelope', async () => {
    const { client } = clientWith(() =>
      errorResponse(429, 'rate_limited', 'Slow down.', {
        headers: { 'Retry-After': '7' },
        requestId: 'abc123',
      }),
    );
    const error = await client.audit({ password: 'x' }).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ApiRequestError);
    expect(error).toMatchObject({
      kind: 'http',
      status: 429,
      code: 'rate_limited',
      requestId: 'abc123',
      retryAfter: 7,
    });
  });

  it('copes with an error status that has no JSON body', async () => {
    const { client } = clientWith(() => new Response('<html>not found</html>', { status: 404 }));
    const error = (await client.health().catch((e: unknown) => e)) as ApiRequestError;
    expect(error.kind).toBe('http');
    expect(error.status).toBe(404);
    expect(error.message).toBe('The service answered with status 404.');
  });

  it('a bare 5xx (proxy or gateway with nothing behind it) means "unreachable"', async () => {
    for (const status of [500, 502, 503, 504]) {
      const { client } = clientWith(() => new Response('', { status }));
      const error = (await client
        .audit({ password: 'x' })
        .catch((e: unknown) => e)) as ApiRequestError;
      expect(error.kind, String(status)).toBe('network');
    }
    // ...but the service's own 500 (with its envelope) stays an http error with a request id.
    const { client } = clientWith(() =>
      errorResponse(500, 'internal_error', 'Boom.', { requestId: 'r9' }),
    );
    expect(await client.audit({ password: 'x' }).catch((e: unknown) => e)).toMatchObject({
      kind: 'http',
      requestId: 'r9',
    });
  });

  it('an unreachable service is a "network" error with fixed text (never the thrown message)', async () => {
    const client = createApiClient({
      fetchImpl: () => Promise.reject(new TypeError(`Failed to fetch ${CANARY}`)),
    });
    const error = (await client
      .audit({ password: CANARY })
      .catch((e: unknown) => e)) as ApiRequestError;
    expect(error.kind).toBe('network');
    expect(error.message).not.toContain(CANARY);
  });

  it('rejects a success response with an unexpected shape', async () => {
    const { client } = clientWith(() => json({ nope: true }));
    const error = (await client
      .audit({ password: 'x' })
      .catch((e: unknown) => e)) as ApiRequestError;
    expect(error.kind).toBe('invalid-response');
    await expect(
      clientWith(() => json({ nope: true })).client.batch({ items: [] }),
    ).rejects.toMatchObject({
      kind: 'invalid-response',
    });
  });

  it('times out slow requests and honours caller cancellation', async () => {
    vi.useFakeTimers();
    const never = ((_: RequestInfo | URL, init: RequestInit = {}) =>
      new Promise((_resolve, reject) => {
        init.signal?.addEventListener('abort', () => {
          reject(new DOMException('aborted', 'AbortError'));
        });
      })) as typeof fetch;
    const client = createApiClient({ fetchImpl: never });
    const slow = client.health().catch((e: unknown) => e);
    await vi.advanceTimersByTimeAsync(5001);
    expect(await slow).toMatchObject({ kind: 'timeout' });

    const controller = new AbortController();
    const cancelled = client.audit({ password: 'x' }, controller.signal).catch((e: unknown) => e);
    controller.abort();
    expect(await cancelled).toMatchObject({ kind: 'aborted' });
    vi.useRealTimers();
  });
});
