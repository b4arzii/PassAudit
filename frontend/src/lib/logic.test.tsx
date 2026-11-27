import { act, renderHook } from '@testing-library/react';

import { ApiRequestError } from '../api/client.ts';
import { FALLBACK_LIMITS } from '../state/api.ts';
import { parseBatchInput, parseCsv } from './csv.ts';
import { friendlyError } from './errors.ts';
import {
  buildPolicyReportCsv,
  buildReportJson,
  csvCell,
  recordsToCsv,
  safeFilename,
} from './export.ts';
import { DEFAULT_POLICY, parsePolicyJson, policyOverrides, validatePolicy } from './policy.ts';
import type { AnalysisRecord } from './records.ts';
import { summarizeRecords } from './records.ts';
import { useAsyncAction } from './useAsyncAction.ts';
import {
  codePointLength,
  parsePersonalInfo,
  validateBatchEntries,
  validatePasswordInput,
} from './validation.ts';

const CANARY = 'Zq9-canary-Secret-4471';

describe('validation', () => {
  it('counts code points like the server, not UTF-16 units', () => {
    expect(codePointLength('abc')).toBe(3);
    expect(codePointLength('a\u{1F600}b')).toBe(3);
    expect(codePointLength('')).toBe(0);
  });

  it('checks password length without quoting the password', () => {
    expect(validatePasswordInput('', FALLBACK_LIMITS)).toMatch(/Enter a password/);
    expect(validatePasswordInput('x'.repeat(1024), FALLBACK_LIMITS)).toBeNull();
    const tooLong = validatePasswordInput(CANARY.repeat(60), FALLBACK_LIMITS);
    expect(tooLong).toMatch(/limit is 1024/);
    expect(tooLong).not.toContain(CANARY);
  });

  it('parses personal details: trims, drops blanks and duplicates, enforces limits', () => {
    expect(parsePersonalInfo(' Jane \n\nJane\nAcme\r\n', FALLBACK_LIMITS)).toEqual({
      items: ['Jane', 'Acme'],
      error: null,
    });
    const many = Array.from({ length: 51 }, (_, i) => `n${String(i)}`).join('\n');
    expect(parsePersonalInfo(many, FALLBACK_LIMITS).error).toMatch(/At most 50/);
    const long = parsePersonalInfo(`ok\n${'y'.repeat(257)}`, FALLBACK_LIMITS);
    expect(long.error).toBe('Line 2 is longer than 256 characters.');
  });

  it('checks a batch by count and by line number', () => {
    const entry = (line: number, password: string) => ({
      line,
      label: `Row ${String(line)}`,
      password,
    });
    expect(validateBatchEntries([], FALLBACK_LIMITS)).toMatch(/at least one/);
    expect(validateBatchEntries([entry(1, 'a')], FALLBACK_LIMITS)).toBeNull();
    const over = Array.from({ length: 51 }, (_, i) => entry(i + 1, 'a'));
    expect(validateBatchEntries(over, FALLBACK_LIMITS)).toMatch(/at most 50/);
    const message = validateBatchEntries(
      [entry(1, 'a'), entry(7, CANARY.repeat(60))],
      FALLBACK_LIMITS,
    );
    expect(message).toMatch(/line 7/);
    expect(message).not.toContain(CANARY);
  });
});

describe('batch input parsing', () => {
  it('lines: skips blanks, keeps spaces, handles CRLF and a byte-order mark', () => {
    const parsed = parseBatchInput('\uFEFFfirst\r\n\r\n  spaced  \nlast', 'lines');
    expect(parsed.entries.map((e) => e.password)).toEqual(['first', '  spaced  ', 'last']);
    expect(parsed.entries.map((e) => e.line)).toEqual([1, 3, 4]);
    expect(parsed.skipped).toBe(1);
  });

  it('csv: header lookup, quoting, embedded commas and newlines', () => {
    expect(parseCsv('a,"b ""q""",c\r\n1,2,3')).toEqual([
      ['a', 'b "q"', 'c'],
      ['1', '2', '3'],
    ]);
    const parsed = parseBatchInput('Label,Password\nalice,"p,1"\nbob,\n,"two\nlines"', 'csv');
    expect(parsed.error).toBeNull();
    expect(parsed.entries.map((e) => [e.label, e.password])).toEqual([
      ['alice', 'p,1'],
      ['Row 2', 'two\nlines'],
    ]);
    expect(parsed.skipped).toBe(1);
  });

  it('csv without a password column is an error that does not echo the header', () => {
    const parsed = parseBatchInput(`${CANARY}\nother`, 'csv');
    expect(parsed.entries).toEqual([]);
    expect(parsed.error).not.toContain(CANARY);
    expect(parseBatchInput('', 'csv').error).toMatch(/empty/);
  });
});

describe('friendlyError', () => {
  const http = (status: number, extra: ConstructorParameters<typeof ApiRequestError>[2] = {}) =>
    new ApiRequestError('http', 'Server text.', { status, ...extra });

  it('explains an unreachable backend and offers demo data', () => {
    const info = friendlyError(new ApiRequestError('network', 'Could not reach.'));
    expect(info).toMatchObject({ offline: true, retryable: true });
    expect(info.hints.join(' ')).toMatch(/dev\.ps1/);
  });

  it('rate limits and busy states carry a wait and are warnings', () => {
    expect(friendlyError(http(429, { retryAfter: 4 }))).toMatchObject({
      tone: 'warning',
      retryAfter: 4,
    });
    expect(friendlyError(http(503))).toMatchObject({ tone: 'warning', retryAfter: 2 });
  });

  it('validation errors list locations and are not retryable', () => {
    const info = friendlyError(
      http(422, {
        code: 'validation_error',
        details: [{ loc: ['body', 'items', 2, 'password'], type: 't', message: 'Too long' }],
      }),
    );
    expect(info.retryable).toBe(false);
    expect(info.issues).toEqual([{ field: 'items / item 3 / password', message: 'Too long' }]);
  });

  it('never leaks unexpected error text', () => {
    const info = friendlyError(new Error(`secret ${CANARY}`));
    expect(JSON.stringify(info)).not.toContain(CANARY);
    expect(friendlyError(http(500, { requestId: 'r1' })).hints[0]).toMatch(/r1/);
  });
});

const RECORD: AnalysisRecord = {
  id: 'r1',
  label: 'Row 1',
  length: 9,
  risk_score: 55,
  risk_level: 'high',
  strength_score: 1,
  strength_label: 'weak',
  guesses_log10: 4.2,
  estimated_bits: 14.4,
  policy_compliant: false,
  findings: ['common_password'],
  recommendations: ['lengthen'],
  reused: false,
  breach: null,
  reuse_datasets: null,
};

describe('reports', () => {
  it('neutralises spreadsheet formulas and quotes per RFC 4180', () => {
    expect(csvCell('=HYPERLINK("x")')).toBe(`"'=HYPERLINK(""x"")"`);
    expect(csvCell('+1')).toBe("'+1");
    expect(csvCell('-1')).toBe("'-1");
    expect(csvCell('@SUM')).toBe("'@SUM");
    expect(csvCell('a,b')).toBe('"a,b"');
    expect(csvCell(-5)).toBe('-5'); // numbers are not text
    expect(csvCell(true)).toBe('true');
    expect(csvCell(null)).toBe('');
  });

  it('a record-based report has a fixed, password-free column set and marks demo data', () => {
    const csv = recordsToCsv([RECORD], 'demo');
    expect(csv.split('\n')[0]).toBe(
      'index,label,length,risk_score,risk_level,strength_score,strength_label,guesses_log10,estimated_bits,policy_compliant,findings,recommendations,reused_in_batch,breach_check,reuse_datasets,data_source',
    );
    expect(csv.split('\n')[1]).toMatch(/,demo$/);
    const json = JSON.parse(
      buildReportJson({
        title: 'T',
        kind: 'batch',
        source: 'demo',
        generatedAt: new Date(0),
        records: [RECORD],
        includeRecommendations: false,
      }),
    ) as { report: Record<string, unknown>; results: Record<string, unknown>[] };
    expect(json.report).toMatchObject({ synthetic: true, sanitized: true, source: 'demo' });
    expect(json.results[0]).not.toHaveProperty('recommendations');
  });

  it('a hostile label cannot become a formula or break the row', () => {
    const csv = recordsToCsv([{ ...RECORD, label: '=cmd|\' /C calc\'!A0,"x"' }], 'live');
    const row = csv.split('\n')[1] ?? '';
    expect(row.startsWith('1,"\'=cmd')).toBe(true);
  });

  it('policy report CSV has one row per rule', () => {
    const csv = buildPolicyReportCsv({
      title: 'x',
      source: 'live',
      generatedAt: new Date(0),
      policy: {},
      result: {
        compliant: false,
        length: 3,
        violations: [],
        rules: [
          {
            rule: 'min_length',
            requirement: 'At least 12 characters',
            status: 'fail',
            required: 12,
            actual: 3,
            message: 'Too short',
          },
        ],
      },
    });
    expect(csv.trim().split('\n')).toHaveLength(2);
  });

  it('file names are restricted to safe characters, with the right extension and demo prefix', () => {
    expect(safeFilename('../../etc/passwd', 'json', 'live')).toBe('etc-passwd.json');
    expect(safeFilename('my report.csv', 'csv', 'live')).toBe('my-report.csv');
    expect(safeFilename('   ', 'json', 'live')).toBe('passaudit-report.json');
    expect(safeFilename('x', 'json', 'demo')).toBe('demo-x.json');
    expect(safeFilename('C:\\a\\b*?.json', 'json', 'live')).not.toMatch(/[\\/:*?]/);
  });

  it('summarises records consistently', () => {
    const stats = summarizeRecords([
      RECORD,
      {
        ...RECORD,
        id: 'r2',
        risk_score: 15,
        risk_level: 'low',
        policy_compliant: true,
        findings: [],
      },
    ]);
    expect(stats).toMatchObject({
      total: 2,
      averageRisk: 35,
      maxRisk: 55,
      compliant: 1,
      atRiskShare: 0.5,
    });
    expect(summarizeRecords([]).averageRisk).toBeNull();
  });
});

describe('policy parsing', () => {
  it('accepts partial policies and a {"policy": ...} wrapper, filling defaults', () => {
    const parsed = parsePolicyJson('{"min_length": 20}');
    expect(parsed).toEqual({ ok: true, policy: { ...DEFAULT_POLICY, min_length: 20 } });
    expect(parsePolicyJson('{"policy": {"min_digits": 2}}')).toMatchObject({ ok: true });
  });

  it('rejects bad JSON, unknown fields, wrong types and out-of-range values without quoting content', () => {
    for (const text of [
      'nope',
      '[]',
      '{"zzz": 1}',
      '{"min_length": "12"}',
      '{"min_length": -1}',
      '{"allow_whitespace": "yes"}',
      '{"max_length": 3}',
    ]) {
      const result = parsePolicyJson(text);
      expect(result.ok, text).toBe(false);
    }
    const unknown = parsePolicyJson(`{"${CANARY}": 1}`);
    expect(unknown.ok).toBe(false);
  });

  it('validates like the backend model and computes overrides', () => {
    expect(validatePolicy(DEFAULT_POLICY)).toEqual({});
    expect(
      validatePolicy({ ...DEFAULT_POLICY, min_length: 20, max_length: 10 }).max_length,
    ).toBeDefined();
    expect(
      validatePolicy({ ...DEFAULT_POLICY, max_sequence_length: 1 }).max_sequence_length,
    ).toBeDefined();
    expect(
      validatePolicy({ ...DEFAULT_POLICY, min_strength_score: 5 }).min_strength_score,
    ).toBeDefined();
    expect(validatePolicy({ ...DEFAULT_POLICY, min_length: Number.NaN }).min_length).toBeDefined();
    expect(policyOverrides({ ...DEFAULT_POLICY, min_length: 14 })).toEqual({ min_length: 14 });
  });
});

describe('useAsyncAction', () => {
  it('goes idle -> loading -> success and keeps only the result', async () => {
    const { result } = renderHook(() => useAsyncAction<string>());
    expect(result.current.state.status).toBe('idle');
    let value: string | undefined;
    await act(async () => {
      const pending = result.current.run(() => Promise.resolve('done'));
      value = await pending;
    });
    expect(value).toBe('done');
    expect(result.current.state).toEqual({ status: 'success', data: 'done' });
  });

  it('records failures', async () => {
    const { result } = renderHook(() => useAsyncAction<string>());
    const boom = new Error('boom');
    await act(async () => {
      await result.current.run(() => Promise.reject(boom));
    });
    expect(result.current.state).toEqual({ status: 'error', error: boom });
  });

  it('a stale slow response can never overwrite a newer one', async () => {
    const { result } = renderHook(() => useAsyncAction<string>());
    let releaseFirst: (() => void) | undefined;
    await act(async () => {
      void result.current.run(
        () =>
          new Promise<string>((resolve) => {
            releaseFirst = () => {
              resolve('first');
            };
          }),
      );
      await result.current.run(() => Promise.resolve('second'));
    });
    await act(async () => {
      releaseFirst?.();
      await Promise.resolve();
    });
    expect(result.current.state).toEqual({ status: 'success', data: 'second' });
  });

  it('aborts the request when cancelled or unmounted', async () => {
    const { result, unmount } = renderHook(() => useAsyncAction<string>());
    let signal: AbortSignal | undefined;
    await act(async () => {
      void result.current.run((s) => {
        signal = s;
        return new Promise<string>(() => undefined);
      });
      await Promise.resolve();
    });
    expect(signal?.aborted).toBe(false);
    act(() => {
      result.current.cancel();
    });
    expect(signal?.aborted).toBe(true);
    expect(result.current.state.status).toBe('idle');

    let second: AbortSignal | undefined;
    await act(async () => {
      void result.current.run((s) => {
        second = s;
        return new Promise<string>(() => undefined);
      });
      await Promise.resolve();
    });
    unmount();
    expect(second?.aborted).toBe(true);
  });
});
