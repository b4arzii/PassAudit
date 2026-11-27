import { act, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import type { MockInstance } from 'vitest';

import App from './App.tsx';
import { demo } from './demo/demo.ts';
import { expectNoA11yViolations } from './test/a11y.ts';
import { createFakeApi, errorResponse, json } from './test/fakeApi.ts';
import type { FakeApi } from './test/fakeApi.ts';
import { must } from './test/must.ts';

/**
 * End-to-end (UI -> typed client -> fake API) workflows, with the privacy guarantees checked
 * after each one: no password in storage, URLs, console output, the DOM after submission,
 * session history or exports.
 */

const CANARY = 'Zq9-canary-Secret-4471';
const PERSONAL = 'Wilhelmina-Q-Fox';

let api: FakeApi;
let consoleSpies: MockInstance[];
let downloads: Blob[];

beforeEach(() => {
  window.localStorage.clear();
  window.sessionStorage.clear();
  api = createFakeApi();
  downloads = [];
  consoleSpies = (['log', 'info', 'warn', 'error', 'debug'] as const).map((method) =>
    vi.spyOn(console, method).mockImplementation(() => undefined),
  );
  // jsdom has no object URLs: capture what would be downloaded.
  URL.createObjectURL = vi.fn((blob: Blob) => {
    downloads.push(blob);
    return 'blob:test';
  });
  URL.revokeObjectURL = vi.fn();
  vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => undefined);
});
afterEach(() => {
  vi.restoreAllMocks();
});

function renderAt(path: string, fake: FakeApi = api) {
  const user = userEvent.setup();
  const view = render(
    <MemoryRouter initialEntries={[path]}>
      <App client={fake.client} />
    </MemoryRouter>,
  );
  return { user, ...view };
}

/** Everything in a Storage object, as one string. */
function dump(storage: Storage): string {
  return Object.keys(storage)
    .map((key) => `${key}=${storage.getItem(key) ?? ''}`)
    .join(' | ');
}

function expectNoLeak(...secrets: string[]): void {
  checkLeaks(secrets, true);
}
/** For states where the form legitimately still holds what the user typed (after an error). */
function expectNoLeakOutsideForm(...secrets: string[]): void {
  checkLeaks(secrets, false);
}
function checkLeaks(secrets: string[], dom: boolean): void {
  const stored = dump(window.localStorage) + dump(window.sessionStorage);
  const logged = JSON.stringify(consoleSpies.flatMap((spy) => spy.mock.calls));
  const place = window.location.href;
  for (const secret of secrets) {
    expect(stored, 'storage').not.toContain(secret);
    expect(logged, 'console').not.toContain(secret);
    expect(place, 'URL').not.toContain(secret);
    // Text the user typed into a visible form field (personal details) legitimately stays there.
    if (secret === PERSONAL || !dom) continue;
    expect(document.body.textContent, 'page text').not.toContain(secret);
    expect(document.documentElement.innerHTML, 'markup').not.toContain(secret);
  }
  for (const call of api.calls) {
    expect(call.url, 'request URL').not.toContain(secret_(secrets));
    expect(call.url).not.toContain('?');
  }
}
function secret_(secrets: string[]): string {
  return secrets[0] ?? '';
}

async function passwordField(): Promise<HTMLInputElement> {
  const fields = await screen.findAllByLabelText(/password to (analyse|check)/i);
  return must(
    fields.find((el): el is HTMLInputElement => el instanceof HTMLInputElement),
    'password input',
  );
}

async function exportText(): Promise<string> {
  expect(downloads.length).toBeGreaterThan(0);
  return must(downloads.at(-1), 'a download').text();
}

describe('Audit workflow', () => {
  it('sends the password only in a POST body, shows the result, and leaves no trace of it', async () => {
    const { user } = renderAt('/audit');
    await user.type(await passwordField(), CANARY);
    await user.type(screen.getByLabelText(/personal details to check against/i), PERSONAL);
    await user.click(screen.getByRole('button', { name: 'Analyse password' }));

    // Result appears and takes focus.
    const heading = await screen.findByRole('heading', { level: 2, name: 'Result' });
    await waitFor(() => {
      expect(heading).toHaveFocus();
    });
    expect(screen.getByText(/Analysis complete\. Risk/)).toBeInTheDocument();
    expect(screen.getByRole('heading', { level: 3, name: 'Strength' })).toBeInTheDocument();

    // Exactly one analysis request: a POST with a JSON body and nothing in the URL.
    const [call] = api.analysisCalls();
    expect(api.analysisCalls()).toHaveLength(1);
    expect(call?.method).toBe('POST');
    expect(call?.url).toBe('/api/v1/audit');
    expect(call?.headers['content-type']).toBe('application/json');
    expect(call?.init.credentials).toBe('omit');
    expect(call?.init.cache).toBe('no-store');
    expect(call?.init.referrerPolicy).toBe('no-referrer');
    expect(call?.body).toMatchObject({
      password: CANARY,
      context: { usage: 'general', personal_info: [PERSONAL], reused_elsewhere: false },
    });
    // The full policy is sent, so what the UI shows is what the server applies.
    expect((call?.body as { policy: { min_length: number } }).policy.min_length).toBe(12);

    // The form was cleared, and nothing leaked anywhere.
    expect(await passwordField()).toHaveValue('');
    expectNoLeak(CANARY, PERSONAL);
  });

  it('shows loading state while waiting, and ignores a second submit', async () => {
    let release: (() => void) | undefined;
    api.on(
      '/audit',
      () =>
        new Promise((resolve) => {
          release = () => {
            resolve(json(demo.analyses[0]?.analysis));
          };
        }),
    );
    const { user } = renderAt('/audit');
    await user.type(await passwordField(), CANARY);
    await user.click(screen.getByRole('button', { name: 'Analyse password' }));

    const busy = await screen.findByRole('button', { name: 'Analysing...' });
    expect(busy).toHaveAttribute('aria-busy', 'true');
    expect(screen.getByText('Analysing locally...')).toBeInTheDocument();
    await user.click(busy);
    await user.keyboard('{Enter}');
    expect(api.analysisCalls()).toHaveLength(1);

    await act(async () => {
      release?.();
      await Promise.resolve();
    });
    expect(await screen.findByText(/Analysis complete/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Analyse password' })).not.toHaveAttribute(
      'aria-busy',
    );
  });

  it('validates before sending: empty and over-long passwords never reach the network', async () => {
    const { user } = renderAt('/audit');
    await user.click(await screen.findByRole('button', { name: 'Analyse password' }));
    expect(screen.getByText('Enter a password to analyse.')).toBeInTheDocument();
    expect(await passwordField()).toHaveFocus();

    await user.click(await passwordField());
    await user.paste('x'.repeat(1025));
    await user.click(screen.getByRole('button', { name: 'Analyse password' }));
    expect(screen.getByText(/1025 characters long; the limit is 1024/)).toBeInTheDocument();
    expect(api.analysisCalls()).toHaveLength(0);
  });

  it('reveal toggle shows the text only on request', async () => {
    const { user } = renderAt('/audit');
    const field = await passwordField();
    await user.type(field, CANARY);
    expect(field).toHaveAttribute('type', 'password');
    await user.click(screen.getByRole('button', { name: 'Show password' }));
    expect(field).toHaveAttribute('type', 'text');
  });

  it('keeps the password in the field only when the user opted in (memory only)', async () => {
    window.localStorage.setItem('passaudit.keep-password', 'true');
    const { user } = renderAt('/audit');
    await user.type(await passwordField(), CANARY);
    await user.click(screen.getByRole('button', { name: 'Analyse password' }));
    await screen.findByText(/Analysis complete/);
    expect(await passwordField()).toHaveValue(CANARY);
    // Even then it is not stored anywhere.
    expect(dump(window.localStorage)).not.toContain(CANARY);
    expect(window.location.href).not.toContain(CANARY);
  });

  it('rate limiting: warns, counts down, and the retry re-sends from memory', async () => {
    let attempts = 0;
    api.on('/audit', () => {
      attempts += 1;
      return attempts === 1
        ? errorResponse(429, 'rate_limited', 'Too many requests.', {
            headers: { 'Retry-After': '1' },
          })
        : json(demo.analyses[0]?.analysis);
    });
    const { user } = renderAt('/audit');
    await user.type(await passwordField(), CANARY);
    await user.click(screen.getByRole('button', { name: 'Analyse password' }));

    expect(await screen.findByText('Too many requests')).toBeInTheDocument();
    expect(screen.getByText('req-test-0001')).toBeInTheDocument();
    // The input survives an error so a retry is possible.
    expect(await passwordField()).toHaveValue(CANARY);
    const retry = screen.getByRole('button', { name: /Retry in 1s/ });
    expect(retry).toBeDisabled();
    const ready = await screen.findByRole('button', { name: 'Retry' }, { timeout: 3000 });
    await userEvent.setup().click(ready);

    expect(await screen.findByText(/Analysis complete/)).toBeInTheDocument();
    expect(api.analysisCalls()).toHaveLength(2);
    expect(api.analysisCalls()[1]?.body).toMatchObject({ password: CANARY });
    expectNoLeak(CANARY);
  });

  it('shows field-level validation problems from the server without echoing input', async () => {
    api.on('/audit', () =>
      errorResponse(422, 'validation_error', 'The request body failed validation.', {
        details: [
          {
            loc: ['body', 'policy', 'min_length'],
            type: 'greater_than_equal',
            message: 'Input should be greater than or equal to 0',
          },
        ],
      }),
    );
    const { user } = renderAt('/audit');
    await user.type(await passwordField(), CANARY);
    await user.click(screen.getByRole('button', { name: 'Analyse password' }));
    await screen.findByText('The request was not valid');
    // (The toast region is also an, empty, assertive live region.)
    const alert = must(
      screen.getAllByRole('alert').find((el) => el.textContent),
      'an alert with text',
    );
    expect(within(alert).getByText('The request was not valid')).toBeInTheDocument();
    expect(within(alert).getByText(/policy \/ min length:/)).toBeInTheDocument();
    expect(alert.textContent).not.toContain(CANARY);
    expectNoLeakOutsideForm(CANARY);
    // Validation errors are not retryable as-is.
    expect(within(alert).queryByRole('button', { name: /Retry/ })).toBeNull();
  });

  it('backend down: explains how to start it, offers demo data that is clearly labelled', async () => {
    const down = createFakeApi({
      '/health': () => {
        throw new TypeError('Failed to fetch');
      },
      '/limits': () => {
        throw new TypeError('Failed to fetch');
      },
      '/audit': () => {
        throw new TypeError('Failed to fetch');
      },
    });
    const { user } = renderAt('/audit', down);
    expect(await screen.findByText('The PassAudit service is not reachable')).toBeInTheDocument();
    await user.type(await passwordField(), CANARY);
    await user.click(screen.getByRole('button', { name: 'Analyse password' }));
    expect(await screen.findByText("Can't reach the PassAudit service")).toBeInTheDocument();
    expect(await passwordField()).toHaveValue(CANARY); // not lost

    await user.click(screen.getByRole('button', { name: 'Preview with demo data' }));
    const banner = await screen.findByText(/You are viewing/);
    expect(banner.closest('[data-demo-banner]')).not.toBeNull();

    // Demo exports say so, in the file and in the name.
    await user.click(screen.getByRole('button', { name: 'Download JSON' }));
    const report = JSON.parse(await exportText()) as {
      report: { source: string; synthetic: boolean };
    };
    expect(report.report.source).toBe('demo');
    expect(report.report.synthetic).toBe(true);
    expectNoLeakOutsideForm(CANARY); // the form still holds the text after a failed request
  });

  it('export is sanitised: scores and advice only, never the password or personal details', async () => {
    const { user } = renderAt('/audit');
    await user.type(await passwordField(), CANARY);
    await user.type(screen.getByLabelText(/personal details to check against/i), PERSONAL);
    await user.click(screen.getByRole('button', { name: 'Analyse password' }));
    await screen.findByText(/Analysis complete/);

    await user.click(screen.getByRole('checkbox', { name: 'Include the full analysis' }));
    await user.click(screen.getByRole('button', { name: 'Download JSON' }));
    const json = await exportText();
    expect(json).not.toContain(CANARY);
    expect(json).not.toContain(PERSONAL);
    const parsed = JSON.parse(json) as { report: { sanitized: boolean; source: string } };
    expect(parsed.report).toMatchObject({ sanitized: true, source: 'live' });

    await user.click(screen.getByRole('radio', { name: 'CSV' }));
    await user.click(screen.getByRole('button', { name: 'Download CSV' }));
    const csv = await exportText();
    expect(csv.split('\n')[0]).toContain('risk_score');
    expect(csv).not.toContain(CANARY);
    expect(csv).toContain('live');
    expectNoLeak(CANARY, PERSONAL);
  });

  it('clearing the form removes the result and the typed values', async () => {
    const { user } = renderAt('/audit');
    await user.type(await passwordField(), CANARY);
    await user.type(screen.getByLabelText(/personal details to check against/i), PERSONAL);
    await user.click(screen.getByRole('button', { name: 'Clear form and result' }));
    expect(await passwordField()).toHaveValue('');
    expect(screen.getByLabelText(/personal details to check against/i)).toHaveValue('');
  });

  it('has no accessibility violations with a result on screen', async () => {
    const { user, container } = renderAt('/audit');
    await user.type(await passwordField(), CANARY);
    await user.click(screen.getByRole('button', { name: 'Analyse password' }));
    await screen.findByText(/Analysis complete/);
    await expectNoA11yViolations(container, { page: true });
  });
});

describe('Batch workflow', () => {
  const LINES = [CANARY, 'Another-Secret-8812', CANARY, '', 'third-Secret-1'].join('\n');

  async function pasteAndSubmit(user: ReturnType<typeof userEvent.setup>, text = LINES) {
    const box = await screen.findByRole('textbox', { name: /^Passwords/ });
    await user.click(box);
    await user.paste(text);
    await user.click(screen.getByRole('button', { name: /^Audit \d+ passwords?$/ }));
  }

  it('audits a pasted list, flags reuse, shows a sortable table and clears the input', async () => {
    const { user } = renderAt('/batch');
    await user.click(await screen.findByRole('textbox', { name: /^Passwords/ }));
    await user.paste(LINES);
    expect(screen.getByText(/4 passwords detected \(1 blank line skipped\)/)).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Audit 4 passwords' }));

    await screen.findByText('Audit complete: 4 passwords analysed.');
    const [call] = api.analysisCalls();
    expect(call?.url).toBe('/api/v1/audit/batch');
    const body = call?.body as { items: { id: string; password: string }[]; detail: string };
    expect(body.detail).toBe('full');
    expect(body.items.map((i) => i.id)).toEqual(['Row 1', 'Row 2', 'Row 3', 'Row 4']);
    expect(body.items[0]?.password).toBe(CANARY);

    const table = within(screen.getByRole('region', { name: 'Audit results' })).getByRole('table');
    expect(within(table).getAllByRole('row')).toHaveLength(5);
    expect(within(table).getAllByText('Reused')).toHaveLength(2);
    expect(screen.getByRole('textbox', { name: /^Passwords/ })).toHaveValue('');
    expectNoLeak(CANARY, 'Another-Secret-8812', 'third-Secret-1');
  });

  it('opens a full per-password detail view and exports without passwords', async () => {
    const { user } = renderAt('/batch');
    await pasteAndSubmit(user);
    await screen.findByText(/Audit complete/);

    await user.click(
      must(screen.getAllByRole('button', { name: /Open details for Row/ })[0], 'a result row'),
    );
    const dialog = await screen.findByRole('dialog');
    expect(within(dialog).getByRole('heading', { level: 3, name: 'Strength' })).toBeInTheDocument();
    await user.click(within(dialog).getByRole('button', { name: 'Close dialog' }));

    await user.click(screen.getByRole('button', { name: 'Download JSON' }));
    const text = await exportText();
    for (const secret of [CANARY, 'Another-Secret-8812', 'third-Secret-1'])
      expect(text).not.toContain(secret);
    const parsed = JSON.parse(text) as { results: unknown[]; summary: { analyzed: number } };
    expect(parsed.results).toHaveLength(4);
    expect(parsed.summary.analyzed).toBe(4);
    expectNoLeak(CANARY, 'Another-Secret-8812', 'third-Secret-1');
  });

  it('rejects oversize and empty input before sending, naming lines never content', async () => {
    const { user } = renderAt('/batch');
    await user.click(await screen.findByRole('button', { name: 'Audit passwords' }));
    expect(screen.getByText('Add at least one password.')).toBeInTheDocument();

    await user.click(screen.getByRole('textbox', { name: /^Passwords/ }));
    await user.paste(Array.from({ length: 51 }, (_, i) => `pw-${String(i)}-secret`).join('\n'));
    await user.click(screen.getByRole('button', { name: 'Audit 51 passwords' }));
    expect(screen.getByText(/51 passwords; the service accepts at most 50/)).toBeInTheDocument();
    expect(api.analysisCalls()).toHaveLength(0);
  });

  it('CSV input: needs a password column, uses the label column, and never echoes the header', async () => {
    const { user } = renderAt('/batch');
    await user.click(await screen.findByRole('radio', { name: 'CSV' }));
    await user.click(screen.getByRole('textbox', { name: /^Passwords/ }));
    await user.paste(`${CANARY}\nsecond-secret`);
    await user.click(screen.getByRole('button', { name: 'Audit passwords' }));
    const message = screen.getByText('The CSV needs a "password" column in its header row.');
    expect(message.textContent).not.toContain(CANARY);
    expect(api.analysisCalls()).toHaveLength(0);

    await user.clear(screen.getByRole('textbox', { name: /^Passwords/ }));
    await user.click(screen.getByRole('textbox', { name: /^Passwords/ }));
    await user.paste(`label,password\nalice,${CANARY}\nbob,"with,comma"`);
    await user.click(screen.getByRole('button', { name: 'Audit 2 passwords' }));
    await screen.findByText(/Audit complete/);
    expect(
      (api.analysisCalls()[0]?.body as { items: { id: string }[] }).items.map((i) => i.id),
    ).toEqual(['alice', 'bob']);
  });

  it('a password file is read in the browser, never displayed, and cleared after the audit', async () => {
    const { user } = renderAt('/batch');
    await user.click(await screen.findByRole('radio', { name: 'Upload file' }));
    const file = new File([`${CANARY}\nother-secret-22\n`], 'list.txt', { type: 'text/plain' });
    await user.upload(screen.getByLabelText('Choose a .txt or .csv file'), file);
    expect(await screen.findByText(/2 passwords ready/)).toBeInTheDocument();
    expect(document.body.textContent).not.toContain(CANARY);

    await user.click(screen.getByRole('button', { name: 'Audit 2 passwords' }));
    await screen.findByText(/Audit complete/);
    expect(api.analysisCalls()[0]?.rawBody).toContain(CANARY);
    // The loaded entries are gone, so a second click has nothing to send.
    expect(screen.getByRole('button', { name: 'Audit passwords' })).toBeInTheDocument();
    expectNoLeak(CANARY, 'other-secret-22');
  });

  it('server size rejection is explained (413) and keeps the list for another try', async () => {
    api.on('/audit/batch', () =>
      errorResponse(413, 'payload_too_large', 'The request body is too large.'),
    );
    const { user } = renderAt('/batch');
    await pasteAndSubmit(user);
    expect(await screen.findByText('The request is too large')).toBeInTheDocument();
    expect(screen.getByRole('textbox', { name: /^Passwords/ })).not.toHaveValue('');
  });

  it('has no accessibility violations with results on screen', async () => {
    const { user, container } = renderAt('/batch');
    await pasteAndSubmit(user);
    await screen.findByText(/Audit complete/);
    await expectNoA11yViolations(container, { page: true });
  });
});

describe('Policy workflow', () => {
  it('edits the policy, remembers rules only, and applies it to the check request', async () => {
    const { user } = renderAt('/policies');
    const minLength = await screen.findByLabelText('Minimum length');
    await user.clear(minLength);
    await user.type(minLength, '20');
    const stored = JSON.parse(window.localStorage.getItem('passaudit.policy') ?? '{}') as {
      min_length: number;
    };
    expect(stored.min_length).toBe(20);

    await user.type(await passwordField(), CANARY);
    await user.click(screen.getByRole('button', { name: 'Check password' }));
    await screen.findByRole('region', { name: 'Rule results' });

    const [call] = api.analysisCalls();
    expect(call?.url).toBe('/api/v1/policy/validate');
    expect((call?.body as { policy: { min_length: number } }).policy.min_length).toBe(20);
    expect(await passwordField()).toHaveValue('');
    expectNoLeak(CANARY);
  });

  it('keeps the last valid policy while a field is invalid, and says what to fix', async () => {
    const { user } = renderAt('/policies');
    const minLength = await screen.findByLabelText('Minimum length');
    await user.clear(minLength);
    await user.type(minLength, '16');
    await user.clear(minLength);
    await user.type(minLength, 'abc');
    expect(screen.getByText('Enter a whole number from 0 to 1024.')).toBeInTheDocument();
    expect(minLength).toHaveAttribute('aria-invalid', 'true');
    const stored = JSON.parse(window.localStorage.getItem('passaudit.policy') ?? '{}') as {
      min_length: number;
    };
    expect(stored.min_length).toBe(16);
  });

  it('presets, reset and import', async () => {
    const { user } = renderAt('/policies');
    await user.click(await screen.findByRole('button', { name: 'Use preset: Strict' }));
    expect(screen.getByLabelText('Minimum length')).toHaveValue('16');
    await user.click(screen.getByRole('button', { name: 'Reset to default' }));
    expect(screen.getByLabelText('Minimum length')).toHaveValue('12');

    await user.click(screen.getByText('Import a policy from a JSON file'));
    await user.upload(
      screen.getByLabelText('Choose a policy .json file'),
      new File([`{"${CANARY}": 1}`], 'p.json', { type: 'application/json' }),
    );
    const problem = await screen.findByText(/Unknown policy field/);
    expect(screen.getByLabelText('Minimum length')).toHaveValue('12');
    expect(problem).toBeInTheDocument();

    await user.upload(
      screen.getByLabelText('Choose a policy .json file'),
      new File(['{"min_length": 18}'], 'p.json', { type: 'application/json' }),
    );
    await waitFor(() => {
      expect(screen.getByLabelText('Minimum length')).toHaveValue('18');
    });
  });

  it('shows pass and fail per rule and exports the check without the password', async () => {
    const { user } = renderAt('/policies');
    await user.type(await passwordField(), CANARY);
    await user.click(screen.getByRole('button', { name: 'Check password' }));
    const table = await screen.findByRole('region', { name: 'Rule results' });
    expect(
      within(table).getAllByText('Pass').length + within(table).getAllByText('Fail').length,
    ).toBe(demo.policyCheck.result.rules.length);
    await user.click(screen.getByRole('button', { name: 'Download JSON' }));
    const text = await exportText();
    expect(text).not.toContain(CANARY);
    expect(JSON.parse(text)).toMatchObject({ report: { type: 'policy_check', sanitized: true } });
    expectNoLeak(CANARY);
  });

  it('has no accessibility violations', async () => {
    const { user, container } = renderAt('/policies');
    await user.type(await passwordField(), CANARY);
    await user.click(screen.getByRole('button', { name: 'Check password' }));
    await screen.findByRole('region', { name: 'Rule results' });
    await expectNoA11yViolations(container, { page: true });
  });
});

describe('Session, overview and storage', () => {
  it('the overview summarises results held in memory and can clear them', async () => {
    const { user } = renderAt('/audit');
    await user.type(await passwordField(), CANARY);
    await user.click(screen.getByRole('button', { name: 'Analyse password' }));
    await screen.findByText(/Analysis complete/);

    await user.click(
      within(screen.getByRole('navigation', { name: 'Primary' })).getByRole('link', {
        name: 'Overview',
      }),
    );
    expect(await screen.findByText('Summarising 1 password.')).toBeInTheDocument();
    expect(screen.queryByText(/You are viewing/)).toBeNull();
    await user.click(screen.getByRole('button', { name: 'Clear session results' }));
    expect(await screen.findByText('Nothing audited yet')).toBeInTheDocument();
    expectNoLeak(CANARY);
  });

  it('demo data on the overview is opt-in and labelled', async () => {
    const { user } = renderAt('/');
    await user.click(await screen.findByRole('button', { name: 'Preview with demo data' }));
    expect(await screen.findByText(/You are viewing/)).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Hide demo data' }));
    expect(await screen.findByText('Nothing audited yet')).toBeInTheDocument();
  });

  it('only preferences and policy rules are ever persisted', async () => {
    const { user } = renderAt('/audit');
    await user.type(await passwordField(), CANARY);
    await user.click(screen.getByRole('button', { name: 'Analyse password' }));
    await screen.findByText(/Analysis complete/);
    const allowed = new Set([
      'passaudit.theme',
      'passaudit.sidebar-collapsed',
      'passaudit.policy',
      'passaudit.demo-mode',
      'passaudit.keep-password',
    ]);
    for (const key of Object.keys(window.localStorage)) expect(allowed.has(key), key).toBe(true);
    expect(window.sessionStorage.length).toBe(0);
  });

  it('every page has no violations with the providers mounted', async () => {
    for (const path of ['/', '/audit', '/batch', '/policies', '/settings']) {
      const { container, unmount } = renderAt(path);
      await screen.findAllByRole('heading', { level: 1 });
      await expectNoA11yViolations(container, { page: true });
      unmount();
    }
  });

  it('the header shows the service connection and settings show its limits', async () => {
    renderAt('/settings');
    expect(await screen.findByText('Service connected')).toBeInTheDocument();
    expect(screen.getByText('9.9.9-test')).toBeInTheDocument();
  });
});
