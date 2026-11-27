import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import type { MockInstance } from 'vitest';

import App from './App.tsx';
import type { BatchRequest, BatchResponse, CapabilitiesResponse } from './api/types.ts';
import { demo } from './demo/demo.ts';
import { expectNoA11yViolations } from './test/a11y.ts';
import {
  NO_FEATURES,
  analysisWithExposure,
  batchResponseFor,
  capabilitiesWith,
  createFakeApi,
  errorResponse,
  json,
} from './test/fakeApi.ts';
import type { FakeApi } from './test/fakeApi.ts';
import { must } from './test/must.ts';

/**
 * Phase 8 in the UI: every external check is opt-in, off by default, never remembered, honestly
 * worded ("not found" is not "safe"; a failed lookup is "unchecked"), and the password still
 * appears nowhere but the request body.
 */

const CANARY = 'Zq9-canary-Secret-4471';
const ONLINE: CapabilitiesResponse = capabilitiesWith({
  external_lookups_enabled: true,
  breach: { local: true, online: true, online_host: 'range.example', protocol: 'k-anonymity' },
});
const WITH_REUSE: CapabilitiesResponse = capabilitiesWith({
  reuse_index: {
    available: true,
    datasets: ['hr-export', 'vpn'],
    authorization_reference: 'TICKET-9',
  },
});

let consoleSpies: MockInstance[];
let downloads: Blob[];

beforeEach(() => {
  window.localStorage.clear();
  window.sessionStorage.clear();
  downloads = [];
  consoleSpies = (['log', 'info', 'warn', 'error', 'debug'] as const).map((m) =>
    vi.spyOn(console, m).mockImplementation(() => undefined),
  );
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

function api(capabilities: CapabilitiesResponse | null): FakeApi {
  const fake = createFakeApi();
  fake.on('/capabilities', () =>
    capabilities ? json(capabilities) : errorResponse(404, 'not_found', 'Not found.'),
  );
  return fake;
}

function renderAt(path: string, fake: FakeApi) {
  const user = userEvent.setup();
  const view = render(
    <MemoryRouter initialEntries={[path]}>
      <App client={fake.client} />
    </MemoryRouter>,
  );
  return { user, ...view };
}

async function typePassword(user: ReturnType<typeof userEvent.setup>) {
  const field = (await screen.findAllByLabelText(/password to analyse/i)).find(
    (el): el is HTMLInputElement => el instanceof HTMLInputElement,
  );
  await user.type(must(field, 'password field'), CANARY);
}

const breachSelect = () => screen.findByRole('combobox', { name: /check against known breaches/i });

function bodyOf(fake: FakeApi): Record<string, unknown> {
  return must(fake.analysisCalls()[0], 'a request').body as {
    min_length: number;
    block_breached_passwords: boolean;
  };
}

function noLeak(fake: FakeApi): void {
  const stored = JSON.stringify(
    [window.localStorage, window.sessionStorage].map((s) => Object.entries(s)),
  );
  const logged = JSON.stringify(consoleSpies.flatMap((spy) => spy.mock.calls));
  expect(stored).not.toContain(CANARY);
  expect(logged).not.toContain(CANARY);
  expect(window.location.href).not.toContain(CANARY);
  for (const call of fake.calls) expect(call.url).not.toContain(CANARY);
}

describe('opt-in breach checks (Audit)', () => {
  it('is off by default: nothing external is requested, sent or shown', async () => {
    const fake = api(NO_FEATURES);
    const { user } = renderAt('/audit', fake);
    const select = await breachSelect();
    expect(select).toHaveValue('off');
    expect(within(select).getByRole('option', { name: /online/i })).toBeDisabled();
    expect(
      within(select).getByRole('option', { name: /not enabled on this server/i }),
    ).toBeInTheDocument();
    expect(screen.getByText(/Breach checks are not enabled on this server/)).toBeInTheDocument();

    await typePassword(user);
    await user.click(screen.getByRole('button', { name: 'Analyse password' }));
    await screen.findByText(/Analysis complete/);
    expect(bodyOf(fake)).not.toHaveProperty('exposure');
    expect(screen.queryByText('External checks')).toBeNull();
  });

  it('online: says exactly what leaves the machine, sends only the option, shows an honest result', async () => {
    const fake = api(ONLINE);
    fake.on('/audit', () =>
      json(
        analysisWithExposure({
          breach: { status: 'breached', source: 'online', count: 4242 },
          reuse: null,
        }),
      ),
    );
    const { user } = renderAt('/audit', fake);
    await user.selectOptions(await breachSelect(), 'online');
    const notice = screen.getByText('What leaves this machine').closest('[role="status"]');
    expect(notice).toHaveTextContent('first 5 characters');
    expect(notice).toHaveTextContent('range.example');
    expect(notice).toHaveTextContent('never leave this machine');

    await typePassword(user);
    await user.click(screen.getByRole('button', { name: 'Analyse password' }));
    await screen.findByText('Found in breaches');
    expect(bodyOf(fake)).toMatchObject({ exposure: { breach: 'online', reuse: false } });
    expect(screen.getByText(/seen at least 4,242 times/)).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'Download JSON' }));
    const text = await must(downloads.at(-1), 'a download').text();
    const report = JSON.parse(text) as {
      external_checks: { breach_check: string };
      results: { breach: string }[];
    };
    expect(report.external_checks.breach_check).toBe('online');
    expect(report.results[0]?.breach).toBe('breached');
    expect(text).not.toContain(CANARY);
    noLeak(fake);
  });

  it('the choice is never remembered: a fresh page starts at Off again', async () => {
    const fake = api(ONLINE);
    const first = renderAt('/audit', fake);
    await first.user.selectOptions(await breachSelect(), 'online');
    expect(Object.keys(window.localStorage).join()).not.toMatch(/breach|exposure|online/i);
    first.unmount();
    renderAt('/audit', api(ONLINE));
    expect(await breachSelect()).toHaveValue('off');
  });

  it('"not found" is never presented as "safe"', async () => {
    const fake = api(ONLINE);
    fake.on('/audit', () =>
      json(
        analysisWithExposure({
          breach: { status: 'clean', source: 'online', count: 0 },
          reuse: null,
        }),
      ),
    );
    const { user } = renderAt('/audit', fake);
    await user.selectOptions(await breachSelect(), 'online');
    await typePassword(user);
    await user.click(screen.getByRole('button', { name: 'Analyse password' }));
    expect(await screen.findByText('Not found')).toBeInTheDocument();
    expect(screen.getByText(/not a guarantee/i)).toBeInTheDocument();
    expect(screen.queryByText(/\bsafe\b/i)).toBeNull();
  });

  it('a lookup that did not complete is "unchecked", never clean', async () => {
    const fake = api(ONLINE);
    fake.on('/audit', () =>
      json(
        analysisWithExposure({ breach: { status: 'unavailable', source: 'online', count: null } }),
      ),
    );
    const { user } = renderAt('/audit', fake);
    await user.selectOptions(await breachSelect(), 'online');
    await typePassword(user);
    await user.click(screen.getByRole('button', { name: 'Analyse password' }));
    expect(await screen.findByText('Unchecked')).toBeInTheDocument();
    expect(screen.getByText(/says nothing/i)).toBeInTheDocument();
    expect(screen.queryByText('Not found')).toBeNull();
    await user.click(screen.getByRole('radio', { name: 'CSV' }));
    await user.click(screen.getByRole('button', { name: 'Download CSV' }));
    const csv = await must(downloads.at(-1), 'a download').text();
    expect(csv.split('\n')[1]).toContain('unavailable');
  });

  it('a server that refuses online checks is explained, and nothing was sent', async () => {
    const fake = api(ONLINE);
    fake.on('/audit', () =>
      errorResponse(
        403,
        'external_lookups_disabled',
        'Online breach checks are disabled on this server.',
      ),
    );
    const { user } = renderAt('/audit', fake);
    await user.selectOptions(await breachSelect(), 'online');
    await typePassword(user);
    await user.click(screen.getByRole('button', { name: 'Analyse password' }));
    expect(await screen.findByText('Online checks are turned off')).toBeInTheDocument();
    expect(screen.getByText('Nothing was sent anywhere.')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Retry' })).toBeNull();
    noLeak(fake);
  });

  it('an older backend (no /capabilities) simply does not offer the feature', async () => {
    const fake = api(null);
    const { user } = renderAt('/audit', fake);
    await screen.findByRole('button', { name: 'Analyse password' });
    expect(screen.queryByText('Optional external checks')).toBeNull();
    await typePassword(user);
    await user.click(screen.getByRole('button', { name: 'Analyse password' }));
    expect(await screen.findByText(/Analysis complete/)).toBeInTheDocument();
    expect(bodyOf(fake)).not.toHaveProperty('exposure');
  });

  it('has no accessibility violations with the options and a result on screen', async () => {
    const fake = api(WITH_REUSE);
    fake.on('/audit', () =>
      json(
        analysisWithExposure({
          breach: { status: 'breached', source: 'local', count: 3 },
          reuse: { status: 'reused', sources: ['vpn'] },
        }),
      ),
    );
    const { user, container } = renderAt('/audit', fake);
    await user.selectOptions(await breachSelect(), 'off');
    await user.click(
      await screen.findByRole('checkbox', { name: /reuse in the authorised datasets/i }),
    );
    await typePassword(user);
    await user.click(screen.getByRole('button', { name: 'Analyse password' }));
    await screen.findByText('Reuse check (authorised datasets)');
    await expectNoA11yViolations(container, { page: true });
  });
});

describe('batch: reuse dataset check', () => {
  it('sends the option, shows dataset badges and summary, exports names only', async () => {
    const fake = api(WITH_REUSE);
    fake.on('/audit/batch', (call) => {
      const request = call.body as BatchRequest;
      const base: BatchResponse = batchResponseFor(request);
      return json({
        ...base,
        summary: { ...base.summary, reused_in_datasets: 1, breached: 0 },
        results: base.results.map((r, i) => ({
          ...r,
          breach: null,
          reuse_datasets: i === 0 ? ['hr-export'] : [],
        })),
      });
    });
    const { user } = renderAt('/batch', fake);
    await user.click(
      await screen.findByRole('checkbox', { name: /reuse in the authorised datasets/i }),
    );
    expect(screen.getByText(/hr-export, vpn/)).toBeInTheDocument();
    expect(screen.getByText(/Authorisation: TICKET-9/)).toBeInTheDocument();
    await user.click(await screen.findByRole('textbox', { name: /^Passwords/ }));
    await user.paste(`${CANARY}\nsecond-Secret-77`);
    await user.click(screen.getByRole('button', { name: 'Audit 2 passwords' }));
    await screen.findByText(/Audit complete/);

    expect(bodyOf(fake)).toMatchObject({ exposure: { breach: 'off', reuse: true } });
    expect(screen.getByText('In datasets')).toBeInTheDocument();
    expect(screen.getByRole('group', { name: 'Reused in datasets' })).toHaveTextContent('1');

    await user.click(screen.getByRole('button', { name: 'Download JSON' }));
    const report = JSON.parse(await must(downloads.at(-1), 'a download').text()) as {
      external_checks: { reuse_datasets: string[] };
      results: { reuse_datasets: string[] }[];
    };
    expect(report.external_checks.reuse_datasets).toEqual(['hr-export', 'vpn']);
    expect(report.results[0]?.reuse_datasets).toEqual(['hr-export']);
    expect(JSON.stringify(report)).not.toContain(CANARY);
    noLeak(fake);
  });

  it('without the option the request has no exposure field', async () => {
    const fake = api(WITH_REUSE);
    const { user } = renderAt('/batch', fake);
    await user.click(await screen.findByRole('textbox', { name: /^Passwords/ }));
    await user.paste(`${CANARY}\nother-Secret-8`);
    await user.click(screen.getByRole('button', { name: 'Audit 2 passwords' }));
    await screen.findByText(/Audit complete/);
    expect(bodyOf(fake)).not.toHaveProperty('exposure');
  });
});

describe('server policy profiles and unchecked rules', () => {
  it('applies a server profile to the editor and remembers the rules only', async () => {
    const fake = api(NO_FEATURES);
    const { user } = renderAt('/policies', fake);
    await user.click(await screen.findByRole('button', { name: 'Use profile: High security' }));
    expect(await screen.findByLabelText('Minimum length')).toHaveValue('16');
    const stored = JSON.parse(window.localStorage.getItem('passaudit.policy') ?? '{}') as Record<
      string,
      unknown
    >;
    expect(stored.min_length).toBe(16);
    expect(stored.block_breached_passwords).toBe(true);
    expect(screen.getByRole('switch', { name: /reject breached passwords/i })).toBeChecked();
  });

  it('a profile that cannot be loaded is reported, not fatal', async () => {
    const fake = api(NO_FEATURES);
    fake.on('/policy/profiles/high-security', () =>
      errorResponse(422, 'unknown_profile', 'Unknown policy profile.'),
    );
    const { user } = renderAt('/policies', fake);
    await user.click(await screen.findByRole('button', { name: 'Use profile: High security' }));
    expect(await screen.findByText('Could not load the profile')).toBeInTheDocument();
    expect(screen.getByLabelText('Minimum length')).toHaveValue('12');
  });

  it('rules that need a breach check show as "Not checked", never as passed', async () => {
    const fake = api(NO_FEATURES);
    fake.on('/policy/validate', () =>
      json({
        compliant: true,
        length: 18,
        violations: [],
        rules: [
          {
            rule: 'min_length',
            requirement: 'At least 12 characters',
            status: 'pass',
            required: null,
            actual: null,
            message: null,
          },
          {
            rule: 'block_breached_passwords',
            requirement: 'Not found in known data breaches',
            status: 'unchecked',
            required: null,
            actual: null,
            message: 'No breach check was run (it is opt-in); this rule was not evaluated.',
          },
        ],
      }),
    );
    const { user } = renderAt('/policies', fake);
    const field = must(
      (await screen.findAllByLabelText(/password to check/i)).find(
        (el): el is HTMLInputElement => el instanceof HTMLInputElement,
      ),
      'password field',
    );
    await user.type(field, CANARY);
    await user.click(screen.getByRole('button', { name: 'Check password' }));
    const table = within(await screen.findByRole('region', { name: 'Rule results' })).getByRole(
      'table',
    );
    expect(within(table).getByText('Not checked')).toBeInTheDocument();
    expect(within(table).getAllByText('Pass')).toHaveLength(1);
    expect(screen.getByText(/1 rule was not checked/)).toBeInTheDocument();
  });
});

describe('settings', () => {
  it('shows what optional features the server has', async () => {
    renderAt(
      '/settings',
      api(capabilitiesWith({ ...ONLINE, reuse_index: WITH_REUSE.reuse_index })),
    );
    expect(
      await screen.findByText(/Enabled \(range\.example\) - sends a 5-character hash prefix/),
    ).toBeInTheDocument();
    expect(screen.getByText('hr-export, vpn')).toBeInTheDocument();
    expect(screen.getByText(/278 words, 182 names/)).toBeInTheDocument();
  });

  it('says plainly that nothing is sent when online checks are off', async () => {
    renderAt('/settings', api(NO_FEATURES));
    expect(await screen.findByText('Off - nothing is sent anywhere')).toBeInTheDocument();
  });
});

describe('demo data stays unaffected', () => {
  it('demo records carry no external-check claims', () => {
    const batch = demo.batch.results;
    expect(batch.every((r) => (r as { breach?: unknown }).breach === undefined)).toBe(true);
  });
});
