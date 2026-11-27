import { Monitor, Moon, RefreshCw, Sun } from 'lucide-react';

import {
  Badge,
  Button,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  PageHeader,
  SegmentedControl,
  Switch,
} from '../components/ui/index.ts';
import { useApiStatus } from '../state/api.ts';
import { usePreferences } from '../state/preferences.ts';
import { useSession } from '../state/session.ts';
import { useTheme } from '../theme/useTheme.ts';
import type { ThemePreference } from '../theme/theme.ts';

const THEME_OPTIONS = [
  { value: 'light', label: 'Light', icon: <Sun aria-hidden="true" className="size-4" /> },
  { value: 'dark', label: 'Dark', icon: <Moon aria-hidden="true" className="size-4" /> },
  { value: 'system', label: 'System', icon: <Monitor aria-hidden="true" className="size-4" /> },
] as const satisfies readonly { value: ThemePreference; label: string; icon: React.ReactNode }[];

const HONOURED = [
  ['Reduced motion', 'Animations and transitions are removed.'],
  ['More contrast', 'Glass surfaces become solid with stronger borders.'],
  ['Forced colors', 'Borders and focus rings use system colours.'],
  ['Colour scheme', 'The System theme follows your operating system.'],
] as const;

export default function Settings({ version }: { version: string }) {
  const { preference, resolved, setPreference } = useTheme();
  const { keepPassword, setKeepPassword, demoMode, setDemoMode } = usePreferences();
  const session = useSession();
  const api = useApiStatus();
  return (
    <div>
      <PageHeader
        eyebrow="System"
        title="Settings"
        description="Preferences are stored in this browser only."
      />
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <Card as="section" aria-labelledby="appearance-heading">
          <CardHeader>
            <div>
              <CardTitle id="appearance-heading" level={2}>
                Appearance
              </CardTitle>
              <CardDescription>Choose how PassAudit looks.</CardDescription>
            </div>
          </CardHeader>
          <SegmentedControl
            legend="Theme"
            options={THEME_OPTIONS}
            value={preference}
            onChange={setPreference}
          />
          <p className="mt-3 text-sm text-fg-muted" aria-live="polite">
            Currently showing the <strong className="font-semibold text-fg">{resolved}</strong>{' '}
            theme
            {preference === 'system' ? ' (following your system).' : '.'}
          </p>
        </Card>

        <Card as="section" aria-labelledby="a11y-heading">
          <CardHeader>
            <div>
              <CardTitle id="a11y-heading" level={2}>
                Accessibility
              </CardTitle>
              <CardDescription>System preferences PassAudit already respects.</CardDescription>
            </div>
          </CardHeader>
          <CardContent>
            <dl className="divide-y divide-line/10">
              {HONOURED.map(([term, detail]) => (
                <div key={term} className="py-2.5 first:pt-0 last:pb-0">
                  <dt className="font-medium text-fg">{term}</dt>
                  <dd>{detail}</dd>
                </div>
              ))}
            </dl>
          </CardContent>
        </Card>

        <Card as="section" aria-labelledby="privacy-heading">
          <CardHeader>
            <div>
              <CardTitle id="privacy-heading" level={2}>
                Privacy
              </CardTitle>
              <CardDescription>How passwords are handled in this browser.</CardDescription>
            </div>
          </CardHeader>
          <CardContent className="space-y-5">
            <Switch
              label="Keep the password in the form after analysing"
              description="Off by default: the field is cleared as soon as a result arrives. Turning this on leaves the text in the form (in memory only) until you clear it or leave the page."
              checked={keepPassword}
              onChange={(event) => {
                setKeepPassword(event.target.checked);
              }}
            />
            <Switch
              label="Show demo data on the overview"
              description="Only while nothing has been audited. Always labelled as demonstration data."
              checked={demoMode}
              onChange={(event) => {
                setDemoMode(event.target.checked);
              }}
            />
            <div className="flex flex-wrap items-center justify-between gap-3 border-t border-line/10 pt-4">
              <p className="text-sm">
                <span className="font-medium text-fg">Session results:</span>{' '}
                {session.runs.length === 0
                  ? 'none'
                  : `${String(session.runs.length)} kept in memory`}
              </p>
              <Button
                variant="outline"
                size="sm"
                disabled={session.runs.length === 0}
                onClick={session.clear}
              >
                Clear session results
              </Button>
            </div>
          </CardContent>
        </Card>

        <Card as="section" aria-labelledby="service-heading">
          <CardHeader>
            <div>
              <CardTitle id="service-heading" level={2}>
                Service
              </CardTitle>
              <CardDescription>The local PassAudit API this page talks to.</CardDescription>
            </div>
            <Button
              variant="outline"
              size="sm"
              onClick={api.refresh}
              leadingIcon={<RefreshCw aria-hidden="true" className="size-4" />}
            >
              Check now
            </Button>
          </CardHeader>
          <CardContent>
            <dl className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <div>
                <dt className="text-xs uppercase tracking-wider text-fg-subtle">Status</dt>
                <dd className="mt-1">
                  <Badge
                    tone={
                      api.state === 'online'
                        ? 'success'
                        : api.state === 'offline'
                          ? 'warning'
                          : 'neutral'
                    }
                    dot
                  >
                    {api.state === 'online'
                      ? 'Connected'
                      : api.state === 'offline'
                        ? 'Not reachable'
                        : 'Checking'}
                  </Badge>
                </dd>
              </div>
              <div>
                <dt className="text-xs uppercase tracking-wider text-fg-subtle">Service version</dt>
                <dd className="mt-1 font-mono text-fg">{api.version ?? 'unknown'}</dd>
              </div>
              <div>
                <dt className="text-xs uppercase tracking-wider text-fg-subtle">
                  Passwords per batch
                </dt>
                <dd className="mt-1 text-fg">{api.limits.batch_max_items}</dd>
              </div>
              <div>
                <dt className="text-xs uppercase tracking-wider text-fg-subtle">
                  Longest password
                </dt>
                <dd className="mt-1 text-fg">{api.limits.max_password_length} characters</dd>
              </div>
            </dl>
            {api.capabilities && (
              <dl className="mt-5 grid grid-cols-1 gap-3 border-t border-line/10 pt-4 sm:grid-cols-2">
                <div>
                  <dt className="text-xs uppercase tracking-wider text-fg-subtle">
                    Breach check: local dataset
                  </dt>
                  <dd className="mt-1 text-fg">
                    {api.capabilities.breach.local ? 'Available' : 'Not configured'}
                  </dd>
                </div>
                <div>
                  <dt className="text-xs uppercase tracking-wider text-fg-subtle">
                    Breach check: online (k-anonymity)
                  </dt>
                  <dd className="mt-1 text-fg">
                    {api.capabilities.breach.online
                      ? `Enabled (${api.capabilities.breach.online_host ?? 'service'}) - sends a 5-character hash prefix`
                      : 'Off - nothing is sent anywhere'}
                  </dd>
                </div>
                <div>
                  <dt className="text-xs uppercase tracking-wider text-fg-subtle">Reuse index</dt>
                  <dd className="mt-1 text-fg">
                    {api.capabilities.reuse_index.available
                      ? api.capabilities.reuse_index.datasets.join(', ')
                      : 'Not configured'}
                  </dd>
                </div>
                <div>
                  <dt className="text-xs uppercase tracking-wider text-fg-subtle">Dictionaries</dt>
                  <dd className="mt-1 text-fg">
                    {api.capabilities.dictionaries.words} words,{' '}
                    {api.capabilities.dictionaries.names} names,{' '}
                    {api.capabilities.dictionaries.passwords} common passwords
                  </dd>
                </div>
              </dl>
            )}
            {!api.limitsLive && (
              <p className="mt-3 text-xs text-fg-muted">
                Limits shown are the documented defaults until the service responds.
              </p>
            )}
          </CardContent>
        </Card>

        <Card as="section" aria-labelledby="about-heading" className="lg:col-span-2">
          <CardHeader>
            <div>
              <CardTitle id="about-heading" level={2}>
                About
              </CardTitle>
              <CardDescription>PassAudit runs entirely on this machine.</CardDescription>
            </div>
          </CardHeader>
          <CardContent>
            <dl className="grid grid-cols-1 gap-4 sm:grid-cols-3">
              <div>
                <dt className="text-xs uppercase tracking-wider text-fg-subtle">Version</dt>
                <dd className="mt-1 font-mono text-fg">{version}</dd>
              </div>
              <div>
                <dt className="text-xs uppercase tracking-wider text-fg-subtle">API</dt>
                <dd className="mt-1 font-mono text-fg">127.0.0.1 (loopback only)</dd>
              </div>
              <div>
                <dt className="text-xs uppercase tracking-wider text-fg-subtle">
                  Stored in browser
                </dt>
                <dd className="mt-1 text-fg">
                  Preferences and the policy rules only - never passwords or results
                </dd>
              </div>
            </dl>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
