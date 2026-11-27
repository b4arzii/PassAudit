import {
  ArrowRight,
  BarChart3,
  Check,
  FileSpreadsheet,
  FlaskConical,
  Palette,
  ScrollText,
  ShieldCheck,
  Sparkles,
  Trash2,
} from 'lucide-react';
import { useMemo } from 'react';
import { Link } from 'react-router-dom';

import { DemoBanner } from '../components/feature/DemoBanner.tsx';
import { SummaryPanel } from '../components/feature/SummaryPanel.tsx';
import {
  Badge,
  Button,
  Card,
  CardContent,
  CardDescription,
  CardTitle,
  EmptyState,
  buttonClasses,
} from '../components/ui/index.ts';
import { demoAllRecords } from '../demo/demo.ts';
import { plural } from '../lib/format.ts';
import { summarizeRecords } from '../lib/records.ts';
import { usePreferences } from '../state/preferences.ts';
import { useSession } from '../state/session.ts';

const FEATURES = [
  {
    to: '/audit',
    icon: ShieldCheck,
    title: 'Audit a password',
    text: 'Strength, weaknesses, entropy and a transparent risk score - analysed locally, never stored.',
    accent: 'primary',
  },
  {
    to: '/batch',
    icon: FileSpreadsheet,
    title: 'Audit in bulk',
    text: 'Check a whole list at once, spot reuse, and export sanitized JSON or CSV reports.',
    accent: 'secondary',
  },
  {
    to: '/policies',
    icon: ScrollText,
    title: 'Check a policy',
    text: 'Validate passwords against a configurable policy, rule by rule, with clear reasons.',
    accent: 'accent',
  },
] as const;

const FOUNDATIONS = [
  { name: 'Analysis engine', detail: 'Strength, patterns, dictionary, policy, risk score' },
  { name: 'Command-line interface', detail: 'audit, batch, policy check' },
  { name: 'Local HTTP API', detail: 'Versioned, rate-limited, privacy-first' },
  { name: 'Design system', detail: 'Components, themes, accessibility' },
  { name: 'Web workspaces', detail: 'Audit, Batch and Policies, connected to the local API' },
] as const;

/** Decorative illustration of the kind of result PassAudit produces. Not real data. */
function HeroPreview() {
  const rules = [
    ['Length of 16 characters', 'w-full'],
    ['Not a common password', 'w-full'],
    ['No keyboard patterns', 'w-4/5'],
  ] as const;
  return (
    <div
      aria-hidden="true"
      className="pointer-events-none absolute right-8 top-1/2 hidden w-72 -translate-y-1/2 xl:block"
    >
      <div className="glass-strong rounded-2xl p-5">
        <div className="mb-4 flex items-center justify-between">
          <span className="text-xs font-semibold uppercase tracking-[0.14em] text-fg-subtle">
            Example result
          </span>
          <Badge tone="success" size="sm" dot>
            Low risk
          </Badge>
        </div>
        <div className="mb-5 flex items-center gap-4">
          <svg viewBox="0 0 72 72" className="size-[72px] -rotate-90">
            <circle
              cx="36"
              cy="36"
              r="30"
              fill="none"
              stroke="rgb(var(--fg) / 0.1)"
              strokeWidth="7"
            />
            <circle
              cx="36"
              cy="36"
              r="30"
              fill="none"
              stroke="rgb(var(--primary))"
              strokeWidth="7"
              strokeLinecap="round"
              strokeDasharray="188.5"
              strokeDashoffset="160"
            />
          </svg>
          <div>
            <p className="tabular font-mono text-3xl font-semibold leading-none text-fg">
              12<span className="text-base text-fg-subtle">/100</span>
            </p>
            <p className="mt-1 text-xs text-fg-muted">Risk score</p>
          </div>
        </div>
        <ul className="space-y-3">
          {rules.map(([label, width]) => (
            <li key={label}>
              <p className="mb-1.5 flex items-center gap-2 text-xs text-fg-muted">
                <Check className="size-3.5 text-primary" />
                {label}
              </p>
              <div className="h-1 rounded-full bg-fg/10">
                <div className={`h-1 rounded-full bg-brand-gradient ${width}`} />
              </div>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}

/** What this browser tab has audited so far (results only), or clearly labelled demo data. */
function SessionOverview() {
  const session = useSession();
  const { demoMode, setDemoMode } = usePreferences();
  const live = session.records;
  const showDemo = live.length === 0 && demoMode;
  const records = useMemo(() => (showDemo ? demoAllRecords() : live), [showDemo, live]);
  const stats = useMemo(() => summarizeRecords(records), [records]);

  return (
    <section aria-labelledby="session-heading" className="space-y-4">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h2 id="session-heading" className="text-xl font-semibold">
            This session
          </h2>
          <p className="mt-1 text-sm text-fg-muted">
            Results from this browser tab only. They are kept in memory - closing or reloading the
            page clears them - and never include passwords.
          </p>
        </div>
        {live.length > 0 && (
          <Button
            variant="outline"
            size="sm"
            leadingIcon={<Trash2 aria-hidden="true" className="size-4" />}
            onClick={session.clear}
          >
            Clear session results
          </Button>
        )}
      </div>

      {records.length === 0 ? (
        <EmptyState
          level={3}
          icon={<BarChart3 className="size-6" />}
          title="Nothing audited yet"
          description="Run an audit, a batch or a policy check and the results are summarised here."
          action={
            <div className="flex flex-wrap justify-center gap-3">
              <Link to="/audit" className={buttonClasses()}>
                Audit a password
              </Link>
              <Button
                variant="outline"
                leadingIcon={<FlaskConical aria-hidden="true" className="size-4" />}
                onClick={() => {
                  setDemoMode(true);
                }}
              >
                Preview with demo data
              </Button>
            </div>
          }
        />
      ) : (
        <>
          {showDemo && (
            <DemoBanner
              onExit={() => {
                setDemoMode(false);
              }}
            />
          )}
          <p className="text-sm text-fg-muted" role="status">
            {showDemo ? 'Showing' : 'Summarising'} {plural(records.length, 'password')}.
          </p>
          <SummaryPanel stats={stats} />
        </>
      )}
    </section>
  );
}

export default function Overview() {
  return (
    <div className="space-y-10">
      <Card variant="glass" accent="primary" padding="lg" className="overflow-hidden">
        <div
          aria-hidden="true"
          className="pointer-events-none absolute -right-24 -top-24 size-72 rounded-full bg-primary/10 blur-3xl"
        />
        <HeroPreview />
        <div className="relative max-w-2xl xl:max-w-xl">
          <Badge tone="primary" dot className="mb-5">
            Local-first password auditing
          </Badge>
          <h1 className="text-4xl font-semibold tracking-tight sm:text-5xl">
            Know how strong your passwords <span className="gradient-text">really are.</span>
          </h1>
          <p className="mt-5 text-lg text-fg-muted">
            PassAudit analyses passwords on your machine and explains every weakness it finds.
            Nothing is sent to a server you do not control, and nothing is written down.
          </p>
          <div className="mt-8 flex flex-wrap gap-3">
            <Link to="/audit" className={buttonClasses({ size: 'lg' })}>
              Start an audit
              <ArrowRight aria-hidden="true" className="size-5" />
            </Link>
            <Link to="/design-system" className={buttonClasses({ variant: 'outline', size: 'lg' })}>
              <Palette aria-hidden="true" className="size-5" />
              Explore the design system
            </Link>
          </div>
        </div>
      </Card>

      <section aria-labelledby="workspaces-heading">
        <h2 id="workspaces-heading" className="mb-4 text-xl font-semibold">
          Workspaces
        </h2>
        <ul className="grid grid-cols-1 gap-4 md:grid-cols-3">
          {FEATURES.map(({ to, icon: Icon, title, text, accent }) => (
            <li key={to} className="flex">
              <Card as="article" interactive accent={accent} className="flex w-full flex-col">
                <div className="mb-4 flex items-center justify-between">
                  <span
                    aria-hidden="true"
                    className="flex size-11 items-center justify-center rounded-xl bg-brand-gradient-soft text-primary ring-1 ring-line/10"
                  >
                    <Icon className="size-5" />
                  </span>
                </div>
                <CardTitle level={3}>
                  <Link to={to} className="rounded after:absolute after:inset-0">
                    {title}
                  </Link>
                </CardTitle>
                <CardDescription className="flex-1">{text}</CardDescription>
              </Card>
            </li>
          ))}
        </ul>
      </section>

      <SessionOverview />

      <section aria-labelledby="foundations-heading">
        <Card>
          <div className="mb-4 flex items-center gap-2">
            <Sparkles aria-hidden="true" className="size-5 text-secondary" />
            <h2 id="foundations-heading" className="text-xl font-semibold">
              What is already built
            </h2>
          </div>
          <CardContent>
            <ul className="divide-y divide-line/10">
              {FOUNDATIONS.map((item) => (
                <li
                  key={item.name}
                  className="flex flex-wrap items-center justify-between gap-2 py-3"
                >
                  <div>
                    <p className="font-medium text-fg">{item.name}</p>
                    <p className="text-sm text-fg-muted">{item.detail}</p>
                  </div>
                  <Badge tone="success" dot size="sm">
                    Ready
                  </Badge>
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>
      </section>
    </div>
  );
}
