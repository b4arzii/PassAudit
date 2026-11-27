import {
  Download,
  Mail,
  Moon,
  Plus,
  Search,
  Settings as SettingsIcon,
  Shield,
  Sun,
  Trash2,
} from 'lucide-react';
import { useState } from 'react';
import type { ReactNode } from 'react';

import {
  Alert,
  Badge,
  Button,
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
  Checkbox,
  ConfirmDialog,
  Dialog,
  EmptyState,
  Field,
  IconButton,
  Input,
  Kbd,
  PageHeader,
  PasswordInput,
  Progress,
  Section,
  SegmentedControl,
  Select,
  Skeleton,
  SkeletonText,
  Spinner,
  Switch,
  TBody,
  TD,
  TH,
  THead,
  TR,
  Table,
  TableEmpty,
  TableSkeletonRows,
  Textarea,
  useToast,
} from '../components/ui/index.ts';
import type { BadgeTone, ButtonVariant, SortDirection } from '../components/ui/index.ts';

const SECTIONS = [
  ['colour', 'Colour'],
  ['typography', 'Typography'],
  ['buttons', 'Buttons'],
  ['badges', 'Badges'],
  ['forms', 'Form controls'],
  ['cards', 'Cards'],
  ['alerts', 'Alerts'],
  ['tables', 'Tables'],
  ['dialogs', 'Dialogs'],
  ['notifications', 'Notifications'],
  ['loading', 'Loading'],
] as const;

const SWATCHES = [
  { name: 'canvas', cls: 'bg-canvas', use: 'Page background' },
  { name: 'surface', cls: 'bg-surface', use: 'Cards, tables' },
  { name: 'surface-2', cls: 'bg-surface-2', use: 'Inputs, headers' },
  { name: 'surface-3', cls: 'bg-surface-3', use: 'Raised, selected' },
  { name: 'primary', cls: 'bg-primary', use: 'Brand, primary actions' },
  { name: 'secondary', cls: 'bg-secondary', use: 'Purple accent' },
  { name: 'accent', cls: 'bg-accent', use: 'Cyan accent, focus' },
  { name: 'success', cls: 'bg-success', use: 'Positive status' },
  { name: 'warning', cls: 'bg-warning', use: 'Caution' },
  { name: 'danger', cls: 'bg-danger', use: 'Errors, destructive' },
] as const;

const VARIANTS: readonly ButtonVariant[] = ['primary', 'secondary', 'outline', 'ghost', 'danger'];
const TONES: readonly BadgeTone[] = [
  'neutral',
  'primary',
  'secondary',
  'accent',
  'success',
  'warning',
  'danger',
];

interface Row {
  name: string;
  rules: number;
  status: 'Active' | 'Draft' | 'Archived';
  updated: string;
}
const ROWS: readonly Row[] = [
  { name: 'Default policy', rules: 4, status: 'Active', updated: '2026-11-20' },
  { name: 'Strict (admin accounts)', rules: 9, status: 'Active', updated: '2026-11-18' },
  { name: 'Legacy (pre-2024)', rules: 3, status: 'Archived', updated: '2026-02-02' },
  { name: 'Contractors', rules: 6, status: 'Draft', updated: '2026-11-25' },
];
const STATUS_TONE = { Active: 'success', Draft: 'warning', Archived: 'neutral' } as const;

function Demo({ children, className = '' }: { children: ReactNode; className?: string }) {
  return <div className={`flex flex-wrap items-center gap-3 ${className}`}>{children}</div>;
}

export default function DesignSystem() {
  const toast = useToast();
  const [dialog, setDialog] = useState<'none' | 'basic' | 'confirm'>('none');
  const [confirming, setConfirming] = useState(false);
  const [sort, setSort] = useState<SortDirection>('ascending');
  const [tableState, setTableState] = useState<'data' | 'loading' | 'empty'>('data');
  const [view, setView] = useState<'comfortable' | 'compact'>('comfortable');
  const [notify, setNotify] = useState(true);
  const [progress, setProgress] = useState(64);

  const rows = [...ROWS].sort((a, b) =>
    sort === 'descending' ? b.name.localeCompare(a.name) : a.name.localeCompare(b.name),
  );

  return (
    <div>
      <PageHeader
        eyebrow="System"
        title="Design system"
        description="The components, tokens and patterns every PassAudit screen is built from. Switch the theme in the header to see both modes."
        actions={
          <Badge tone="secondary" dot>
            Phase 5
          </Badge>
        }
      />

      <nav aria-label="On this page" className="mb-10">
        <ul className="flex flex-wrap gap-2">
          {SECTIONS.map(([id, label]) => (
            <li key={id}>
              <a
                href={`#${id}`}
                className="inline-flex h-9 items-center rounded-full border border-line/15 bg-surface/60 px-4 text-sm text-fg-muted transition-colors hover:border-line/30 hover:text-fg"
              >
                {label}
              </a>
            </li>
          ))}
        </ul>
      </nav>

      <div className="space-y-16">
        {/* ---------------------------------------------------------------- colour */}
        <Section
          id="colour"
          headingId="h-colour"
          title="Colour"
          description="Near-black and charcoal surfaces, a neon-green primary, purple and cyan accents. Every colour is a token that re-maps for the light theme."
        >
          <ul className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
            {SWATCHES.map((s) => (
              <li
                key={s.name}
                className="overflow-hidden rounded-xl border border-line/10 bg-surface"
              >
                <div className={`h-16 ${s.cls}`} />
                <div className="p-3">
                  <p className="font-mono text-xs font-medium text-fg">{s.name}</p>
                  <p className="text-xs text-fg-muted">{s.use}</p>
                </div>
              </li>
            ))}
          </ul>
          <div
            className="mt-4 h-3 rounded-full bg-brand-gradient"
            role="img"
            aria-label="Brand gradient from green to cyan"
          />
        </Section>

        {/* ------------------------------------------------------------- typography */}
        <Section
          id="typography"
          headingId="h-typography"
          title="Typography"
          description="Inter Variable for the interface, JetBrains Mono Variable for data. Both are bundled - nothing loads from a CDN."
        >
          <Card className="space-y-4">
            <p className="text-4xl font-semibold tracking-tight">Display 40 - Secure by design</p>
            <p className="text-3xl font-semibold tracking-tight">Heading 30 - Audit results</p>
            <p className="text-2xl font-semibold">Heading 24 - Policy rules</p>
            <p className="text-xl font-semibold">Heading 20 - Recommendations</p>
            <p className="text-base text-fg">
              Body 16 - Passwords are analysed in memory on this machine and are never stored,
              logged, or sent anywhere.
            </p>
            <p className="text-sm text-fg-muted">Small 14 - Secondary text and help.</p>
            <p className="text-xs text-fg-subtle">Caption 12 - Meta information</p>
            <p className="font-mono text-sm text-fg">
              <span className="tabular">risk_score = 37 / 100 &nbsp; guesses_log10 = 7.44</span>
            </p>
          </Card>
        </Section>

        {/* ---------------------------------------------------------------- buttons */}
        <Section
          id="buttons"
          headingId="h-buttons"
          title="Buttons"
          description="Five variants and three sizes. Loading buttons stay focusable and announce aria-busy; icon-only buttons require an accessible label."
        >
          <Card className="space-y-6">
            <Demo>
              {VARIANTS.map((v) => (
                <Button key={v} variant={v}>
                  {v[0]?.toUpperCase()}
                  {v.slice(1)}
                </Button>
              ))}
            </Demo>
            <Demo>
              <Button size="sm">Small</Button>
              <Button size="md">Medium</Button>
              <Button size="lg">Large</Button>
              <Button leadingIcon={<Plus aria-hidden="true" className="size-4" />}>
                New audit
              </Button>
              <Button
                variant="outline"
                trailingIcon={<Download aria-hidden="true" className="size-4" />}
              >
                Export
              </Button>
            </Demo>
            <Demo>
              <Button loading>Analysing</Button>
              <Button variant="secondary" loading>
                Saving
              </Button>
              <Button disabled>Disabled</Button>
              <Button variant="outline" disabled>
                Disabled
              </Button>
            </Demo>
            <Demo>
              <IconButton label="Settings" variant="secondary">
                <SettingsIcon aria-hidden="true" className="size-5" />
              </IconButton>
              <IconButton label="Delete item" variant="ghost">
                <Trash2 aria-hidden="true" className="size-5" />
              </IconButton>
              <IconButton label="Search" variant="outline">
                <Search aria-hidden="true" className="size-5" />
              </IconButton>
              <IconButton label="Loading" variant="secondary" loading>
                <Shield aria-hidden="true" className="size-5" />
              </IconButton>
            </Demo>
          </Card>
        </Section>

        {/* ----------------------------------------------------------------- badges */}
        <Section
          id="badges"
          headingId="h-badges"
          title="Badges"
          description="Status is always carried by text; colour and the dot only reinforce it."
        >
          <Card className="space-y-4">
            <Demo>
              {TONES.map((t) => (
                <Badge key={t} tone={t}>
                  {t}
                </Badge>
              ))}
            </Demo>
            <Demo>
              {TONES.map((t) => (
                <Badge key={t} tone={t} dot outline>
                  {t}
                </Badge>
              ))}
            </Demo>
            <Demo>
              <Badge tone="success" size="sm" dot>
                Passed
              </Badge>
              <Badge tone="danger" size="sm" dot>
                Critical risk
              </Badge>
              <Badge tone="warning" size="sm" dot>
                Reused
              </Badge>
            </Demo>
          </Card>
        </Section>

        {/* ------------------------------------------------------------------ forms */}
        <Section
          id="forms"
          headingId="h-forms"
          title="Form controls"
          description="Field wires the label, hint, error and required state to its control. The password field here is a demo - nothing is sent or stored."
        >
          <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
            <Card className="space-y-5">
              <Field label="Display name" hint="Shown on reports. 3-40 characters.">
                <Input placeholder="e.g. Quarterly review" leadingIcon={<Search />} />
              </Field>
              <Field
                label="Password"
                hint="Demo field: hidden by default, with a reveal toggle."
                required
              >
                <PasswordInput placeholder="Type to try the field" />
              </Field>
              <Field label="E-mail" error="Enter a valid e-mail address." required>
                <Input type="email" defaultValue="not-an-email" leadingIcon={<Mail />} />
              </Field>
              <Field label="Disabled" disabled>
                <Input defaultValue="Read only value" />
              </Field>
            </Card>
            <Card className="space-y-5">
              <Field label="Usage">
                <Select defaultValue="online_account">
                  <option value="general">General</option>
                  <option value="online_account">Online account</option>
                  <option value="privileged_account">Privileged account</option>
                  <option value="master_password">Master password</option>
                </Select>
              </Field>
              <Field label="Notes" hint="Optional.">
                <Textarea placeholder="Add context for reviewers" />
              </Field>
              <div className="space-y-3">
                <Checkbox
                  label="Include recommendations"
                  description="Adds advice to the report."
                  defaultChecked
                />
                <Checkbox label="Detect reused passwords" />
              </div>
              <Switch
                label="Email me a summary"
                description="Applies immediately."
                checked={notify}
                onChange={(e) => {
                  setNotify(e.target.checked);
                }}
              />
              <SegmentedControl
                legend="Density"
                value={view}
                onChange={setView}
                options={[
                  { value: 'comfortable', label: 'Comfortable' },
                  { value: 'compact', label: 'Compact' },
                ]}
              />
            </Card>
          </div>
        </Section>

        {/* ------------------------------------------------------------------ cards */}
        <Section
          id="cards"
          headingId="h-cards"
          title="Cards"
          description="Solid, glass and outline surfaces, with optional accent glow and hover lift."
        >
          <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
            <Card accent="primary">
              <CardHeader>
                <div>
                  <CardTitle level={3}>Solid</CardTitle>
                  <CardDescription>Default surface with a top accent.</CardDescription>
                </div>
                <Badge tone="primary" size="sm">
                  New
                </Badge>
              </CardHeader>
              <CardContent>Used for most content blocks.</CardContent>
              <CardFooter>
                <Button size="sm" variant="secondary">
                  Action
                </Button>
              </CardFooter>
            </Card>
            <Card variant="glass" accent="secondary">
              <CardHeader>
                <div>
                  <CardTitle level={3}>Glass</CardTitle>
                  <CardDescription>Translucent with backdrop blur.</CardDescription>
                </div>
              </CardHeader>
              <CardContent>Used for chrome and highlights over the ambient background.</CardContent>
            </Card>
            <Card variant="outline" interactive accent="accent">
              <CardHeader>
                <div>
                  <CardTitle level={3}>Interactive</CardTitle>
                  <CardDescription>Lifts on hover.</CardDescription>
                </div>
              </CardHeader>
              <CardContent>For cards that behave like links.</CardContent>
            </Card>
          </div>
        </Section>

        {/* ----------------------------------------------------------------- alerts */}
        <Section
          id="alerts"
          headingId="h-alerts"
          title="Alerts"
          description="Errors are announced immediately (role=alert); everything else politely (role=status)."
        >
          <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
            <Alert tone="info" title="Heads up">
              Analysis happens on this machine.
            </Alert>
            <Alert tone="success" title="Policy satisfied">
              All 4 rules passed.
            </Alert>
            <Alert tone="warning" title="Reused password">
              This password appears twice in the batch.
            </Alert>
            <Alert
              tone="danger"
              title="Could not reach the API"
              action={
                <Button size="sm" variant="outline">
                  Retry
                </Button>
              }
            >
              Start the backend and try again.
            </Alert>
          </div>
        </Section>

        {/* ----------------------------------------------------------------- tables */}
        <Section
          id="tables"
          headingId="h-tables"
          title="Tables"
          description="Real table semantics, sortable headers with aria-sort, a keyboard-scrollable region, and loading and empty states."
        >
          <div className="mb-4">
            <SegmentedControl
              legend="Demo state"
              value={tableState}
              onChange={setTableState}
              options={[
                { value: 'data', label: 'Data' },
                { value: 'loading', label: 'Loading' },
                { value: 'empty', label: 'Empty' },
              ]}
            />
          </div>
          <div aria-busy={tableState === 'loading'}>
            <Table
              label="Example policies"
              caption="Example policies with their rule count, status and last update"
            >
              <THead>
                <TR>
                  <TH
                    sort={sort}
                    onSort={() => {
                      setSort((s) => (s === 'ascending' ? 'descending' : 'ascending'));
                    }}
                  >
                    Policy
                  </TH>
                  <TH align="right">Rules</TH>
                  <TH>Status</TH>
                  <TH>Updated</TH>
                </TR>
              </THead>
              <TBody>
                {tableState === 'loading' && <TableSkeletonRows columns={4} />}
                {tableState === 'empty' && (
                  <TableEmpty colSpan={4}>No policies yet. Create one to get started.</TableEmpty>
                )}
                {tableState === 'data' &&
                  rows.map((row) => (
                    <TR key={row.name}>
                      <TD className={view === 'compact' ? 'py-2' : ''}>
                        <span className="font-medium">{row.name}</span>
                      </TD>
                      <TD align="right" className="tabular font-mono">
                        {row.rules}
                      </TD>
                      <TD>
                        <Badge tone={STATUS_TONE[row.status]} size="sm" dot>
                          {row.status}
                        </Badge>
                      </TD>
                      <TD className="tabular text-fg-muted">{row.updated}</TD>
                    </TR>
                  ))}
              </TBody>
            </Table>
          </div>
        </Section>

        {/* ---------------------------------------------------------------- dialogs */}
        <Section
          id="dialogs"
          headingId="h-dialogs"
          title="Dialogs"
          description="Focus is trapped and restored, Escape closes, the page behind is inert, and the dialog is named and described for screen readers."
        >
          <Card>
            <Demo>
              <Button
                variant="secondary"
                onClick={() => {
                  setDialog('basic');
                }}
              >
                Open dialog
              </Button>
              <Button
                variant="danger"
                leadingIcon={<Trash2 aria-hidden="true" className="size-4" />}
                onClick={() => {
                  setDialog('confirm');
                }}
              >
                Delete policy
              </Button>
              <span className="text-sm text-fg-muted">
                Press <Kbd>Esc</Kbd> to close, <Kbd>Tab</Kbd> to move within.
              </span>
            </Demo>
          </Card>
          <Dialog
            open={dialog === 'basic'}
            onClose={() => {
              setDialog('none');
            }}
            title="Rename policy"
            description="Names appear on reports and in the policy list."
            footer={
              <>
                <Button
                  variant="outline"
                  onClick={() => {
                    setDialog('none');
                  }}
                >
                  Cancel
                </Button>
                <Button
                  onClick={() => {
                    setDialog('none');
                    toast.success('Policy renamed');
                  }}
                >
                  Save
                </Button>
              </>
            }
          >
            <Field label="Policy name">
              <Input defaultValue="Default policy" data-autofocus />
            </Field>
          </Dialog>
          <ConfirmDialog
            open={dialog === 'confirm'}
            onClose={() => {
              setDialog('none');
            }}
            title="Delete this policy?"
            description="This cannot be undone. Reports already exported are not affected."
            confirmLabel="Delete policy"
            tone="danger"
            loading={confirming}
            onConfirm={() => {
              setConfirming(true);
              window.setTimeout(() => {
                setConfirming(false);
                setDialog('none');
                toast.error('Policy deleted', 'The "Contractors" policy was removed.');
              }, 900);
            }}
          />
        </Section>

        {/* ---------------------------------------------------------- notifications */}
        <Section
          id="notifications"
          headingId="h-notifications"
          title="Notifications"
          description="Toasts announce through live regions, pause while hovered or focused, dismiss with the button or Escape, and never steal focus."
        >
          <Card>
            <Demo>
              <Button
                variant="secondary"
                onClick={() =>
                  toast.info('Report ready', 'Your sanitized report has been generated.')
                }
              >
                Info
              </Button>
              <Button
                variant="secondary"
                onClick={() => toast.success('Saved', 'Settings were updated.')}
              >
                Success
              </Button>
              <Button
                variant="secondary"
                onClick={() => toast.warning('Rate limit close', 'Slow down for a moment.')}
              >
                Warning
              </Button>
              <Button
                variant="secondary"
                onClick={() => toast.error('Request failed', 'The API did not respond.')}
              >
                Error
              </Button>
              <Button
                variant="outline"
                onClick={() =>
                  toast.show({
                    title: 'Policy archived',
                    description: 'You can restore it for 30 days.',
                    tone: 'info',
                    duration: null,
                    action: { label: 'Undo', onClick: () => toast.success('Restored') },
                  })
                }
              >
                With action
              </Button>
              <Button variant="ghost" onClick={toast.dismissAll}>
                Clear all
              </Button>
            </Demo>
          </Card>
        </Section>

        {/* ---------------------------------------------------------------- loading */}
        <Section
          id="loading"
          headingId="h-loading"
          title="Loading states"
          description="Spinners, skeletons and progress bars - each with an accessible name, and all stilled for users who prefer reduced motion."
        >
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
            <Card>
              <CardTitle level={3} className="mb-4 text-base">
                Spinners
              </CardTitle>
              <Demo className="gap-6">
                <Spinner size="sm" label="Loading small" />
                <Spinner size="md" label="Loading medium" />
                <Spinner size="lg" label="Loading large" className="text-primary" />
              </Demo>
            </Card>
            <Card aria-busy="true">
              <CardTitle level={3} className="mb-4 text-base">
                Skeleton
              </CardTitle>
              <div className="flex gap-3">
                <Skeleton className="size-11 shrink-0 rounded-xl" />
                <div className="flex-1 space-y-2">
                  <Skeleton className="h-4 w-1/2" />
                  <SkeletonText lines={2} />
                </div>
              </div>
              <span className="sr-only" role="status">
                Loading content
              </span>
            </Card>
            <Card>
              <CardTitle level={3} className="mb-4 text-base">
                Progress
              </CardTitle>
              <div className="space-y-4">
                <Progress label="Analysing passwords" value={progress} />
                <Progress label="Preparing report" tone="secondary" />
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => {
                    setProgress((p) => (p >= 100 ? 0 : Math.min(100, p + 18)));
                  }}
                >
                  Advance ({progress}%)
                </Button>
              </div>
            </Card>
          </div>
          <EmptyState
            className="mt-6"
            icon={<Sun className="size-6" />}
            title="Empty state"
            description="Use it when a list or workspace has nothing to show yet, and point to the next step."
            action={
              <Button
                variant="outline"
                leadingIcon={<Moon aria-hidden="true" className="size-4" />}
              >
                Take the next step
              </Button>
            }
            level={3}
          />
        </Section>
      </div>
    </div>
  );
}
