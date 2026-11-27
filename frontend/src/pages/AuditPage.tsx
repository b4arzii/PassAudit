import { ShieldCheck, Trash2 } from 'lucide-react';
import { useEffect, useRef, useState } from 'react';
import type { SyntheticEvent } from 'react';

import type { AuditRequest, BreachMode, ExposureOptions, PasswordAnalysis } from '../api/types.ts';
import { AnalysisView } from '../components/feature/AnalysisView.tsx';
import { ContextFields } from '../components/feature/ContextFields.tsx';
import { EMPTY_CONTEXT } from '../components/feature/contextValue.ts';
import type { ContextValue } from '../components/feature/contextValue.ts';
import { DemoBanner } from '../components/feature/DemoBanner.tsx';
import { ErrorPanel } from '../components/feature/ErrorPanel.tsx';
import { ExportPanel } from '../components/feature/ExportPanel.tsx';
import { ExposureFields } from '../components/feature/ExposureFields.tsx';
import { ConnectionNotice, PolicyNotice } from '../components/feature/Notices.tsx';
import {
  Button,
  Card,
  CardDescription,
  CardTitle,
  Field,
  PageHeader,
  PasswordInput,
  SkeletonText,
  Spinner,
} from '../components/ui/index.ts';
import { demo } from '../demo/demo.ts';
import { exposureField, NO_EXPOSURE } from '../lib/exposure.ts';
import { recordFromAnalysis } from '../lib/records.ts';
import type { AnalysisRecord, DataSource } from '../lib/records.ts';
import { useAsyncAction } from '../lib/useAsyncAction.ts';
import { nextRunPrefix, parsePersonalInfo, validatePasswordInput } from '../lib/validation.ts';
import { RISK_LABEL } from '../lib/labels.ts';
import { useApi, useApiStatus } from '../state/api.ts';
import { usePolicy } from '../state/policyState.ts';
import { usePreferences } from '../state/preferences.ts';
import { useSession } from '../state/session.ts';

interface ResultView {
  source: DataSource;
  analysis: PasswordAnalysis;
  record: AnalysisRecord;
  /** Which external breach check this run used (recorded in exports; never data). */
  breachMode?: BreachMode;
  reuseDatasets?: string[];
}

/**
 * Audit one password.
 *
 * Secret handling: the password and personal details live only in this component's state. They
 * are sent in the body of one POST, cleared after a successful analysis (unless the user opted
 * to keep them), and are never written to storage, the URL, the console or the session history,
 * which holds results only.
 */
export default function AuditPage() {
  const client = useApi();
  const { limits, capabilities } = useApiStatus();
  const { policy } = usePolicy();
  const { keepPassword } = usePreferences();
  const session = useSession();

  const [password, setPassword] = useState('');
  const [context, setContext] = useState<ContextValue>(EMPTY_CONTEXT);
  const [passwordError, setPasswordError] = useState<string | null>(null);
  const [personalError, setPersonalError] = useState<string | null>(null);
  const [exposure, setExposure] = useState<ExposureOptions>(NO_EXPOSURE);
  const [view, setView] = useState<ResultView | null>(null);
  const action = useAsyncAction<PasswordAnalysis>();

  const passwordRef = useRef<HTMLInputElement>(null);
  const resultHeading = useRef<HTMLHeadingElement>(null);
  const loading = action.state.status === 'loading';

  // Move focus to the result once it appears, so keyboard and screen-reader users land on it.
  useEffect(() => {
    if (view) resultHeading.current?.focus();
  }, [view]);

  async function submit(event?: SyntheticEvent): Promise<void> {
    event?.preventDefault();
    if (loading) return;
    const problem = validatePasswordInput(password, limits);
    const personal = parsePersonalInfo(context.personalText, limits);
    setPasswordError(problem);
    setPersonalError(personal.error);
    if (problem) {
      passwordRef.current?.focus();
      return;
    }
    if (personal.error) return;

    const body: AuditRequest = {
      password,
      policy,
      context: {
        usage: context.usage,
        personal_info: personal.items,
        reused_elsewhere: context.reused,
      },
      ...exposureField(exposure),
    };
    const analysis = await action.run((signal) => client.audit(body, signal));
    if (!analysis) return;

    const label = `Analysis ${String(session.runs.filter((r) => r.kind === 'analysis').length + 1)}`;
    const record = recordFromAnalysis(nextRunPrefix('a'), label, analysis);
    session.addRun({
      kind: 'analysis',
      title: label,
      records: [record],
      usage: context.usage,
      policy,
      analysis,
    });
    setView({
      source: 'live',
      analysis,
      record,
      breachMode: exposure.breach,
      ...(exposure.reuse && capabilities
        ? { reuseDatasets: capabilities.reuse_index.datasets }
        : {}),
    });
    if (!keepPassword) setPassword('');
  }

  function showDemo(): void {
    const sample = demo.analyses[0];
    if (!sample) return;
    action.cancel();
    setView({
      source: 'demo',
      analysis: sample.analysis,
      record: recordFromAnalysis(`demo-${sample.id}`, sample.title, sample.analysis),
    });
  }

  function clearAll(): void {
    action.cancel();
    setPassword('');
    setContext(EMPTY_CONTEXT);
    setExposure(NO_EXPOSURE);
    setPasswordError(null);
    setPersonalError(null);
    setView(null);
    passwordRef.current?.focus();
  }

  const hasInput = password !== '' || context.personalText !== '' || view !== null;

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="Workspace"
        title="Audit"
        description="Analyse one password: how it would be attacked, what weakens it, and how to fix it."
      />
      <ConnectionNotice />

      <Card as="section" aria-labelledby="audit-form-h">
        <CardTitle id="audit-form-h" level={2}>
          Password
        </CardTitle>
        <CardDescription>
          Analysed by the local service on this machine. The password is never stored or logged, and
          is cleared from this form after the analysis.
        </CardDescription>
        <form
          onSubmit={(event) => void submit(event)}
          noValidate
          autoComplete="off"
          aria-busy={loading || undefined}
          className="mt-5 grid grid-cols-1 gap-6 lg:grid-cols-2"
        >
          <div className="space-y-4">
            <Field label="Password to analyse" error={passwordError ?? undefined} required>
              <PasswordInput
                ref={passwordRef}
                value={password}
                name="audit-secret"
                disabled={loading}
                onChange={(event) => {
                  setPassword(event.target.value);
                  if (passwordError) setPasswordError(null);
                }}
              />
            </Field>
            <PolicyNotice />
          </div>
          <div className="space-y-6">
            <ContextFields
              value={context}
              onChange={setContext}
              personalError={personalError}
              disabled={loading}
            />
            <ExposureFields value={exposure} onChange={setExposure} disabled={loading} />
          </div>
          <div className="flex flex-wrap items-center gap-3 lg:col-span-2">
            <Button
              type="submit"
              loading={loading}
              leadingIcon={<ShieldCheck aria-hidden="true" className="size-4" />}
            >
              {loading ? 'Analysing...' : 'Analyse password'}
            </Button>
            <Button
              variant="ghost"
              onClick={clearAll}
              disabled={!hasInput && action.state.status !== 'error'}
              leadingIcon={<Trash2 aria-hidden="true" className="size-4" />}
            >
              Clear form and result
            </Button>
          </div>
        </form>
      </Card>

      {action.state.status === 'error' && (
        <ErrorPanel
          error={action.state.error}
          onRetry={() => void submit()}
          onUseDemo={showDemo}
          onDismiss={action.cancel}
        />
      )}

      <section
        aria-labelledby="audit-result-h"
        aria-busy={loading || undefined}
        className="space-y-4"
      >
        {view || loading ? (
          <h2
            id="audit-result-h"
            ref={resultHeading}
            tabIndex={-1}
            className="text-xl font-semibold outline-none"
          >
            {loading ? 'Analysing...' : 'Result'}
          </h2>
        ) : (
          <h2 id="audit-result-h" className="sr-only">
            Result
          </h2>
        )}

        {loading && (
          <Card>
            <div className="mb-4 flex items-center gap-3 text-sm text-fg-muted">
              <Spinner label="Analysing the password" size="sm" />
              Analysing locally...
            </div>
            <SkeletonText lines={4} />
          </Card>
        )}

        {!loading && view && (
          <>
            {view.source === 'demo' && (
              <DemoBanner
                reason="The service is not connected."
                onExit={() => {
                  setView(null);
                }}
              />
            )}
            <p role="status" className="sr-only">
              Analysis complete. Risk {view.analysis.risk.score} out of 100,{' '}
              {RISK_LABEL[view.analysis.risk.level]}.
            </p>
            <AnalysisView analysis={view.analysis} headingLevel={3} />
            <Card>
              <ExportPanel
                title={view.source === 'demo' ? 'Demo password analysis' : 'Password analysis'}
                kind="analysis"
                source={view.source}
                records={[view.record]}
                analysis={view.analysis}
                breachMode={view.breachMode ?? 'off'}
                reuseDatasets={view.reuseDatasets}
                defaultName="passaudit-analysis"
                headingLevel={3}
              />
            </Card>
          </>
        )}
      </section>
    </div>
  );
}
