import { FileSpreadsheet, Trash2 } from 'lucide-react';
import { useEffect, useMemo, useRef, useState } from 'react';
import type { SyntheticEvent } from 'react';

import type { BatchRequest, BatchResponse, BreachMode, ExposureOptions } from '../api/types.ts';
import { ContextFields } from '../components/feature/ContextFields.tsx';
import { EMPTY_CONTEXT } from '../components/feature/contextValue.ts';
import type { ContextValue } from '../components/feature/contextValue.ts';
import { DemoBanner } from '../components/feature/DemoBanner.tsx';
import { ErrorPanel } from '../components/feature/ErrorPanel.tsx';
import { ExportPanel } from '../components/feature/ExportPanel.tsx';
import { ExposureFields } from '../components/feature/ExposureFields.tsx';
import { ConnectionNotice, PolicyNotice } from '../components/feature/Notices.tsx';
import { RecordDetail } from '../components/feature/RecordDetail.tsx';
import { ResultsTable } from '../components/feature/ResultsTable.tsx';
import { SummaryPanel } from '../components/feature/SummaryPanel.tsx';
import {
  Alert,
  Button,
  Card,
  CardDescription,
  CardTitle,
  Dialog,
  Field,
  FileDrop,
  PageHeader,
  Progress,
  SegmentedControl,
  SkeletonText,
  Textarea,
} from '../components/ui/index.ts';
import { demo } from '../demo/demo.ts';
import { exposureField, NO_EXPOSURE } from '../lib/exposure.ts';
import { parseBatchInput } from '../lib/csv.ts';
import type { BatchEntry, BatchInputFormat, ParsedBatch } from '../lib/csv.ts';
import { plural } from '../lib/format.ts';
import { recordsFromBatch, summarizeRecords } from '../lib/records.ts';
import type { AnalysisRecord, DataSource } from '../lib/records.ts';
import { useAsyncAction } from '../lib/useAsyncAction.ts';
import { nextRunPrefix, parsePersonalInfo, validateBatchEntries } from '../lib/validation.ts';
import { useApi, useApiStatus } from '../state/api.ts';
import { usePolicy } from '../state/policyState.ts';
import { usePreferences } from '../state/preferences.ts';
import { useSession } from '../state/session.ts';

type InputMode = 'paste' | 'file';

interface LoadedFile {
  name: string;
  parsed: ParsedBatch;
}

interface BatchView {
  source: DataSource;
  prefix: string;
  batch: BatchResponse;
  records: AnalysisRecord[];
  breachMode?: BreachMode;
  reuseDatasets?: string[];
}

const LABEL_MAX = 64;

/**
 * Audit many passwords at once.
 *
 * Secret handling: pasted text and parsed entries are held in component state only. A password
 * file is read into memory, parsed and never displayed. Entries are sent in one POST body and
 * cleared after success (unless the user opted to keep them). Results, the session history and
 * exports hold scores and finding kinds only.
 */
export default function BatchPage() {
  const client = useApi();
  const { limits, capabilities } = useApiStatus();
  const { policy } = usePolicy();
  const { keepPassword } = usePreferences();
  const session = useSession();

  const [mode, setMode] = useState<InputMode>('paste');
  const [format, setFormat] = useState<BatchInputFormat>('lines');
  const [text, setText] = useState('');
  const [loadedFile, setLoadedFile] = useState<LoadedFile | null>(null);
  const [fileProblem, setFileProblem] = useState<string | null>(null);
  const [context, setContext] = useState<ContextValue>(EMPTY_CONTEXT);
  const [exposure, setExposure] = useState<ExposureOptions>(NO_EXPOSURE);
  const [personalError, setPersonalError] = useState<string | null>(null);
  const [inputError, setInputError] = useState<string | null>(null);
  const [view, setView] = useState<BatchView | null>(null);
  const [selected, setSelected] = useState<AnalysisRecord | null>(null);
  const action = useAsyncAction<BatchResponse>();

  const resultHeading = useRef<HTMLHeadingElement>(null);
  const loading = action.state.status === 'loading';

  const parsed = useMemo<ParsedBatch>(
    () =>
      mode === 'file'
        ? (loadedFile?.parsed ?? { entries: [], skipped: 0, error: null })
        : parseBatchInput(text, format),
    [mode, loadedFile, text, format],
  );

  useEffect(() => {
    if (view) resultHeading.current?.focus();
  }, [view]);

  async function onFile(file: File): Promise<void> {
    setFileProblem(null);
    setInputError(null);
    if (file.size > limits.batch_max_body_bytes) {
      setLoadedFile(null);
      setFileProblem(
        `That file is larger than the ${String(Math.round(limits.batch_max_body_bytes / 1024))} KiB the service accepts.`,
      );
      return;
    }
    try {
      const content = await file.text();
      const kind: BatchInputFormat = /\.csv$/i.test(file.name) ? 'csv' : 'lines';
      setFormat(kind);
      setLoadedFile({ name: file.name, parsed: parseBatchInput(content, kind) });
    } catch {
      setLoadedFile(null);
      setFileProblem('That file could not be read.');
    }
  }

  function changeFormat(next: BatchInputFormat): void {
    setFormat(next);
    setInputError(null);
    // A loaded file's text is not kept, so it cannot be re-parsed: the user picks the file again.
    if (mode === 'file') setLoadedFile(null);
  }

  async function submit(event?: SyntheticEvent): Promise<void> {
    event?.preventDefault();
    if (loading) return;
    const personal = parsePersonalInfo(context.personalText, limits);
    setPersonalError(personal.error);
    const problem = parsed.error ?? validateBatchEntries(parsed.entries, limits);
    setInputError(problem);
    if (problem || personal.error) return;

    const body: BatchRequest = {
      items: parsed.entries.map((entry: BatchEntry) => ({
        id: entry.label.slice(0, LABEL_MAX),
        password: entry.password,
      })),
      policy,
      context: { usage: context.usage, personal_info: personal.items },
      detail: 'full',
      ...exposureField(exposure),
    };
    const batch = await action.run((signal) => client.batch(body, signal));
    if (!batch) return;

    const prefix = nextRunPrefix('b');
    const records = recordsFromBatch(prefix, batch);
    const title = `Batch of ${plural(batch.count, 'password')}`;
    session.addRun({
      kind: 'batch',
      title,
      records,
      usage: context.usage,
      policy,
      summary: batch.summary,
    });
    setView({
      source: 'live',
      prefix,
      batch,
      records,
      breachMode: exposure.breach,
      ...(exposure.reuse && capabilities
        ? { reuseDatasets: capabilities.reuse_index.datasets }
        : {}),
    });
    setSelected(null);
    if (!keepPassword) {
      setText('');
      setLoadedFile(null);
    }
  }

  function showDemo(): void {
    action.cancel();
    setView({
      source: 'demo',
      prefix: 'demo',
      batch: demo.batch,
      records: recordsFromBatch('demo', demo.batch),
    });
    setSelected(null);
  }

  function clearAll(): void {
    action.cancel();
    setText('');
    setLoadedFile(null);
    setFileProblem(null);
    setInputError(null);
    setPersonalError(null);
    setContext(EMPTY_CONTEXT);
    setExposure(NO_EXPOSURE);
    setView(null);
    setSelected(null);
  }

  const detail = useMemo(() => {
    if (!view || !selected) return null;
    return (
      view.batch.results.find((item) => `${view.prefix}-${String(item.index)}` === selected.id)
        ?.analysis ?? null
    );
  }, [view, selected]);

  const stats = useMemo(() => (view ? summarizeRecords(view.records) : null), [view]);
  const hasInput = text !== '' || loadedFile !== null || view !== null;
  const count = parsed.entries.length;

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="Workspace"
        title="Batch"
        description="Audit many passwords at once and see the picture across all of them."
      />
      <ConnectionNotice />

      <Card as="section" aria-labelledby="batch-form-h">
        <CardTitle id="batch-form-h" level={2}>
          Passwords to audit
        </CardTitle>
        <CardDescription>
          Up to {limits.batch_max_items} passwords per batch. They are analysed by the local
          service, never stored or logged, and cleared from this page after the audit. Identical
          passwords are flagged as reused.
        </CardDescription>
        <form
          onSubmit={(event) => void submit(event)}
          noValidate
          autoComplete="off"
          aria-busy={loading || undefined}
          className="mt-5 grid grid-cols-1 gap-6 lg:grid-cols-2"
        >
          <div className="space-y-4">
            <div className="flex flex-wrap gap-4">
              <SegmentedControl
                legend="Input"
                value={mode}
                onChange={(next) => {
                  setMode(next);
                  setInputError(null);
                }}
                options={[
                  { value: 'paste', label: 'Paste' },
                  { value: 'file', label: 'Upload file' },
                ]}
              />
              <SegmentedControl
                legend="Input format"
                value={format}
                onChange={changeFormat}
                options={[
                  { value: 'lines', label: 'One per line' },
                  { value: 'csv', label: 'CSV' },
                ]}
              />
            </div>

            {mode === 'paste' ? (
              <Field
                label="Passwords"
                hint={
                  format === 'csv'
                    ? 'CSV with a header row: a "password" column and an optional "label" column.'
                    : 'One password per line. Blank lines are skipped.'
                }
                error={inputError ?? undefined}
                required
              >
                <Textarea
                  rows={8}
                  value={text}
                  name="batch-secrets"
                  disabled={loading}
                  autoComplete="off"
                  autoCapitalize="off"
                  autoCorrect="off"
                  spellCheck={false}
                  wrap="off"
                  className="font-mono"
                  onChange={(event) => {
                    setText(event.target.value);
                    if (inputError) setInputError(null);
                  }}
                />
              </Field>
            ) : (
              <div className="space-y-3">
                <FileDrop
                  label="Choose a .txt or .csv file"
                  hint="Read in your browser; the contents are not shown and never leave this machine except to the local service."
                  accept=".txt,.csv,text/plain,text/csv"
                  disabled={loading}
                  onFile={(file) => void onFile(file)}
                />
                {fileProblem && <Alert tone="danger">{fileProblem}</Alert>}
                {loadedFile && (
                  <p className="text-sm text-fg-muted" role="status">
                    Loaded <strong className="font-semibold text-fg">{loadedFile.name}</strong>
                    {loadedFile.parsed.error
                      ? '.'
                      : `: ${plural(loadedFile.parsed.entries.length, 'password')} ready.`}
                  </p>
                )}
                {inputError && <Alert tone="danger">{inputError}</Alert>}
              </div>
            )}

            {mode === 'paste' && text !== '' && !parsed.error && (
              <p className="tabular text-sm text-fg-muted" role="status">
                {plural(count, 'password')} detected
                {parsed.skipped > 0 ? ` (${plural(parsed.skipped, 'blank line')} skipped)` : ''}.
              </p>
            )}
            <PolicyNotice />
          </div>

          <div className="space-y-6">
            <ContextFields
              value={context}
              onChange={setContext}
              personalError={personalError}
              disabled={loading}
              showReused={false}
            />
            <ExposureFields
              value={exposure}
              onChange={setExposure}
              disabled={loading}
              subject="passwords"
            />
          </div>

          <div className="flex flex-wrap items-center gap-3 lg:col-span-2">
            <Button
              type="submit"
              loading={loading}
              leadingIcon={<FileSpreadsheet aria-hidden="true" className="size-4" />}
            >
              {loading
                ? 'Auditing...'
                : count > 0
                  ? `Audit ${plural(count, 'password')}`
                  : 'Audit passwords'}
            </Button>
            <Button
              variant="ghost"
              onClick={clearAll}
              disabled={!hasInput && action.state.status !== 'error'}
              leadingIcon={<Trash2 aria-hidden="true" className="size-4" />}
            >
              Clear passwords and results
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
        aria-labelledby="batch-result-h"
        aria-busy={loading || undefined}
        className="space-y-4"
      >
        {view || loading ? (
          <h2
            id="batch-result-h"
            ref={resultHeading}
            tabIndex={-1}
            className="text-xl font-semibold outline-none"
          >
            {loading ? 'Auditing...' : 'Results'}
          </h2>
        ) : (
          <h2 id="batch-result-h" className="sr-only">
            Results
          </h2>
        )}

        {loading && (
          <Card>
            <Progress label="Auditing passwords" className="mb-4" />
            <SkeletonText lines={5} />
          </Card>
        )}

        {!loading && view && stats && (
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
              Audit complete: {plural(view.batch.count, 'password')} analysed.
            </p>
            <SummaryPanel stats={stats} />
            <Card>
              <CardTitle level={3} className="mb-4 text-base">
                All passwords
              </CardTitle>
              <ResultsTable
                key={view.prefix}
                records={view.records}
                label="Audit results"
                onSelect={setSelected}
              />
            </Card>
            <Card>
              <ExportPanel
                title={view.source === 'demo' ? 'Demo batch audit' : 'Batch audit'}
                kind="batch"
                source={view.source}
                records={view.records}
                summary={view.batch.summary}
                breachMode={view.breachMode ?? 'off'}
                reuseDatasets={view.reuseDatasets}
                defaultName="passaudit-batch"
                headingLevel={3}
              />
            </Card>
          </>
        )}
      </section>

      <Dialog
        open={selected !== null}
        onClose={() => {
          setSelected(null);
        }}
        title={selected?.label ?? 'Details'}
        description="Scores and findings only - the password itself is never shown or stored."
        size="lg"
      >
        {selected && <RecordDetail record={selected} analysis={detail} />}
      </Dialog>
    </div>
  );
}
