import { Download, ShieldCheck } from 'lucide-react';
import { useId, useMemo, useState } from 'react';

import type { PasswordAnalysis } from '../../api/types.ts';
import { buildReport, downloadText, safeFilename } from '../../lib/export.ts';
import type { ExportFormat, ReportInput } from '../../lib/export.ts';
import type { AnalysisRecord, DataSource } from '../../lib/records.ts';
import {
  Alert,
  Button,
  Checkbox,
  CodeBlock,
  CopyButton,
  Field,
  Input,
  SegmentedControl,
  useToast,
} from '../ui/index.ts';
import { DemoBadge } from './DemoBanner.tsx';

export interface ExportPanelProps {
  title: string;
  kind: ReportInput['kind'];
  source: DataSource;
  records: readonly AnalysisRecord[];
  summary?: ReportInput['summary'];
  analysis?: PasswordAnalysis | undefined;
  /** Which external breach check ran (default off); recorded in the report, never data. */
  breachMode?: 'off' | 'local' | 'online';
  reuseDatasets?: readonly string[] | undefined;
  defaultName: string;
  /** Fixed clock for tests. */
  now?: () => Date;
  /** Heading level of the panel title. */
  headingLevel?: 2 | 3;
}

const PREVIEW_LINES = 24;

/**
 * The export interface: format, content options, file name (validated), a preview of exactly
 * what will be written, then Download or Copy. Reports are sanitised by construction (see
 * lib/export.ts) and demo reports are marked as such inside the file and in its name.
 */
export function ExportPanel({
  title,
  kind,
  source,
  records,
  summary,
  analysis,
  breachMode = 'off',
  reuseDatasets,
  defaultName,
  now = () => new Date(),
  headingLevel = 3,
}: ExportPanelProps) {
  const toast = useToast();
  const id = useId();
  const [format, setFormat] = useState<ExportFormat>('json');
  const [includeRecs, setIncludeRecs] = useState(true);
  const [includeFull, setIncludeFull] = useState(false);
  const [name, setName] = useState(defaultName);

  const filename = safeFilename(name, format, source);
  const changed =
    name.trim() !== '' &&
    filename.replace(/^demo-/, '') !== `${name.trim().replace(/\.(json|csv)$/i, '')}.${format}`;
  const Heading = `h${String(headingLevel)}` as 'h2' | 'h3';

  function build(): string {
    return buildReport(
      {
        title,
        kind,
        source,
        generatedAt: now(),
        records,
        summary,
        analysis: analysis && includeFull ? analysis : undefined,
        includeRecommendations: includeRecs,
        breachMode,
        reuseDatasets,
      },
      format,
    );
  }

  const preview = useMemo(() => {
    const lines = build().split('\n');
    const shown = lines.slice(0, PREVIEW_LINES).join('\n');
    return lines.length > PREVIEW_LINES
      ? `${shown}\n... (${String(lines.length - PREVIEW_LINES)} more lines in the file)`
      : shown;
    // eslint-disable-next-line react-hooks/exhaustive-deps -- `build` closes over exactly these values
  }, [
    format,
    includeRecs,
    includeFull,
    records,
    summary,
    analysis,
    title,
    source,
    kind,
    breachMode,
    reuseDatasets,
  ]);

  function onDownload(): void {
    downloadText(build(), filename, format);
    toast.success(
      'Report downloaded',
      `${filename} was saved by your browser. Nothing was uploaded.`,
    );
  }

  return (
    <section aria-labelledby={`${id}-h`} className="space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <Heading id={`${id}-h`} className="text-lg font-semibold">
          Export
        </Heading>
        {source === 'demo' && <DemoBadge />}
      </div>

      {source === 'demo' && (
        <Alert tone="info" title="This export will be marked as demo data">
          The file, every CSV row and the file name will say so, so it cannot be mistaken for a real
          audit.
        </Alert>
      )}

      <div className="grid grid-cols-1 gap-5 md:grid-cols-2">
        <div className="space-y-4">
          <SegmentedControl
            legend="Report format"
            value={format}
            onChange={setFormat}
            options={[
              { value: 'json', label: 'JSON' },
              { value: 'csv', label: 'CSV' },
            ]}
          />
          {format === 'json' && (
            <div className="space-y-3">
              <Checkbox
                label="Include recommendations"
                checked={includeRecs}
                onChange={(e) => {
                  setIncludeRecs(e.target.checked);
                }}
              />
              {analysis && (
                <Checkbox
                  label="Include the full analysis"
                  description="Adds strength, entropy, findings and risk detail."
                  checked={includeFull}
                  onChange={(e) => {
                    setIncludeFull(e.target.checked);
                  }}
                />
              )}
            </div>
          )}
          <Field
            label="File name"
            hint={
              changed
                ? `Will be saved as ${filename} (unsupported characters replaced).`
                : `Will be saved as ${filename}`
            }
          >
            <Input
              value={name}
              maxLength={120}
              onChange={(e) => {
                setName(e.target.value);
              }}
            />
          </Field>
          <div className="flex flex-wrap gap-3">
            <Button
              onClick={onDownload}
              leadingIcon={<Download aria-hidden="true" className="size-4" />}
              disabled={records.length === 0 && kind !== 'analysis'}
            >
              Download {format.toUpperCase()}
            </Button>
            <CopyButton getText={build} label="Copy to clipboard" />
          </div>
          <p className="flex items-start gap-2 text-xs text-fg-muted">
            <ShieldCheck aria-hidden="true" className="mt-0.5 size-4 shrink-0 text-primary" />
            Sanitized: contains scores, finding types and advice only - never passwords, hashes or
            personal information. The file is created in your browser.
          </p>
        </div>
        <div>
          <p className="mb-2 text-sm font-medium text-fg">Preview</p>
          <CodeBlock label={`${format.toUpperCase()} preview`} code={preview} />
        </div>
      </div>
    </section>
  );
}
