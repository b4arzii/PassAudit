import { Download } from 'lucide-react';
import { useId, useState } from 'react';

import type { PolicyValidationResponse } from '../../api/types.ts';
import { buildPolicyReport, downloadText, safeFilename } from '../../lib/export.ts';
import type { ExportFormat } from '../../lib/export.ts';
import { POLICY_RULE_LABEL } from '../../lib/labels.ts';
import type { DataSource } from '../../lib/records.ts';
import {
  Alert,
  Badge,
  Button,
  CopyButton,
  Field,
  Input,
  SegmentedControl,
  TBody,
  TD,
  TH,
  THead,
  TR,
  Table,
  useToast,
} from '../ui/index.ts';

export interface PolicyResultProps {
  result: PolicyValidationResponse;
  policy: Record<string, unknown>;
  source: DataSource;
}

/** The rule-by-rule outcome of a policy check, with a sanitised export of it. */
export function PolicyResult({ result, policy, source }: PolicyResultProps) {
  const toast = useToast();
  const id = useId();
  const [format, setFormat] = useState<ExportFormat>('json');
  const [name, setName] = useState('passaudit-policy-check');
  const filename = safeFilename(name, format, source);
  const failed = result.rules.filter((r) => r.status === 'fail').length;
  const unchecked = result.rules.filter((r) => r.status === 'unchecked').length;

  function build(): string {
    return buildPolicyReport(
      {
        title: source === 'demo' ? 'Demo policy check' : 'Policy check',
        source,
        generatedAt: new Date(),
        policy,
        result,
      },
      format,
    );
  }

  return (
    <div className="space-y-5">
      <Alert
        tone={result.compliant ? 'success' : 'danger'}
        title={
          result.compliant
            ? 'Policy satisfied'
            : `${String(failed)} of ${String(result.rules.length)} rules failed`
        }
      >
        {result.compliant
          ? `This ${String(result.length)}-character password meets every rule that was checked.`
          : `This ${String(result.length)}-character password breaks the rules marked "Fail" below.`}
        {unchecked > 0 &&
          ` ${String(unchecked)} rule${unchecked === 1 ? ' was' : 's were'} not checked: ${unchecked === 1 ? 'it needs' : 'they need'} an opt-in breach check, which was not run.`}
      </Alert>

      <Table label="Rule results" caption="Each enabled rule and whether the password meets it">
        <THead>
          <TR>
            <TH>Rule</TH>
            <TH className="hidden sm:table-cell">Requirement</TH>
            <TH>Result</TH>
            <TH className="hidden md:table-cell">Detail</TH>
          </TR>
        </THead>
        <TBody>
          {result.rules.map((rule) => (
            <TR key={rule.rule}>
              <TD className="font-medium">{POLICY_RULE_LABEL[rule.rule]}</TD>
              <TD className="hidden text-fg-muted sm:table-cell">{rule.requirement}</TD>
              <TD>
                <Badge
                  tone={
                    rule.status === 'pass'
                      ? 'success'
                      : rule.status === 'fail'
                        ? 'danger'
                        : 'neutral'
                  }
                  size="sm"
                  dot
                >
                  {rule.status === 'pass'
                    ? 'Pass'
                    : rule.status === 'fail'
                      ? 'Fail'
                      : 'Not checked'}
                </Badge>
              </TD>
              <TD className="hidden text-fg-muted md:table-cell">{rule.message ?? ''}</TD>
            </TR>
          ))}
        </TBody>
      </Table>

      <section aria-labelledby={`${id}-h`} className="space-y-3">
        <h3 id={`${id}-h`} className="text-base font-semibold">
          Export this check
        </h3>
        <div className="flex flex-wrap items-end gap-4">
          <SegmentedControl
            legend="Report format"
            value={format}
            onChange={setFormat}
            options={[
              { value: 'json', label: 'JSON' },
              { value: 'csv', label: 'CSV' },
            ]}
          />
          <Field
            label="File name"
            hint={`Will be saved as ${filename}`}
            className="min-w-56 flex-1"
          >
            <Input
              value={name}
              maxLength={120}
              onChange={(event) => {
                setName(event.target.value);
              }}
            />
          </Field>
        </div>
        <div className="flex flex-wrap gap-3">
          <Button
            leadingIcon={<Download aria-hidden="true" className="size-4" />}
            onClick={() => {
              downloadText(build(), filename, format);
              toast.success(
                'Report downloaded',
                `${filename} was saved by your browser. Nothing was uploaded.`,
              );
            }}
          >
            Download {format.toUpperCase()}
          </Button>
          <CopyButton getText={build} label="Copy to clipboard" />
        </div>
        <p className="text-xs text-fg-muted">
          Sanitized: rule outcomes and the policy only - never the password or personal details.
        </p>
      </section>
    </div>
  );
}
