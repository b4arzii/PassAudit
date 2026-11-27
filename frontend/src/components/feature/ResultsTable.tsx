import { Repeat2, Search } from 'lucide-react';
import { useMemo, useState } from 'react';

import type { RiskLevel } from '../../api/types.ts';
import { FINDING_LABEL, RISK_LABEL, RISK_ORDER, riskTone } from '../../lib/labels.ts';
import { paginate } from '../../lib/paginate.ts';
import type { AnalysisRecord } from '../../lib/records.ts';
import { DEFAULT_QUERY, filterAndSort, isDefaultFilter } from '../../lib/tableData.ts';
import type { SortKey, TableQuery } from '../../lib/tableData.ts';
import {
  Badge,
  Button,
  Field,
  Input,
  Pagination,
  Select,
  TBody,
  TD,
  TH,
  THead,
  TR,
  Table,
  TableEmpty,
} from '../ui/index.ts';

const PAGE_SIZE = 10;

export interface ResultsTableProps {
  records: readonly AnalysisRecord[];
  /** Called when a row's label button is activated. */
  onSelect: (record: AnalysisRecord) => void;
  /** Accessible name for the table. */
  label: string;
  className?: string;
}

/**
 * The audit result table: search, risk and policy filters, sortable columns, pagination.
 * Secondary columns drop away on narrow screens; every row stays reachable through its
 * label button, which opens the detail view. Give it a `key` that changes with the dataset so a
 * new dataset starts on the first page.
 */
export function ResultsTable({ records, onSelect, label, className }: ResultsTableProps) {
  const [query, setQuery] = useState<TableQuery>(DEFAULT_QUERY);
  const [page, setPage] = useState(1);

  const rows = useMemo(() => filterAndSort(records, query), [records, query]);
  const visible = paginate(rows, page, PAGE_SIZE);

  function update(patch: Partial<TableQuery>): void {
    setQuery((q) => ({ ...q, ...patch }));
    setPage(1); // a filter change starts again from the first page
  }
  function sortBy(key: SortKey): void {
    setPage(1);
    setQuery((q) => ({
      ...q,
      sortKey: key,
      sortDir: q.sortKey === key && q.sortDir === 'descending' ? 'ascending' : 'descending',
    }));
  }
  const dir = (key: SortKey) => (query.sortKey === key ? query.sortDir : 'none');

  return (
    <div className={className}>
      <div className="mb-4 grid grid-cols-1 gap-3 sm:grid-cols-[1fr_auto_auto]">
        <Field label="Search results" hideLabel>
          <Input
            type="search"
            placeholder="Search by label"
            leadingIcon={<Search />}
            value={query.text}
            onChange={(e) => {
              update({ text: e.target.value });
            }}
          />
        </Field>
        <Field label="Risk level" hideLabel>
          <Select
            value={query.level}
            onChange={(e) => {
              update({ level: e.target.value as RiskLevel | 'all' });
            }}
          >
            <option value="all">All risk levels</option>
            {RISK_ORDER.map((level) => (
              <option key={level} value={level}>
                {RISK_LABEL[level]} risk
              </option>
            ))}
          </Select>
        </Field>
        <Field label="Policy result" hideLabel>
          <Select
            value={query.policy}
            onChange={(e) => {
              update({ policy: e.target.value as TableQuery['policy'] });
            }}
          >
            <option value="all">Any policy result</option>
            <option value="pass">Policy met</option>
            <option value="fail">Policy broken</option>
          </Select>
        </Field>
      </div>

      <Table
        label={label}
        caption={`${label}: ${String(rows.length)} of ${String(records.length)} shown`}
      >
        <THead>
          <TR>
            <TH
              sort={dir('label')}
              onSort={() => {
                sortBy('label');
              }}
            >
              Label
            </TH>
            <TH
              sort={dir('risk')}
              onSort={() => {
                sortBy('risk');
              }}
            >
              Risk
            </TH>
            <TH
              sort={dir('strength')}
              onSort={() => {
                sortBy('strength');
              }}
            >
              Strength
            </TH>
            <TH
              sort={dir('bits')}
              onSort={() => {
                sortBy('bits');
              }}
              className="hidden md:table-cell"
            >
              Entropy
            </TH>
            <TH className="hidden lg:table-cell">Patterns</TH>
            <TH>Policy</TH>
          </TR>
        </THead>
        <TBody>
          {visible.length === 0 ? (
            <TableEmpty colSpan={6}>
              No results match these filters.{' '}
              {!isDefaultFilter(query) && (
                <Button
                  size="sm"
                  variant="ghost"
                  onClick={() => {
                    setQuery(DEFAULT_QUERY);
                    setPage(1);
                  }}
                >
                  Clear filters
                </Button>
              )}
            </TableEmpty>
          ) : (
            visible.map((r) => (
              <TR key={r.id}>
                <TD>
                  <button
                    type="button"
                    onClick={() => {
                      onSelect(r);
                    }}
                    aria-label={`Open details for ${r.label}`}
                    className="-mx-2 inline-flex max-w-[16rem] items-center gap-2 rounded-lg px-2 py-1.5 text-left font-medium text-fg underline decoration-line/30 underline-offset-4 transition-colors hover:decoration-primary"
                  >
                    <span className="truncate">{r.label}</span>
                  </button>
                  {r.breach === 'breached' && (
                    <Badge tone="danger" size="sm" className="ml-1">
                      Breached
                    </Badge>
                  )}
                  {r.breach === 'unavailable' && (
                    <Badge tone="warning" size="sm" className="ml-1">
                      Unchecked
                    </Badge>
                  )}
                  {r.reuse_datasets !== null && r.reuse_datasets.length > 0 && (
                    <Badge tone="warning" size="sm" className="ml-1">
                      In datasets
                    </Badge>
                  )}
                  {r.reused && (
                    <Badge
                      tone="warning"
                      size="sm"
                      className="ml-1"
                      icon={<Repeat2 aria-hidden="true" className="size-3" />}
                    >
                      Reused
                    </Badge>
                  )}
                </TD>
                <TD>
                  <span className="tabular mr-2 font-semibold">{r.risk_score}</span>
                  <Badge tone={riskTone(r.risk_level)} size="sm" outline={r.risk_level === 'high'}>
                    {RISK_LABEL[r.risk_level]}
                  </Badge>
                </TD>
                <TD className="tabular whitespace-nowrap">{r.strength_score}/4</TD>
                <TD className="tabular hidden text-fg-muted md:table-cell">
                  {Math.round(r.estimated_bits)} bits
                </TD>
                <TD className="hidden lg:table-cell">
                  {r.findings.length === 0 ? (
                    <span className="text-fg-subtle">None</span>
                  ) : (
                    <span className="flex flex-wrap gap-1">
                      {r.findings.slice(0, 2).map((kind) => (
                        <Badge key={kind} size="sm">
                          {FINDING_LABEL[kind].short}
                        </Badge>
                      ))}
                      {r.findings.length > 2 && <Badge size="sm">+{r.findings.length - 2}</Badge>}
                    </span>
                  )}
                </TD>
                <TD>
                  <Badge tone={r.policy_compliant ? 'success' : 'danger'} size="sm" dot>
                    {r.policy_compliant ? 'Met' : 'Broken'}
                  </Badge>
                </TD>
              </TR>
            ))
          )}
        </TBody>
      </Table>
      <Pagination
        page={page}
        pageSize={PAGE_SIZE}
        total={rows.length}
        onPageChange={setPage}
        noun="passwords"
      />
    </div>
  );
}
