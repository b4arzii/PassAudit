/** Drop a leading byte-order mark (files saved by Excel and Notepad often have one). */
function stripBom(text: string): string {
  return text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;
}

/**
 * Minimal RFC 4180 CSV parser for batch input (quotes, escaped quotes, embedded commas and
 * newlines, CRLF). It runs entirely in the browser; the text it parses may contain passwords,
 * so errors report only row numbers - never content.
 */
export function parseCsv(text: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let cell = '';
  let quoted = false;
  const source = stripBom(text);
  for (let i = 0; i < source.length; i++) {
    const ch = source.charAt(i);
    if (quoted) {
      if (ch === '"') {
        if (source[i + 1] === '"') {
          cell += '"';
          i++;
        } else quoted = false;
      } else cell += ch;
    } else if (ch === '"' && cell === '') quoted = true;
    else if (ch === ',') {
      row.push(cell);
      cell = '';
    } else if (ch === '\n' || ch === '\r') {
      if (ch === '\r' && source[i + 1] === '\n') i++;
      row.push(cell);
      rows.push(row);
      row = [];
      cell = '';
    } else cell += ch;
  }
  if (cell !== '' || row.length > 0) {
    row.push(cell);
    rows.push(row);
  }
  return rows;
}

export interface BatchEntry {
  /** 1-based line (or CSV record) number in the input. */
  line: number;
  label: string;
  password: string;
}

export type BatchInputFormat = 'lines' | 'csv';

export interface ParsedBatch {
  entries: BatchEntry[];
  /** Blank lines / empty password cells that were skipped. */
  skipped: number;
  /** A problem with the input as a whole (e.g. no `password` column). */
  error: string | null;
}

/**
 * Parse pasted or uploaded text into batch entries.
 *  - `lines`: one password per line; blank lines are skipped; surrounding spaces are kept.
 *  - `csv`: a header row with a `password` column and an optional `label` column.
 */
export function parseBatchInput(text: string, format: BatchInputFormat): ParsedBatch {
  if (format === 'lines') {
    const entries: BatchEntry[] = [];
    let skipped = 0;
    stripBom(text)
      .split(/\r\n|\n|\r/)
      .forEach((password, index) => {
        if (password === '') skipped += 1;
        else
          entries.push({ line: index + 1, label: `Row ${String(entries.length + 1)}`, password });
      });
    return { entries, skipped, error: null };
  }

  const rows = parseCsv(text);
  const header = rows[0]?.map((h) => h.trim().toLowerCase());
  if (!header || header.length === 0 || (header.length === 1 && header[0] === '')) {
    return { entries: [], skipped: 0, error: 'The CSV is empty or has no header row.' };
  }
  const passwordColumn = header.indexOf('password');
  if (passwordColumn === -1) {
    // Deliberately does not list the header: for a plain password list it *is* a password.
    return {
      entries: [],
      skipped: 0,
      error: 'The CSV needs a "password" column in its header row.',
    };
  }
  const labelColumn = header.indexOf('label');
  const entries: BatchEntry[] = [];
  let skipped = 0;
  rows.slice(1).forEach((cells, index) => {
    const password = cells[passwordColumn] ?? '';
    if (password === '') {
      skipped += 1;
      return;
    }
    const label = labelColumn >= 0 ? (cells[labelColumn] ?? '').trim() : '';
    entries.push({
      line: index + 2,
      label: label === '' ? `Row ${String(entries.length + 1)}` : label,
      password,
    });
  });
  return { entries, skipped, error: null };
}
