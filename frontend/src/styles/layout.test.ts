import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';

/**
 * jsdom has no layout engine, so layout bugs cannot be caught by rendering. This guards the one
 * that a real-browser check found: `grid gap-6 lg:grid-cols-2` has an implicit single column
 * sized by its widest content, so a wide preview (a code block, a table) stretched the whole
 * page sideways on phones. `grid-cols-1` is `minmax(0, 1fr)`, which lets content shrink.
 */
const SRC = resolve(process.cwd(), 'src');

function sources(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) return sources(path);
    return name.endsWith('.tsx') && !name.includes('.test.') ? [path] : [];
  });
}

describe('responsive grids', () => {
  it('always give the mobile layout an explicit shrinkable column', () => {
    const offenders: string[] = [];
    for (const file of sources(SRC)) {
      const text = readFileSync(file, 'utf-8');
      for (const match of text.matchAll(/className=(?:"([^"]*)"|\{`([^`]*)`\})/g)) {
        const classes = (match[1] ?? match[2] ?? '').split(/\s+/);
        const isGrid = classes.includes('grid');
        const responsive = classes.some((c) => /^(sm|md|lg|xl|2xl):grid-cols-/.test(c));
        const base = classes.some((c) => c.startsWith('grid-cols-'));
        if (isGrid && responsive && !base) offenders.push(`${relative(SRC, file)}: ${match[0]}`);
      }
    }
    expect(offenders, `add "grid-cols-1" to:\n${offenders.join('\n')}`).toEqual([]);
  });
});
