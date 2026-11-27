import axe from 'axe-core';
import type { AxeResults, RunOptions } from 'axe-core';

const normalise = (text: string): string => text.replace(/\s+/g, ' ').trim().toLowerCase();

/**
 * WCAG 2.5.3 "Label in Name": when a control shows text *and* has an `aria-label`, the label
 * must contain that text, or voice-control users cannot say what they see ("click Use preset"
 * must reach a button labelled "Use preset: Strict", not "Use the Strict preset").
 *
 * axe-core has this rule (`label-content-name-mismatch`) but it is experimental and needs a
 * layout engine, so it never fires in jsdom. A real-browser axe run found two violations; this
 * is the equivalent check for the test suite.
 */
export function labelInNameMismatches(container: Element): string[] {
  const problems: string[] = [];
  for (const el of container.querySelectorAll('button, a[href], [role="button"], [role="link"]')) {
    const label = el.getAttribute('aria-label');
    const visible = normalise(el.textContent);
    // Skip icon-only controls (their text is empty) and symbol-only glyphs.
    if (!label || !/[\p{L}\p{N}]/u.test(visible)) continue;
    if (!normalise(label).includes(visible)) {
      problems.push(`aria-label "${label}" does not contain the visible text "${visible}"`);
    }
  }
  return problems;
}

/**
 * Run axe-core on a rendered container and fail with a readable list of violations.
 *
 * `color-contrast` is disabled because jsdom has no layout/paint engine, so axe cannot compute
 * it; contrast is instead verified from the design tokens in src/styles/tokens.test.ts and
 * in a real browser. `region` is off for component fragments (they are not whole pages).
 */
export async function expectNoA11yViolations(
  container: Element,
  options: { page?: boolean } = {},
): Promise<void> {
  const runOptions: RunOptions = {
    rules: {
      'color-contrast': { enabled: false },
      region: { enabled: options.page === true },
    },
  };
  const results: AxeResults = await axe.run(container, runOptions);
  const summary = [
    ...results.violations.map(
      (v) =>
        `${v.id} (${v.impact ?? 'n/a'}): ${v.help}\n` +
        v.nodes.map((n) => `    ${n.html.slice(0, 120)}`).join('\n'),
    ),
    ...labelInNameMismatches(container).map((p) => `label-in-name: ${p}`),
  ];
  expect(summary, `accessibility violations:\n${summary.join('\n')}`).toEqual([]);
}
