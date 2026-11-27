import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

type RGB = readonly [number, number, number];
type Palette = Record<string, RGB>;

// vitest runs with the frontend package as the working directory.
const css = readFileSync(resolve(process.cwd(), 'src/styles/tokens.css'), 'utf-8');

/** Extract `--name: r g b;` declarations from the first block that starts with `selector`. */
function parseBlock(selector: string): Palette {
  const start = css.indexOf(selector);
  if (start === -1) throw new Error(`selector not found: ${selector}`);
  const open = css.indexOf('{', start);
  const close = css.indexOf('}', open);
  const block = css.slice(open + 1, close);
  const palette: Palette = {};
  for (const match of block.matchAll(/--([a-z0-9-]+):\s*(\d+)\s+(\d+)\s+(\d+)\s*;/g)) {
    const [, name, r, g, b] = match;
    if (name && r && g && b) palette[name] = [Number(r), Number(g), Number(b)];
  }
  return palette;
}

const THEMES: Record<string, Palette> = {
  dark: parseBlock(":root[data-theme='dark']"),
  light: parseBlock(":root[data-theme='light']"),
};

function channel(value: number): number {
  const v = value / 255;
  return v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4;
}

function luminance([r, g, b]: RGB): number {
  return 0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b);
}

/** WCAG 2.x contrast ratio between two opaque colours. */
function contrast(a: RGB, b: RGB): number {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x) as [number, number];
  return (hi + 0.05) / (lo + 0.05);
}

/** Composite `fg` at `alpha` over `bg`. */
function blend(fg: RGB, bg: RGB, alpha: number): RGB {
  return [0, 1, 2].map((i) =>
    Math.round(fg[i as 0] * alpha + bg[i as 0] * (1 - alpha)),
  ) as unknown as RGB;
}

function get(palette: Palette, name: string): RGB {
  const value = palette[name];
  if (!value) throw new Error(`token --${name} missing`);
  return value;
}

describe('design token files', () => {
  it('defines the same set of tokens for light and dark', () => {
    expect(Object.keys(THEMES.light ?? {}).sort()).toEqual(Object.keys(THEMES.dark ?? {}).sort());
  });

  it('keeps the brand colours: neon green primary, purple and cyan accents (dark)', () => {
    const dark = THEMES.dark;
    if (!dark) throw new Error('dark theme missing');
    const [pr, pg, pb] = get(dark, 'primary');
    expect(pg).toBeGreaterThan(220); // neon green
    expect(pg).toBeGreaterThan(pr);
    expect(pg).toBeGreaterThan(pb);
    expect(get(dark, 'purple')[2]).toBeGreaterThan(200);
    expect(get(dark, 'cyan')[2]).toBeGreaterThan(200);
    expect(luminance(get(dark, 'canvas'))).toBeLessThan(0.01); // near-black
  });
});

describe.each(Object.entries(THEMES))('WCAG contrast - %s theme', (_theme, palette) => {
  const surfaces = ['canvas', 'surface', 'surface-2', 'surface-3'] as const;
  const accents = ['primary', 'purple', 'cyan', 'success', 'warning', 'danger'] as const;

  it.each(surfaces)('body text (fg) is AAA (>= 7:1) on %s', (surface) => {
    expect(contrast(get(palette, 'fg'), get(palette, surface))).toBeGreaterThanOrEqual(7);
  });

  it.each(surfaces)('muted text (fg-muted) is AA (>= 4.5:1) on %s', (surface) => {
    expect(contrast(get(palette, 'fg-muted'), get(palette, surface))).toBeGreaterThanOrEqual(4.5);
  });

  it.each(['canvas', 'surface', 'surface-2'] as const)(
    'subtle text (fg-subtle: placeholders, captions) is AA on %s',
    (surface) => {
      expect(contrast(get(palette, 'fg-subtle'), get(palette, surface))).toBeGreaterThanOrEqual(
        4.5,
      );
    },
  );

  it.each(accents)('%s is readable as text on canvas and surface (>= 4.5:1)', (accent) => {
    for (const surface of ['canvas', 'surface', 'surface-2'] as const) {
      expect(contrast(get(palette, accent), get(palette, surface))).toBeGreaterThanOrEqual(4.5);
    }
  });

  it.each(['primary', 'success', 'warning', 'danger'] as const)(
    'on-primary text is readable on a solid %s button (>= 4.5:1)',
    (accent) => {
      expect(contrast(get(palette, 'on-primary'), get(palette, accent))).toBeGreaterThanOrEqual(
        4.5,
      );
    },
  );

  it.each(accents)('tinted badge: %s text on its /15 fill stays AA on every surface', (accent) => {
    for (const surface of ['canvas', 'surface', 'surface-2'] as const) {
      const fill = blend(get(palette, accent), get(palette, surface), 0.15);
      expect(contrast(get(palette, accent), fill)).toBeGreaterThanOrEqual(4.5);
    }
  });

  it.each(accents)(
    'alert: %s text on its /10 tint stays AA, and muted text beside it too',
    (accent) => {
      for (const surface of ['canvas', 'surface'] as const) {
        const tint = blend(get(palette, accent), get(palette, surface), 0.1);
        expect(contrast(get(palette, accent), tint)).toBeGreaterThanOrEqual(4.5);
        expect(contrast(get(palette, 'fg-muted'), tint)).toBeGreaterThanOrEqual(4.5);
      }
    },
  );

  it('neutral badge: muted text on the fg/10 fill is AA', () => {
    for (const surface of ['canvas', 'surface'] as const) {
      const fill = blend(get(palette, 'fg'), get(palette, surface), 0.1);
      expect(contrast(get(palette, 'fg-muted'), fill)).toBeGreaterThanOrEqual(4.5);
    }
  });

  it('active nav item: fg on primary/10 is AAA', () => {
    const fill = blend(get(palette, 'primary'), get(palette, 'surface'), 0.1);
    expect(contrast(get(palette, 'fg'), fill)).toBeGreaterThanOrEqual(7);
  });

  it.each(surfaces)(
    'focus ring is a visible indicator (>= 3:1) on %s (WCAG 2.2 non-text)',
    (surface) => {
      expect(contrast(get(palette, 'ring'), get(palette, surface))).toBeGreaterThanOrEqual(3);
    },
  );

  it('on-primary text is readable on the primary gradient end (cyan) as well', () => {
    expect(contrast(get(palette, 'on-primary'), get(palette, 'cyan'))).toBeGreaterThanOrEqual(3);
  });
});

describe('contrast helper', () => {
  it('matches the WCAG reference values', () => {
    expect(contrast([0, 0, 0], [255, 255, 255])).toBeCloseTo(21, 5);
    expect(contrast([255, 255, 255], [255, 255, 255])).toBeCloseTo(1, 5);
    expect(contrast([119, 119, 119], [255, 255, 255])).toBeCloseTo(4.48, 1); // #777 on white
  });

  it('blends with alpha', () => {
    expect(blend([255, 255, 255], [0, 0, 0], 0.5)).toEqual([128, 128, 128]);
    expect(blend([10, 20, 30], [200, 200, 200], 0)).toEqual([200, 200, 200]);
    expect(blend([10, 20, 30], [200, 200, 200], 1)).toEqual([10, 20, 30]);
  });
});
