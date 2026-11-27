import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

import { CONTENT_SECURITY_POLICY, META_CONTENT_SECURITY_POLICY } from '../../csp.ts';

function directives(policy: string): Map<string, string[]> {
  return new Map(
    policy.split(';').map((part) => {
      const [name = '', ...values] = part.trim().split(/\s+/);
      return [name, values];
    }),
  );
}

describe('Content-Security-Policy of the built frontend', () => {
  const header = directives(CONTENT_SECURITY_POLICY);

  it('only lets the page talk to its own origin (the privacy-critical rule)', () => {
    expect(header.get('connect-src')).toEqual(["'self'"]);
    expect(header.get('default-src')).toEqual(["'none'"]);
  });

  it('allows no inline script, eval, or foreign script, and no plugins', () => {
    expect(header.get('script-src')).toEqual(["'self'"]);
    expect(header.get('object-src')).toEqual(["'none'"]);
    expect(CONTENT_SECURITY_POLICY).not.toMatch(/unsafe-inline|unsafe-eval|\*|https?:/);
  });

  it('forbids framing, <base> hijacking and form posts', () => {
    expect(header.get('frame-ancestors')).toEqual(["'none'"]);
    expect(header.get('base-uri')).toEqual(["'none'"]);
    expect(header.get('form-action')).toEqual(["'none'"]);
  });

  it('is the same policy the Docker web image sends (docker/nginx.conf)', () => {
    // vitest runs with the frontend package as the working directory.
    const conf = readFileSync(resolve(process.cwd(), '../docker/nginx.conf'), 'utf-8');
    const sent = /add_header Content-Security-Policy "([^"]+)"/.exec(conf)?.[1];
    expect(sent).toBe(CONTENT_SECURITY_POLICY);
  });

  it('the meta-tag variant is the same policy minus frame-ancestors (not allowed in a meta tag)', () => {
    const meta = directives(META_CONTENT_SECURITY_POLICY);
    expect(meta.has('frame-ancestors')).toBe(false);
    for (const [name, values] of header) {
      if (name !== 'frame-ancestors') expect(meta.get(name)).toEqual(values);
    }
  });
});
