/**
 * The Content-Security-Policy PassAudit's built frontend is served with.
 *
 * Everything is same-origin: no CDN, no analytics, no inline scripts, no `eval`. The two font
 * families are bundled (`@fontsource`), and the theme bootstrap is a same-origin file.
 *
 * - `connect-src 'self'` is the privacy-critical directive: a password can only be sent to this
 *   origin (which proxies `/api`), never to a third party.
 * - `style-src 'self'` still allows React's `style={...}` props, which are applied through the
 *   CSSOM rather than as inline `style` attributes in markup.
 * - `data:` / `blob:` images and `data:` fonts cover assets Vite inlines and chart exports.
 */

const DIRECTIVES: readonly string[] = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self' data: blob:",
  "font-src 'self' data:",
  "connect-src 'self'",
  "base-uri 'none'",
  "form-action 'none'",
  "object-src 'none'",
];

/** The full header value. `frame-ancestors` is only honoured in a real header, not a meta tag. */
export const CONTENT_SECURITY_POLICY = [...DIRECTIVES, "frame-ancestors 'none'"].join('; ');

/** The subset a `<meta http-equiv>` tag may carry (it ignores `frame-ancestors`). */
export const META_CONTENT_SECURITY_POLICY = DIRECTIVES.join('; ');
