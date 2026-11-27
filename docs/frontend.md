# Frontend design system

> Status: design system **implemented in Phase 5**; connected to the API in **Phase 7**.
> Package: `frontend/` (React 19, TypeScript, Vite 7, Tailwind CSS 3, Lucide). It contains the
> application shell, a reusable component library and the Audit, Batch and Policies workspaces
> that call the local API - see [Connecting to the API](#connecting-to-the-api-phase-7).

Run it: `.\scripts\dev.ps1 -Only frontend` (http://127.0.0.1:5173). Browse every component at
**/design-system** (also linked in the sidebar); switch themes with the sun/moon button in the
header.

## Visual direction

A dark cybersecurity SaaS interface: near-black canvas, charcoal surfaces, a **neon-green**
primary, **purple** and **cyan** secondary accents, subtle glassmorphism (translucent blurred
surfaces with a hairline border and top sheen), and a faint ambient glow plus masked grid behind
the content. Light mode is a full re-mapping, not an inversion: the neon green becomes a deep
green so it keeps the same contrast on white.

| Token (Tailwind class) | Dark | Light | Use |
| --- | --- | --- | --- |
| `canvas` | `#07080a` | `#f4f6f9` | page background |
| `surface`, `surface-2`, `surface-3` | near-black / charcoal steps | white / light-grey steps | cards, inputs, raised |
| `fg`, `fg-muted`, `fg-subtle` | `#eceff4` / `#9ea6b2` / `#848d9c` | slate 900 / 600 / ~550 | text tiers |
| `primary` (`primary-fg` on it) | `#39ff88` | `#006f34` | brand, primary actions |
| `secondary` | `#a78bfa` (purple) | `#6d28d9` | accents |
| `accent` | `#22d3ee` (cyan) | `#0d6882` | accents, links |
| `success` / `warning` / `danger` | emerald / amber / rose | deep equivalents | status |
| `ring` | cyan | blue | focus indicator |

Typography: **Inter Variable** for the interface and **JetBrains Mono Variable** for data, both
bundled with the app (`@fontsource-variable/*`) - nothing is fetched from a CDN. Headings use
tight tracking and balanced wrapping; numbers in data views use tabular figures (`.tabular`).

## How theming works

* All colours live in **one file**, `src/styles/tokens.css`, as space-separated RGB channels in
  CSS variables (`--primary: 57 255 136`). Tailwind maps them with `rgb(var(--x) / <alpha-value>)`
  (`tailwind.config.ts`), so utilities support opacity (`bg-primary/20`) and **components never
  branch on the theme**: switching `data-theme` on `<html>` re-themes everything.
* `ThemeProvider` offers three preferences - **light, dark, system** - persists the choice in
  `localStorage` (`passaudit.theme`), follows the OS live while on "system", stays in sync across
  tabs, and tolerates blocked storage.
* `public/theme-init.js` applies the saved theme **before first paint** (a same-origin script,
  so a strict CSP with `script-src 'self'` works) - no flash of the wrong theme.
* Without JavaScript, a `prefers-color-scheme` media query in `tokens.css` still picks the
  right palette.

## Components (`src/components/ui`, import from `./components/ui/index.ts`)

| Component | Notes |
| --- | --- |
| `Button`, `IconButton`, `buttonClasses()` | 5 variants x 3 sizes; `loading` shows a spinner, sets `aria-busy`, ignores clicks **but stays focusable**; `IconButton` *requires* a `label`; `buttonClasses()` styles router links as buttons |
| `Card` (+ Header/Title/Description/Content/Footer) | `solid` / `glass` / `outline`, accent glow (`primary`/`secondary`/`accent`), `interactive` hover lift, `as` for semantic elements; `CardTitle level` picks the heading level |
| `Badge` | 7 tones, fill or outline, optional dot - meaning is always in the text |
| `Field` + `Input` / `PasswordInput` / `Textarea` / `Select` | `Field` wires `<label for>`, `aria-describedby` (hint + error), `aria-invalid` and `required` to its control; native `<select>` for best a11y |
| `PasswordInput` | privacy-safe defaults (`autocomplete`/`autocapitalize`/`autocorrect` off, `spellcheck` false), show/hide toggle exposing `aria-pressed`; **holds no state** - the parent owns the value and must never persist or log it |
| `Checkbox`, `Switch`, `SegmentedControl` | real inputs underneath (`role="switch"`, radio group): keyboard and screen-reader behaviour for free |
| `Table` family (`THead`, `TBody`, `TR`, `TH`, `TD`, `TableEmpty`, `TableSkeletonRows`) | real table semantics, optional caption, **keyboard-focusable named scroll region**, sortable headers with `aria-sort` and a real button |
| `Dialog`, `ConfirmDialog`, `Overlay` | modal: portal, `role="dialog"` + `aria-modal`, named and described, focus trap, focus moves in and **returns to the opener**, Escape and backdrop close, page made `inert` and scroll-locked; `ConfirmDialog` starts focus on Cancel |
| `ToastProvider` + `useToast()` | info/success/warning/error, actions, pause on hover/focus, Escape to dismiss, max 4, never steals focus; announced via live regions (polite, errors assertive) that **stay reachable while a dialog is open** |
| `Alert` | inline message; errors `role="alert"`, others `role="status"` |
| `Spinner`, `Skeleton`, `SkeletonText`, `Progress` | labelled, decorative parts hidden from assistive technology, determinate and indeterminate progress, motion stilled for reduced-motion users |
| `PageHeader`, `Section`, `EmptyState`, `Separator`, `Kbd` | page structure helpers (the single `<h1>` lives in `PageHeader`) |

Design rules: one focus indicator for everything (a 2px outline, so it also works in
forced-colors mode); touch targets grow to 44px on coarse pointers; `className` is always
appended last; optional props accept `undefined` (the project uses `exactOptionalPropertyTypes`).

## Application shell (`src/components/layout`)

* **Landmarks:** skip link -> `<header>` (sticky glass; menu button, breadcrumb, "Local only"
  badge, theme toggle) -> `<nav aria-label="Primary">` -> `<main id="main">` -> `<footer>`.
* **Sidebar:** persistent rail on large screens that **collapses to icons** (remembered in
  `localStorage`; links keep accessible names); on small screens the same navigation opens from
  the header menu button in a **modal drawer** (closes on navigation, on Escape, and when the
  window is widened).
* **Navigation:** `react-router-dom`; the current item carries `aria-current="page"`.
  `RouteAnnouncer` updates `document.title`, announces "Navigated to X" and moves focus to
  `<main>` on every client-side navigation (not on first load).
* **Routing:** the design-system gallery is **lazy-loaded** (own 8 kB chunk) behind a skeleton
  `PageLoading`; unknown URLs get a proper 404 page.

Pages: Overview (hero, workspaces, this session's summary), Audit, Batch, Policies, Settings
(theme, privacy toggles, backend status and limits, honoured accessibility preferences, about),
Design system, 404.

## Accessibility

Targets WCAG 2.2 AA. What is built in and how it is verified:

| Concern | Implementation | Verification |
| --- | --- | --- |
| Colour contrast | every text/surface pairing is a token; light-theme accents were darkened until tinted badges and alerts pass | `src/styles/tokens.test.ts` parses `tokens.css` and runs 84 assertions over the pairings in both themes: body text >= 7:1, muted/subtle >= 4.5:1, accents and tinted fills >= 4.5:1, focus ring >= 3:1 |
| Keyboard | native controls, visible focus ring, skip link, focus traps, roving radio groups, Escape handling, focusable scroll regions | `user-event` tests; real-browser checks |
| Screen readers | labels/descriptions via `Field`; live regions for toasts and route changes; `aria-busy`, `aria-sort`, `aria-pressed`, `aria-current` | testing-library role queries; **axe-core on every page and open overlays** (`src/test/a11y.ts`) |
| Motion | `prefers-reduced-motion` removes animation/transition; spinners and shimmer stop | verified in a real browser |
| Contrast/transparency preferences | `prefers-contrast: more` and `prefers-reduced-transparency` turn glass into solid surfaces; `forced-colors` handled | CSS |
| Touch | 44px minimum targets on coarse pointers; responsive from 360px | real-browser layout sweep |
| Language/title | `<html lang="en">`, per-route `document.title` | tests |

axe cannot compute colour contrast in jsdom, so contrast is verified from the tokens (above)
rather than skipped.

**Phase 9 real-browser pass.** axe-core was also run with *every* rule (including colour
contrast) in Edge against the production build, on all five pages in the dark and light themes
plus the audit result and batch pages at a 390 px phone viewport. It found two problems that
jsdom could not: the policy preset / profile buttons were labelled "Use the Strict preset" while
showing "Use preset" (WCAG 2.5.3 *Label in Name*; now "Use preset: Strict"), and responsive grids
without an explicit mobile column let a wide preview stretch the page sideways (now every
`grid` with breakpoint columns also has `grid-cols-1`). Both have jsdom-level guards
(`src/test/a11y.ts` checks label-in-name; `src/styles/layout.test.ts` checks the grid rule).
After the fixes: 0 violations on every page and theme, no horizontal scroll at 360-390 px,
largest contentful paint under 1 s and layout shift under 0.07 on every page.

## Content-Security-Policy

`frontend/csp.ts` defines the policy (`default-src 'none'`, `script-src 'self'`,
`style-src 'self'`, `connect-src 'self'`, no inline script, no `eval`, no framing). The build
injects it as a `<meta http-equiv>` tag (`vite.config.ts`, `apply: 'build'`); `vite preview`
serves it as a real header together with `frame-ancestors 'none'`, which a meta tag cannot
express. The dev server is exempt because React Fast Refresh injects an inline script.
`connect-src 'self'` is the privacy-critical directive: a compromised script still could not
send a password to another origin. Verify with `npm run build && npm run preview`, then load
<http://127.0.0.1:4173>: the app works, and a cross-origin `fetch`, an inline script and `eval`
are blocked by the browser. Whoever serves `dist/` in production must send the same header.

## Verification performed (Phase 5)

* **Unit/integration:** 216 Vitest tests (components, overlays, toasts, theme, shell,
  navigation, helpers, contrast) - run with `.\scripts\test.ps1 -Only frontend`.
* **Real browser (Microsoft Edge, DevTools protocol):** 70 page x width x theme combinations
  (7 routes x 360/390/768/1024/1440 px x dark/light) have **no horizontal overflow**; 15
  interaction checks pass (drawer focus trap/inert/Escape/focus return, route announcement,
  theme persistence and no-flash reload, sidebar persistence, dialog naming and focus handling,
  assertive toast without focus theft, reduced motion, skip link, **no request to any other
  origin**). This found a real bug the jsdom tests could not: focus was not returned to a
  dialog's opener because it was restored before `inert` was lifted (fixed; focus is now
  restored after the commit's cleanups).

## Writing a new screen

```tsx
import { Card, CardTitle, Field, PageHeader, PasswordInput, Button } from '../components/ui/index.ts';

export default function Example() {
  return (
    <>
      <PageHeader title="Example" description="One h1 per page." />
      <Card as="section" aria-labelledby="form-h">
        <CardTitle id="form-h" level={2}>Details</CardTitle>
        <Field label="Password" hint="Never stored." required>
          <PasswordInput />
        </Field>
        <Button className="mt-4">Analyse</Button>
      </Card>
    </>
  );
}
```

Rules for later phases: take the page title from `PageHeader`; keep heading levels sequential;
add the route to `NAV_GROUPS` in `layout/navigation.ts` (this also feeds titles and breadcrumbs);
never put a password in `localStorage`, `sessionStorage`, a URL, a log or analytics (see
[security.md](security.md)) - and `PasswordInput` is controlled by the *page*, so the page must clear it; give every async region an `aria-busy`/status message.

## Connecting to the API (Phase 7)

The Audit, Batch and Policies pages call the local API through a typed client. Decisions and
rationale: [ADR 0007](adr/0007-frontend-api-integration.md). Endpoint contract:
[api.md](api.md).

### Layers

| Layer | Files | Responsibility |
| --- | --- | --- |
| Typed client | `src/api/client.ts`, `types.ts` | One function per endpoint, response-shape checks, error classification (`network`, `timeout`, `aborted`, `http`, `invalid-response`), timeouts, cancellation. Same-origin base path `/api/v1` (`VITE_API_BASE_URL` overrides) |
| Providers | `src/state/` | `ApiProvider` (client + connection status + live limits from `/limits`), `PolicyProvider` (the active policy, rules only), `SessionProvider` (results of this tab, in memory), `PreferencesProvider` (UI toggles) |
| Async hook | `src/lib/useAsyncAction.ts` | idle / loading / success / error; a newer call or unmount aborts the older one and drops its result |
| Pure logic | `src/lib/` | validation against the server limits, CSV/lines parsing, policy validation and import, report builders, error-to-message mapping |
| Pages | `src/pages/AuditPage`, `BatchPage`, `PoliciesPage` | forms, workflow, result presentation |
| Feature components | `src/components/feature/` | `AnalysisView`, `ResultsTable`, `SummaryPanel`, `PolicyEditor`, `PolicyResult`, `ExportPanel`, `ErrorPanel`, `DemoBanner`, ... |

### Workflows

* **Audit:** password, what it protects, optional personal details, "reused" flag -> `POST /audit`
  with the *full* active policy (so what the UI shows is what the server applies) -> strength
  gauge, risk meter, findings by position, risk breakdown, recommendations, policy result ->
  export. Focus moves to the result heading and a polite status line announces the outcome.
* **Batch:** paste (one per line, or CSV with `password` and optional `label` columns) or upload a
  `.txt`/`.csv` file -> client-side checks (count <= `batch_max_items`, password length, file
  size; messages name line numbers, never content) -> `POST /audit/batch` with `detail: "full"` ->
  summary cards, risk and weakness distributions, sortable/filterable/paginated table, per-password
  detail dialog, reuse flags, export.
* **Policies:** edit rules (changes apply as soon as the whole policy is valid; the last valid
  policy stays in force while a field is invalid), presets, import/export a policy file, reset;
  then *Check a password* -> `POST /policy/validate` -> pass/fail per rule -> export.
* **Overview:** aggregates this tab's results (memory only) or, on request, clearly labelled demo
  data. **Settings:** theme, privacy toggles, backend status and limits.

### States

Every request has all four states: *idle*, *loading* (button `aria-busy`, skeleton + spinner,
`aria-busy` region, duplicate submits ignored), *success* (status line, focus moved to the result),
*error* (one `ErrorPanel`).

| Situation | What the user sees |
| --- | --- |
| Backend not running (also a bare 5xx from the dev proxy) | "Can't reach the PassAudit service" with the command to start it, *Retry*, and *Preview with demo data*; the typed input is kept |
| `429` / `503` | warning with a *Retry in Ns* countdown from `Retry-After` |
| `422` / `413` / `400` | what was wrong (field locations from the server), not retryable as-is |
| `5xx` with the service's envelope | generic message plus the request id to report |
| Unexpected response shape | "frontend and backend versions may not match" |
| Timeout (30 s) / cancelled | explained, retryable |

Messages come from the server's sanitised envelope or from fixed text - never from what was typed.

### Privacy rules in code

Full model: [security.md](security.md#browser-handling-of-passwords). In short: the password lives
only in the owning page's state, goes only in a `POST` body, is cleared after success, and is
never written to storage, a URL, the console, the session history or a report. `localStorage`
holds UI preferences and the policy *rules* only; a test fails on any other key.

### Reports

`lib/export.ts` builds JSON/CSV from `AnalysisRecord`s (scores, finding *kinds*, advice) and policy
check results. There is no password field in those types, so a report cannot contain one. Reports
say `sanitized: true`, CSV cells are formula-neutralised, file names are restricted to
`[A-Za-z0-9._-]`, and demo reports are marked `synthetic` inside the file, in every CSV row and by
a `demo-` file-name prefix. Files are created in the browser (`Blob` download); nothing is uploaded.

### Demo data

`src/demo/` holds engine-generated results for fabricated passwords (`scripts/generate_demo_data.py`).
It appears only on request (overview toggle, or *Preview with demo data* after a connection
failure), always under a `DemoBanner`, never mixed with live results, and exports say so.

### Verification performed (Phase 7)

* **277 Vitest tests** (`.\scripts\test.ps1 -Only frontend`): client behaviour (request shape,
  envelope parsing, timeouts, cancellation, bare-5xx handling), validation and parsing, error
  mapping, report sanitising, the async hook, and `integration.test.tsx` - the real pages and
  client against a fake `fetch` backend (`src/test/fakeApi.ts`) that records every request. After
  each workflow the tests scan storage, URL, console output, DOM, session and downloaded
  exports for canary passwords. axe-core runs on every page with results on screen.
* **Real browser, real backend** - a manual, one-off run, not part of the automated gate (Edge over the DevTools protocol, Vite dev server proxying to
  uvicorn): 152 checks across audit, batch, policy and overview workflows, including the same
  leak scans over cookies, IndexedDB, request URLs/headers and response bodies, downloaded
  files, layout at 360 px and 1280 px, and the backend-down path. It found and fixed: a duplicated
  native reveal button in Edge password fields, ambiguous duplicate "Format" radio groups, and the
  dev proxy's bare `500` being shown as a server error instead of "cannot reach the service".

## Phase 8 in the web UI

* **Optional external checks** (Audit and Batch): an *Off by default* breach-check selector (local
  dataset / online k-anonymity) and, if the server has a reuse index, a checkbox. The UI reads
  `/capabilities` and shows unavailable options **disabled with the reason**; an older backend
  without it simply shows nothing. Choosing *online* shows exactly what leaves the machine (first
  5 characters of the SHA-1 hash, to which host) and what the service can learn. The choice is
  **never stored** and resets on every visit; a request with nothing selected has no `exposure`
  field at all.
* **Results** show an *External checks* card: *Found in breaches* (with the count and a replace-it
  alert), *Not found* (explicitly "not a guarantee"), or *Unchecked* (a failed lookup, never shown as
  clean); batch tables get *Breached* / *Unchecked* / *In datasets* badges and the summary gets cards.
* **Policies:** a *Server profiles* list (built-in and operator profiles) loads a profile into the
  editor; the editor gains *dictionary-built* and *breached* switches; rules that need a breach
  check show **Not checked**, never Pass.
* **Exports** record which external check ran (`external_checks`) and per-result breach / dataset
  statuses - statuses only, never counts of data or any hash.
* **Settings** shows which optional features the server has.
* New findings (`date_pattern`, `dictionary_word`), rules and advice have labels; friendly errors cover
  `external_lookups_disabled`, `feature_unavailable` and `unknown_profile`.

Tests: `src/exposure.test.tsx` (opt-in defaults, the exact request body, honest wording, no
persistence, no leak into storage/console/URL/exports, a11y, profiles, unchecked rules).

## Project layout

```
frontend/
|-- index.html, public/ (theme-init.js, favicon.svg)
|-- csp.ts (the Content-Security-Policy), vite.config.ts
|-- tailwind.config.ts, postcss.config.js
`-- src/
    |-- styles/        tokens.css (all colour), index.css (base, glass, ambient, a11y), tokens.test.ts
    |-- theme/         ThemeProvider, useTheme, theme helpers (+ tests)
    |-- api/           typed client and wire types (+ tests)
    |-- state/         API, policy, session and preference providers
    |-- lib/           validation, parsing, policy, reports, errors, async hook, overlay hooks, storage (+ tests)
    |-- components/ui/      the design system (+ tests)
    |-- components/charts/  gauge, risk meter, bars, donut, pattern strand
    |-- components/feature/ analysis view, results table, policy editor/result, export, errors, demo banner
    |-- components/layout/  AppShell, Sidebar, Header, ConnectionBadge, navigation, RouteAnnouncer, Logo, PageLoading
    |-- demo/          engine-generated synthetic results (always labelled)
    |-- test/          axe helper, matchMedia mock, fake API, helpers
    |-- pages/         Overview, AuditPage, BatchPage, PoliciesPage, Settings, DesignSystem, NotFound
```

## Tooling notes

* **Tailwind CSS 3.4**, not 4: v4's engine is a native binary that Windows Application Control
  may block ([ADR 0002](adr/0002-application-control-compatible-dependencies.md)); v3 is pure
  JavaScript. See [ADR 0006](adr/0006-frontend-design-system.md).
* `lucide-react` icons are imported per icon (tree-shaken) and always `aria-hidden` unless they
  are the only content of a labelled button.
* Run the frontend toolchain from **PowerShell** (the project scripts do): under Git Bash,
  Vitest does not register the `jest-dom` matchers on this machine.
