# ADR 0006: Frontend design system

- Status: Accepted (Phase 5)
- Date: 2026-11-26

## Context

Phase 5 creates the visual and interaction foundation for the PassAudit UI: a dark
cybersecurity SaaS look (near-black surfaces, neon-green primary, purple/cyan accents, subtle
glassmorphism), light and dark themes, a responsive application shell, and a reusable component
library - with accessibility prioritised. No dashboard functionality is built yet. Constraints:
React + TypeScript + Vite + Tailwind + Lucide; Windows Application Control (ADR 0002); a
local-first product that must not call third parties.

## Decisions

1. **Tailwind CSS 3.4, not 4.** Tailwind 4's compiler is a native Rust binary that
   Application Control can block on this class of machine; Tailwind 3 is pure JavaScript
   (PostCSS). Upgrading is a localised change (config and CSS entry) once binaries are allowed.
2. **Colour as CSS-variable tokens, single source of truth.** `tokens.css` holds RGB channels
   per theme; Tailwind maps them with `<alpha-value>`. Components use semantic classes
   (`bg-surface`, `text-fg-muted`, `border-line/10`) and never test the theme, so light/dark
   cannot drift apart and a new theme is one block of variables.
3. **Contrast is tested, not eyeballed.** A test parses `tokens.css` and asserts WCAG ratios for
   every text pairing in both themes (including accents on their own tinted fills). It
   immediately found light-theme accents that failed AA; they were darkened with computed
   values. axe-core cannot measure contrast in jsdom, so this test fills that gap.
4. **Native semantics first, hand-rolled primitives only where needed.** Checkbox, switch,
   radio group and select are native inputs with themed chrome. Modal behaviour (portal, focus
   trap and restore, Escape, scroll lock, inert background) lives in one `Overlay` primitive
   reused by `Dialog`, `ConfirmDialog` and the mobile drawer, instead of a headless-UI
   dependency: fewer dependencies for a security tool, and the behaviour is fully tested.
5. **Real-browser verification in addition to jsdom.** jsdom lacks layout and `inert`, so a
   DevTools-protocol sweep (70 layout combinations, 15 interaction checks) ran against the
   production build. It caught a genuine bug (focus not restored after closing a modal because
   `inert` was still set); the fix restores focus after the commit's cleanups and is covered by
   both layers.
6. **Fonts and assets are bundled.** Inter and JetBrains Mono come from `@fontsource-variable`
   packages; nothing is requested from another origin (checked in the browser run). The theme
   bootstrap is a same-origin script, so a strict CSP remains possible.
7. **Accessibility is structural.** Landmarks, a skip link, a route announcer (title + live
   region + focus to `<main>`), `Field` wiring, named scroll regions, `aria-busy` loading
   buttons that stay focusable, assertive-vs-polite announcements, reduced-motion /
   reduced-transparency / high-contrast / forced-colors support, and 44px touch targets.
8. **Notifications must survive modals.** Making the page `inert` behind a dialog would silence
   live regions, so toasts render in a portal marked `data-keep-active` that the inert logic
   skips.
9. **Scope discipline.** Workspaces are placeholders; the only live behaviour is theme choice
   and sidebar collapse, stored as UI preferences only. A test asserts that no page contains a
   password field or form yet, and that `localStorage` holds nothing but the two preference keys.
10. **Code-split the gallery.** The design-system page is lazy-loaded (separate 8 kB chunk) with
    a skeleton fallback, keeping the main bundle at ~97 kB gzipped.

## Consequences

- New dependencies: `tailwindcss`, `postcss`, `autoprefixer` (build), `lucide-react`,
  `react-router-dom`, two fontsource packages (runtime), `axe-core`, `@testing-library/user-event`
  (tests). `npm audit` reports 0 vulnerabilities.
- Components accept `className` last and optional props with `undefined`, matching the strict
  TypeScript settings; ESLint's fast-refresh rule required keeping constants/helpers
  (`buttonStyles.ts`, `alertStyles.ts`) out of component files.
- Under Git Bash on the development machine Vitest does not register `jest-dom` matchers; the
  project scripts run via PowerShell, where the suite passes.
- The glass effect depends on `backdrop-filter`; unsupported browsers and users who request
  more contrast or less transparency get solid surfaces by design.
