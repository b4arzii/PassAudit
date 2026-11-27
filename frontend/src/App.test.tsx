import { act, render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';

import App from './App.tsx';
import { SIDEBAR_STORAGE_KEY } from './components/layout/AppShell.tsx';
import { pageTitle } from './components/layout/navigation.ts';
import { PageLoading } from './components/layout/PageLoading.tsx';
import { expectNoA11yViolations } from './test/a11y.ts';
import { createFakeApi } from './test/fakeApi.ts';
import { mockColorScheme } from './test/matchMedia.ts';
import type { MediaController } from './test/matchMedia.ts';
import { THEME_STORAGE_KEY } from './theme/theme.ts';

let media: MediaController;

beforeEach(() => {
  window.localStorage.clear();
  media = mockColorScheme(false);
});
afterEach(() => {
  media.restore();
});

function renderAt(path = '/') {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <App client={createFakeApi().client} />
    </MemoryRouter>,
  );
}

describe('application shell', () => {
  it('exposes the landmark structure: banner, navigation, main, contentinfo', () => {
    renderAt('/');
    expect(screen.getByRole('banner')).toBeInTheDocument();
    expect(screen.getByRole('navigation', { name: 'Primary' })).toBeInTheDocument();
    expect(screen.getByRole('navigation', { name: 'Breadcrumb' })).toBeInTheDocument();
    expect(screen.getByRole('main')).toBeInTheDocument();
    expect(screen.getByRole('contentinfo')).toBeInTheDocument();
  });

  it('has exactly one h1 on every page', async () => {
    for (const path of ['/', '/audit', '/batch', '/policies', '/settings', '/nope']) {
      const { unmount } = renderAt(path);
      expect(screen.getAllByRole('heading', { level: 1 })).toHaveLength(1);
      unmount();
    }
    renderAt('/design-system');
    await screen.findByRole('heading', { level: 1, name: 'Design system' });
    expect(screen.getAllByRole('heading', { level: 1 })).toHaveLength(1);
  });

  it('the skip link is the first tab stop and moves focus to <main>', async () => {
    const user = userEvent.setup();
    renderAt('/');
    await user.tab();
    const skip = screen.getByRole('link', { name: 'Skip to main content' });
    expect(skip).toHaveFocus();
    await user.keyboard('{Enter}');
    expect(screen.getByRole('main')).toHaveFocus();
  });

  it('marks the current page with aria-current in the sidebar', () => {
    renderAt('/audit');
    const nav = screen.getByRole('navigation', { name: 'Primary' });
    expect(within(nav).getByRole('link', { name: 'Audit' })).toHaveAttribute(
      'aria-current',
      'page',
    );
    expect(within(nav).getByRole('link', { name: 'Overview' })).not.toHaveAttribute('aria-current');
    expect(within(nav).getByRole('link', { name: 'Batch' })).not.toHaveAttribute('aria-current');
  });

  it('Overview is only current on exactly "/"', () => {
    renderAt('/');
    const nav = screen.getByRole('navigation', { name: 'Primary' });
    expect(within(nav).getByRole('link', { name: 'Overview' })).toHaveAttribute(
      'aria-current',
      'page',
    );
  });

  it('navigating updates title, announces the page, focuses <main>, and updates the breadcrumb', async () => {
    const user = userEvent.setup();
    renderAt('/');
    expect(document.title).toBe('PassAudit - Local password auditing');
    await user.click(
      within(screen.getByRole('navigation', { name: 'Primary' })).getByRole('link', {
        name: 'Batch',
      }),
    );
    expect(screen.getByRole('heading', { level: 1, name: 'Batch' })).toBeInTheDocument();
    expect(document.title).toBe('Batch - PassAudit');
    expect(screen.getByText('Navigated to Batch')).toBeInTheDocument();
    expect(screen.getByRole('main')).toHaveFocus();
    expect(
      within(screen.getByRole('navigation', { name: 'Breadcrumb' })).getByText('Batch'),
    ).toHaveAttribute('aria-current', 'page');
  });

  it('does not steal focus on the first load', () => {
    renderAt('/settings');
    expect(screen.getByRole('main')).not.toHaveFocus();
    expect(document.title).toBe('Settings - PassAudit');
  });

  it('unknown routes render a helpful 404 page', async () => {
    const user = userEvent.setup();
    renderAt('/does-not-exist');
    expect(screen.getByRole('heading', { level: 1, name: 'Page not found' })).toBeInTheDocument();
    expect(document.title).toBe('Page not found - PassAudit');
    await user.click(screen.getByRole('link', { name: 'Back to the overview' }));
    expect(screen.getByRole('heading', { level: 1 })).toHaveTextContent(
      /Know how strong your passwords/,
    );
  });

  it('pageTitle normalises trailing slashes and unknown paths', () => {
    expect(pageTitle('/audit/')).toBe('Audit');
    expect(pageTitle('/')).toBe('Overview');
    expect(pageTitle('/x/y')).toBe('Page not found');
  });

  it('lazy-loads the design-system page', async () => {
    renderAt('/design-system');
    expect(
      await screen.findByRole('heading', { level: 1, name: 'Design system' }),
    ).toBeInTheDocument();
  });
});

describe('PageLoading', () => {
  it('is busy for assistive technology, announces itself, and hides its skeletons', () => {
    const { container } = render(<PageLoading />);
    expect(screen.getByText('Loading page').closest('[aria-busy="true"]')).not.toBeNull();
    expect(screen.getByRole('status')).toHaveTextContent('Loading page');
    for (const skeleton of container.querySelectorAll(
      '.animate-shimmer, [class*="after:animate-shimmer"]',
    )) {
      expect(skeleton).toHaveAttribute('aria-hidden', 'true');
    }
  });
});

describe('sidebar', () => {
  it('collapses to an icon rail, keeps accessible names, and remembers the choice', async () => {
    const user = userEvent.setup();
    const { unmount } = renderAt('/');
    const toggle = screen.getByRole('button', { name: 'Collapse sidebar' });
    expect(toggle).toHaveAttribute('aria-expanded', 'true');
    await user.click(toggle);
    expect(screen.getByRole('button', { name: 'Expand sidebar' })).toHaveAttribute(
      'aria-expanded',
      'false',
    );
    const nav = screen.getByRole('navigation', { name: 'Primary' });
    expect(within(nav).getByRole('link', { name: 'Audit' })).toBeInTheDocument(); // still named
    expect(window.localStorage.getItem(SIDEBAR_STORAGE_KEY)).toBe('true');

    unmount();
    renderAt('/');
    expect(screen.getByRole('button', { name: 'Expand sidebar' })).toBeInTheDocument();
  });
});

describe('mobile navigation drawer', () => {
  it('opens as a labelled modal, closes on Escape, and returns focus to the menu button', async () => {
    const user = userEvent.setup();
    renderAt('/');
    const menu = screen.getByRole('button', { name: 'Open navigation menu' });
    expect(menu).toHaveAttribute('aria-expanded', 'false');
    await user.click(menu);

    const drawer = screen.getByRole('dialog', { name: 'Navigation menu' });
    expect(drawer).toHaveAttribute('aria-modal', 'true');
    expect(within(drawer).getByRole('navigation', { name: 'Primary' })).toBeInTheDocument();
    expect(menu).toHaveAttribute('aria-expanded', 'true');

    await user.keyboard('{Escape}');
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    await act(async () => {
      await Promise.resolve();
    });
    expect(menu).toHaveFocus();
    expect(menu).toHaveAttribute('aria-expanded', 'false');
  });

  it('closes after following a link, and lands on that page', async () => {
    const user = userEvent.setup();
    renderAt('/');
    await user.click(screen.getByRole('button', { name: 'Open navigation menu' }));
    await user.click(within(screen.getByRole('dialog')).getByRole('link', { name: 'Policies' }));
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(screen.getByRole('heading', { level: 1, name: 'Policies' })).toBeInTheDocument();
  });

  it('closes when the window is widened to the desktop layout', async () => {
    const user = userEvent.setup();
    const listeners = new Map<string, Set<(event: MediaQueryListEvent) => void>>();
    const lists = new Map<string, { matches: boolean }>();
    const original = window.matchMedia.bind(window);
    window.matchMedia = ((query: string) => {
      // One live object per query, like a browser: `matches` is updated before `change` fires.
      const list = lists.get(query) ?? { matches: false };
      lists.set(query, list);
      return Object.assign(list, {
        media: query,
        addEventListener: (_type: string, listener: (event: MediaQueryListEvent) => void) => {
          listeners.set(query, (listeners.get(query) ?? new Set()).add(listener));
        },
        removeEventListener: (_type: string, listener: (event: MediaQueryListEvent) => void) => {
          listeners.get(query)?.delete(listener);
        },
      });
    }) as unknown as typeof window.matchMedia;

    try {
      renderAt('/');
      await user.click(screen.getByRole('button', { name: 'Open navigation menu' }));
      expect(screen.getByRole('dialog')).toBeInTheDocument();
      const desktop = listeners.get('(min-width: 1024px)');
      expect(desktop?.size).toBe(1); // the shell is listening while the drawer is open
      const list = lists.get('(min-width: 1024px)');
      if (!list) throw new Error('query was never created');
      act(() => {
        list.matches = true;
        for (const listener of desktop ?? []) listener({ matches: true } as MediaQueryListEvent);
      });
      expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
      expect(listeners.get('(min-width: 1024px)')?.size).toBe(0); // and stops once closed
    } finally {
      window.matchMedia = original;
    }
  });
});

describe('theme controls', () => {
  it('the header toggle switches theme, relabels itself, and persists', async () => {
    const user = userEvent.setup();
    renderAt('/');
    await user.click(screen.getByRole('button', { name: 'Switch to light theme' }));
    expect(document.documentElement).toHaveAttribute('data-theme', 'light');
    expect(window.localStorage.getItem(THEME_STORAGE_KEY)).toBe('light');
    expect(screen.getByRole('button', { name: 'Switch to dark theme' })).toBeInTheDocument();
  });

  it('Settings offers light / dark / system and applies the choice', async () => {
    const user = userEvent.setup();
    renderAt('/settings');
    const group = screen.getByRole('group', { name: 'Theme' });
    expect(
      within(group)
        .getAllByRole('radio')
        .map((r) => r.getAttribute('value')),
    ).toEqual(['light', 'dark', 'system']);
    expect(within(group).getByRole('radio', { name: 'System' })).toBeChecked();

    await user.click(within(group).getByRole('radio', { name: 'Light' }));
    expect(document.documentElement).toHaveAttribute('data-theme', 'light');
    expect(screen.getByText(/Currently showing the/)).toHaveTextContent('light theme.');

    await user.click(within(group).getByRole('radio', { name: 'System' }));
    expect(screen.getByText(/Currently showing the/)).toHaveTextContent('following your system');
  });
});

describe('content', () => {
  it('password fields are masked, never autofilled, and only on the workspaces that analyse', () => {
    for (const path of ['/', '/settings']) {
      const { container, unmount } = renderAt(path);
      expect(container.querySelector('input[type="password"]')).toBeNull();
      unmount();
    }
    for (const path of ['/audit', '/policies']) {
      const { container, unmount } = renderAt(path);
      const field = container.querySelector('input[type="password"]');
      expect(field).not.toBeNull();
      expect(field).toHaveAttribute('autocomplete', 'off');
      expect(field).toHaveAttribute('spellcheck', 'false');
      unmount();
    }
  });

  it('never stores anything but UI preferences in localStorage', async () => {
    const user = userEvent.setup();
    renderAt('/');
    await user.click(screen.getByRole('button', { name: 'Collapse sidebar' }));
    await user.click(screen.getByRole('button', { name: 'Switch to light theme' }));
    // Nothing else (no policy, no results) is written until the user changes it.
    expect(Object.keys(window.localStorage).sort()).toEqual(
      [SIDEBAR_STORAGE_KEY, THEME_STORAGE_KEY].sort(),
    );
  });
});

describe('accessibility (axe) - every page', () => {
  it.each(['/', '/audit', '/batch', '/policies', '/settings', '/nope'])(
    '%s has no violations',
    async (path) => {
      const { container } = renderAt(path);
      await expectNoA11yViolations(container, { page: true });
    },
  );

  it('/design-system has no violations', async () => {
    const { container } = renderAt('/design-system');
    await screen.findByRole('heading', { level: 1, name: 'Design system' });
    await expectNoA11yViolations(container, { page: true });
  });

  it('the open drawer has no violations', async () => {
    const user = userEvent.setup();
    renderAt('/');
    await user.click(screen.getByRole('button', { name: 'Open navigation menu' }));
    await expectNoA11yViolations(screen.getByRole('dialog'));
  });
});
