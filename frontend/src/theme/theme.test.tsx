import { act, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { mockColorScheme } from '../test/matchMedia.ts';
import type { MediaController } from '../test/matchMedia.ts';
import { ThemeProvider } from './ThemeProvider.tsx';
import {
  THEME_COLORS,
  THEME_STORAGE_KEY,
  applyTheme,
  isThemePreference,
  readStoredPreference,
  resolveTheme,
  storePreference,
  systemTheme,
} from './theme.ts';
import { useTheme } from './useTheme.ts';

let media: MediaController;

beforeEach(() => {
  window.localStorage.clear();
  document.documentElement.removeAttribute('data-theme');
  document.head.innerHTML = '<meta name="theme-color" content="#000000" />';
  media = mockColorScheme(false);
});

afterEach(() => {
  media.restore();
  vi.restoreAllMocks();
});

function Probe() {
  const { preference, resolved, setPreference, toggle } = useTheme();
  return (
    <div>
      <output data-testid="state">{`${preference}/${resolved}`}</output>
      <button type="button" onClick={toggle}>
        toggle
      </button>
      <button
        type="button"
        onClick={() => {
          setPreference('system');
        }}
      >
        system
      </button>
      <button
        type="button"
        onClick={() => {
          setPreference('light');
        }}
      >
        light
      </button>
    </div>
  );
}

const state = () => screen.getByTestId('state').textContent;

describe('theme helpers', () => {
  it.each(['light', 'dark', 'system'])('accepts %s as a preference', (value) => {
    expect(isThemePreference(value)).toBe(true);
  });

  it.each(['', 'blue', null, undefined, 3])('rejects %s', (value) => {
    expect(isThemePreference(value)).toBe(false);
  });

  it('defaults to "system" when nothing (or garbage) is stored', () => {
    expect(readStoredPreference()).toBe('system');
    window.localStorage.setItem(THEME_STORAGE_KEY, 'neon');
    expect(readStoredPreference()).toBe('system');
  });

  it('round-trips a stored preference', () => {
    storePreference('light');
    expect(readStoredPreference()).toBe('light');
  });

  it('survives unavailable storage (private mode / blocked)', () => {
    vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => {
      throw new Error('blocked');
    });
    vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
      throw new Error('blocked');
    });
    expect(readStoredPreference()).toBe('system');
    expect(() => {
      storePreference('dark');
    }).not.toThrow();
  });

  it('resolves "system" from the OS preference', () => {
    expect(systemTheme()).toBe('dark');
    media.setLight(true);
    expect(systemTheme()).toBe('light');
    expect(resolveTheme('system')).toBe('light');
    expect(resolveTheme('dark')).toBe('dark');
  });

  it('falls back to dark when matchMedia is unavailable', () => {
    const original = window.matchMedia.bind(window);
    // @ts-expect-error simulating an old browser
    window.matchMedia = undefined;
    expect(systemTheme()).toBe('dark');
    window.matchMedia = original;
  });

  it('applyTheme sets data-theme, color-scheme and the browser chrome colour', () => {
    applyTheme('light');
    expect(document.documentElement).toHaveAttribute('data-theme', 'light');
    expect(document.documentElement.style.colorScheme).toBe('light');
    expect(document.querySelector('meta[name="theme-color"]')).toHaveAttribute(
      'content',
      THEME_COLORS.light,
    );
    applyTheme('dark');
    expect(document.querySelector('meta[name="theme-color"]')).toHaveAttribute(
      'content',
      THEME_COLORS.dark,
    );
  });
});

describe('ThemeProvider', () => {
  it('starts from the OS preference and applies it to <html>', () => {
    media.setLight(true);
    render(
      <ThemeProvider>
        <Probe />
      </ThemeProvider>,
    );
    expect(state()).toBe('system/light');
    expect(document.documentElement).toHaveAttribute('data-theme', 'light');
  });

  it('honours a stored preference over the OS', () => {
    window.localStorage.setItem(THEME_STORAGE_KEY, 'dark');
    media.setLight(true);
    render(
      <ThemeProvider>
        <Probe />
      </ThemeProvider>,
    );
    expect(state()).toBe('dark/dark');
    expect(document.documentElement).toHaveAttribute('data-theme', 'dark');
  });

  it('toggle flips light/dark and persists the choice', async () => {
    const user = userEvent.setup();
    render(
      <ThemeProvider>
        <Probe />
      </ThemeProvider>,
    );
    expect(state()).toBe('system/dark');
    await user.click(screen.getByRole('button', { name: 'toggle' }));
    expect(state()).toBe('light/light');
    expect(window.localStorage.getItem(THEME_STORAGE_KEY)).toBe('light');
    expect(document.documentElement).toHaveAttribute('data-theme', 'light');
    await user.click(screen.getByRole('button', { name: 'toggle' }));
    expect(state()).toBe('dark/dark');
  });

  it('follows live OS changes while on "system", and ignores them otherwise', async () => {
    const user = userEvent.setup();
    render(
      <ThemeProvider>
        <Probe />
      </ThemeProvider>,
    );
    act(() => {
      media.setLight(true);
    });
    expect(state()).toBe('system/light');
    expect(document.documentElement).toHaveAttribute('data-theme', 'light');

    await user.click(screen.getByRole('button', { name: 'light' }));
    await user.click(screen.getByRole('button', { name: 'toggle' })); // -> dark, explicitly
    act(() => {
      media.setLight(true);
    });
    expect(state()).toBe('dark/dark'); // an explicit choice is not overridden by the OS

    await user.click(screen.getByRole('button', { name: 'system' }));
    expect(state()).toBe('system/light'); // back to following the (now light) OS
  });

  it('stays in sync with other tabs through the storage event', () => {
    render(
      <ThemeProvider>
        <Probe />
      </ThemeProvider>,
    );
    act(() => {
      window.dispatchEvent(
        new StorageEvent('storage', { key: THEME_STORAGE_KEY, newValue: 'light' }),
      );
    });
    expect(state()).toBe('light/light');
    act(() => {
      window.dispatchEvent(
        new StorageEvent('storage', { key: THEME_STORAGE_KEY, newValue: 'garbage' }),
      );
      window.dispatchEvent(new StorageEvent('storage', { key: 'other', newValue: 'dark' }));
    });
    expect(state()).toBe('light/light'); // invalid / unrelated values are ignored
  });

  it('unsubscribes from OS changes when unmounted', () => {
    const { unmount } = render(
      <ThemeProvider>
        <Probe />
      </ThemeProvider>,
    );
    unmount();
    expect(() => {
      media.setLight(true);
    }).not.toThrow();
  });

  it('useTheme outside the provider fails loudly', () => {
    vi.spyOn(console, 'error').mockImplementation(() => undefined);
    expect(() => render(<Probe />)).toThrow(/ThemeProvider/);
  });
});
