/**
 * A controllable `window.matchMedia` for tests: set the answer for any query, and fire the
 * `change` listeners the way a browser does when the OS preference flips.
 */
export interface MediaController {
  /** Change what `(prefers-color-scheme: light)` (or any query listed) answers. */
  setLight: (light: boolean) => void;
  restore: () => void;
}

export function mockColorScheme(initialLight: boolean): MediaController {
  const original = window.matchMedia.bind(window);
  let light = initialLight;
  const listeners = new Set<(event: MediaQueryListEvent) => void>();

  window.matchMedia = (query: string): MediaQueryList => {
    const isSchemeQuery = query.includes('prefers-color-scheme: light');
    return {
      get matches() {
        return isSchemeQuery ? light : false;
      },
      media: query,
      onchange: null,
      addEventListener: (_type: string, listener: (event: MediaQueryListEvent) => void) => {
        if (isSchemeQuery) listeners.add(listener);
      },
      removeEventListener: (_type: string, listener: (event: MediaQueryListEvent) => void) => {
        listeners.delete(listener);
      },
      addListener: () => undefined,
      removeListener: () => undefined,
      dispatchEvent: () => false,
    } as unknown as MediaQueryList;
  };

  return {
    setLight(next) {
      light = next;
      for (const listener of listeners) listener({ matches: next } as MediaQueryListEvent);
    },
    restore() {
      window.matchMedia = original;
    },
  };
}
