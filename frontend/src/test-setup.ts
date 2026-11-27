import '@testing-library/jest-dom/vitest';

// jsdom does not implement these browser APIs that the UI relies on.
Object.defineProperty(window, 'scrollTo', { value: () => undefined, writable: true });

if (typeof window.matchMedia !== 'function') {
  Object.defineProperty(window, 'matchMedia', {
    writable: true,
    value: (query: string): MediaQueryList =>
      ({
        matches: false,
        media: query,
        onchange: null,
        addEventListener: () => undefined,
        removeEventListener: () => undefined,
        dispatchEvent: () => false,
      }) as unknown as MediaQueryList,
  });
}
