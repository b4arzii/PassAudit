/* Applies the saved theme before first paint so there is no flash of the wrong theme.
 * Kept as a separate same-origin file (not inline) so a strict Content-Security-Policy
 * (script-src 'self') works. Keep the storage key and logic in sync with src/theme/theme.ts. */
(function () {
  var theme = 'dark';
  try {
    var stored = window.localStorage.getItem('passaudit.theme');
    if (stored === 'light' || stored === 'dark') {
      theme = stored;
    } else if (window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches) {
      theme = 'light';
    }
  } catch (e) {
    if (window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches) {
      theme = 'light';
    }
  }
  var root = document.documentElement;
  root.setAttribute('data-theme', theme);
  root.style.colorScheme = theme;
  var meta = document.querySelector('meta[name="theme-color"]');
  if (meta) meta.setAttribute('content', theme === 'light' ? '#f4f6f9' : '#07080a');
})();
