import type { Config } from 'tailwindcss';

/**
 * Every colour is a CSS variable holding space-separated RGB channels (see
 * src/styles/tokens.css), so utilities support opacity (`bg-primary/20`) and the whole UI
 * re-themes by switching `data-theme` on <html> - components never branch on the theme.
 */
const token = (name: string) => `rgb(var(--${name}) / <alpha-value>)`;

export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  darkMode: ['selector', '[data-theme="dark"]'],
  theme: {
    extend: {
      colors: {
        canvas: token('canvas'),
        surface: {
          DEFAULT: token('surface'),
          2: token('surface-2'),
          3: token('surface-3'),
        },
        line: token('line'),
        ring: token('ring'),
        fg: {
          DEFAULT: token('fg'),
          muted: token('fg-muted'),
          subtle: token('fg-subtle'),
        },
        primary: {
          DEFAULT: token('primary'),
          fg: token('on-primary'),
        },
        secondary: token('purple'),
        accent: token('cyan'),
        success: token('success'),
        warning: token('warning'),
        danger: token('danger'),
      },
      fontFamily: {
        sans: [
          '"Inter Variable"',
          'ui-sans-serif',
          'system-ui',
          '-apple-system',
          '"Segoe UI"',
          'sans-serif',
        ],
        mono: [
          '"JetBrains Mono Variable"',
          'ui-monospace',
          'SFMono-Regular',
          'Consolas',
          'monospace',
        ],
      },
      fontSize: {
        // [size, { lineHeight, letterSpacing }] - a tighter, more editorial scale than default.
        xs: ['0.75rem', { lineHeight: '1.125rem', letterSpacing: '0.01em' }],
        sm: ['0.875rem', { lineHeight: '1.375rem' }],
        base: ['1rem', { lineHeight: '1.625rem' }],
        lg: ['1.125rem', { lineHeight: '1.75rem', letterSpacing: '-0.005em' }],
        xl: ['1.25rem', { lineHeight: '1.75rem', letterSpacing: '-0.01em' }],
        '2xl': ['1.5rem', { lineHeight: '2rem', letterSpacing: '-0.02em' }],
        '3xl': ['1.875rem', { lineHeight: '2.25rem', letterSpacing: '-0.025em' }],
        '4xl': ['2.5rem', { lineHeight: '2.75rem', letterSpacing: '-0.03em' }],
      },
      borderRadius: {
        xl: '0.875rem',
        '2xl': '1.125rem',
      },
      boxShadow: {
        card: '0 1px 0 0 rgb(var(--highlight) / 0.06) inset, 0 12px 32px -16px rgb(0 0 0 / 0.45)',
        pop: '0 1px 0 0 rgb(var(--highlight) / 0.08) inset, 0 24px 64px -16px rgb(0 0 0 / 0.6)',
        'glow-primary':
          '0 0 0 1px rgb(var(--primary) / 0.35), 0 8px 28px -6px rgb(var(--primary) / 0.45)',
        'glow-secondary':
          '0 0 0 1px rgb(var(--purple) / 0.35), 0 8px 28px -6px rgb(var(--purple) / 0.4)',
      },
      backgroundImage: {
        'brand-gradient': 'linear-gradient(135deg, rgb(var(--primary)), rgb(var(--cyan)))',
        'brand-gradient-soft':
          'linear-gradient(135deg, rgb(var(--primary) / 0.14), rgb(var(--purple) / 0.14))',
      },
      keyframes: {
        shimmer: {
          '100%': { transform: 'translateX(100%)' },
        },
        'fade-in': {
          from: { opacity: '0' },
          to: { opacity: '1' },
        },
        'pop-in': {
          from: { opacity: '0', transform: 'translateY(8px) scale(0.98)' },
          to: { opacity: '1', transform: 'translateY(0) scale(1)' },
        },
        'slide-in-left': {
          from: { transform: 'translateX(-100%)' },
          to: { transform: 'translateX(0)' },
        },
        'toast-in': {
          from: { opacity: '0', transform: 'translateX(16px)' },
          to: { opacity: '1', transform: 'translateX(0)' },
        },
        'toast-progress': {
          from: { transform: 'scaleX(1)' },
          to: { transform: 'scaleX(0)' },
        },
        indeterminate: {
          '0%': { transform: 'translateX(-100%)' },
          '100%': { transform: 'translateX(250%)' },
        },
      },
      animation: {
        shimmer: 'shimmer 1.6s infinite',
        'fade-in': 'fade-in 160ms ease-out both',
        'pop-in': 'pop-in 200ms cubic-bezier(0.16, 1, 0.3, 1) both',
        'slide-in-left': 'slide-in-left 240ms cubic-bezier(0.16, 1, 0.3, 1) both',
        'toast-in': 'toast-in 220ms cubic-bezier(0.16, 1, 0.3, 1) both',
        'toast-progress': 'toast-progress linear forwards',
        indeterminate: 'indeterminate 1.4s ease-in-out infinite',
      },
    },
  },
  plugins: [],
} satisfies Config;
