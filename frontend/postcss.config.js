// Tailwind CSS 3 is pure JavaScript (no native binaries), so it runs under Windows Application
// Control - see docs/adr/0002 and docs/adr/0006.
export default {
  plugins: {
    tailwindcss: {},
    autoprefixer: {},
  },
};
