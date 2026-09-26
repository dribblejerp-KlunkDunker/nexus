/** NEXUS Tailwind build config.
 *
 * Replaces the runtime CDN JIT compiler (cdn.tailwindcss.com) that the deck
 * used to load on every boot. This config is the single source of truth for
 * the design tokens; the build step is:
 *
 *   npx tailwindcss@3.4.17 -c web/tailwind.config.js \
 *       -i web/static/css/input.css -o web/static/css/app.css --minify
 *
 * (or just run build_web.bat). The generated app.css is committed so the
 * dashboard never needs Node at runtime.
 */
const path = require('path');

const config = {
  darkMode: 'class',
  // Absolute paths on purpose: content globs resolve relative to the
  // process cwd, so a build launched from the project root used to scan
  // nothing and emit a utility-free app.css. This config now builds
  // correctly from any cwd (root package.json script, build_web.bat, CI).
  content: [
    path.join(__dirname, 'index.html'),
    path.join(__dirname, 'js', 'app.js'),
  ],
  theme: {
    extend: {
      fontFamily: {
        mono: ['"JetBrains Mono"', 'monospace'],
        display: ['"Chakra Petch"', 'sans-serif']
      },
      colors: {
        void: '#05070a',
        panel: '#0a0d14',
        panelBorder: '#161c28',
        panelLight: '#111723',
        laserCyan: '#00f0ff',
        neonRed: '#ff003c',
        matrixGreen: '#00ff88',
        warningAmber: '#ffb703',
        textMuted: '#6b7994'
      },
      boxShadow: {
        cyanGlow: '0 0 20px rgba(0, 240, 255, 0.25)',
        redGlow: '0 0 25px rgba(255, 0, 60, 0.4)',
        greenGlow: '0 0 20px rgba(0, 255, 136, 0.25)'
      }
    }
  }
};

module.exports = config;
